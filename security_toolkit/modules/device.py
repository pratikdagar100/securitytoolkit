"""Device lookup module (by MAC address, optional IP).

What a MAC address can honestly tell you:
  * the hardware **vendor / manufacturer** (from the OUI = first 3 bytes),
  * whether the address is **globally unique** or **locally administered**
    (locally administered usually means a randomized / virtual / spoofed MAC),
  * whether it is **unicast** or **multicast**.

A MAC is only visible on the local network segment -- it is not routable across
the internet -- so richer details require the device to be on your LAN. This
module therefore also searches the local **ARP table** to map the MAC to an IP,
and, when an IP is provided or found, adds reverse DNS, address classification
and reachability. Vendor lookup is offline-first (bundled table + optional local
IEEE OUI file) with a best-effort online fallback.
"""
from __future__ import annotations

import ipaddress
import re
import socket
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

from security_toolkit.core.authorization import AuthorizationContext
from security_toolkit.core.models import ScanResult
from security_toolkit.core.risk_engine import make_finding

# A small curated set of common OUI prefixes (first 3 bytes, upper hex, no
# separators). This works fully offline; point config 'wordlists' or an IEEE
# oui file for exhaustive coverage, or rely on the online fallback.
COMMON_OUI: Dict[str, str] = {
    "FCFBFB": "Cisco Systems", "000C29": "VMware", "005056": "VMware",
    "080027": "Oracle VirtualBox", "0A0027": "VirtualBox (host-only)",
    "525400": "QEMU / KVM virtual NIC", "001C42": "Parallels",
    "00155D": "Microsoft Hyper-V", "0050F2": "Microsoft",
    "F0DEF1": "Wistron (laptops)", "3C5AB4": "Google", "D8A011": "Google Nest",
    "44650D": "Amazon (Echo/Kindle)", "FCA667": "Amazon",
    "B827EB": "Raspberry Pi Foundation", "DCA632": "Raspberry Pi (Trading)",
    "E45F01": "Raspberry Pi", "001A11": "Google",
    "F4F5D8": "Google", "A4C138": "Telink (smart home)",
    "001451": "Apple", "3C0754": "Apple", "F0F61C": "Apple", "AC87A3": "Apple",
    "A45E60": "Apple", "88665A": "Apple", "DC2B2A": "Apple", "F86214": "Apple",
    "001B63": "Apple", "40B395": "Apple",
    "F4F26D": "TP-Link", "50C7BF": "TP-Link", "AC84C6": "TP-Link",
    "C46E1F": "TP-Link", "0C8063": "TP-Link",
    "E8DE27": "TP-Link", "1C61B4": "TP-Link",
    "20DFB9": "Google", "FCECDA": "Ubiquiti", "44D9E7": "Ubiquiti",
    "687251": "Ubiquiti", "F09FC2": "Ubiquiti",
    "B0BE76": "TP-Link", "84D81B": "Roku", "CC6DA0": "Roku",
    "D0D2B0": "Amazon", "747548": "Amazon",
    "0018DE": "Intel", "3CA9F4": "Intel", "A0A8CD": "Intel", "7C7A91": "Intel",
    "8C1645": "Samsung", "5001BB": "Samsung", "0000F0": "Samsung",
    "34BE00": "Samsung", "C4576E": "Samsung",
    "F8E61A": "Samsung", "D0176A": "Samsung",
    "F0D5BF": "Xiaomi", "64B473": "Xiaomi", "286C07": "Xiaomi", "7802F8": "Xiaomi",
    "001788": "Philips Hue", "0017880": "Philips",
    "00170088": "Philips", "ECB5FA": "Philips Hue",
    "0024E4": "Withings", "185936": "Dell", "B083FE": "Dell", "F8BC12": "Dell",
    "D89EF3": "Dell", "18DBF2": "Dell",
    "3417EB": "Dell", "A41F72": "Dell",
    "9C8ECD": "Cisco", "00000C": "Cisco", "001A2F": "Cisco",
    "00E04C": "Realtek", "52540A": "Realtek (virtual)",
    "001999": "Fujitsu", "D4CA6D": "Routerboard/MikroTik", "648D9E": "MikroTik",
    "E48D8C": "Routerboard", "CC2DE0": "MikroTik",
    "001DD8": "Microsoft", "60F81D": "Sony", "FCF152": "Sony",
    "AC220B": "ASUSTek", "049226": "ASUSTek", "1C872C": "ASUSTek",
    "2C4D54": "ASUSTek", "50465D": "ASUSTek",
    "F832E4": "ASUSTek", "38D547": "ASUSTek",
    "00904C": "Epson", "E0CB4E": "ASUSTek", "3822D6": "Huawei",
    "04BD70": "Huawei", "48435A": "Huawei", "781DBA": "Huawei",
    "9CB6D0": "Realtek", "0026B9": "Dell", "005043": "Marvell",
}

MAC_RE = re.compile(r"[0-9A-Fa-f]{2}")


def normalize_mac(raw: str) -> Optional[str]:
    """Return a canonical AA:BB:CC:DD:EE:FF or None if not 6 valid bytes."""
    hexes = MAC_RE.findall(raw or "")
    # Some formats (aabb.ccdd.eeff) yield 6 pairs; others give a run of digits.
    if len(hexes) != 6:
        compact = re.sub(r"[^0-9A-Fa-f]", "", raw or "")
        if len(compact) == 12:
            hexes = [compact[i:i + 2] for i in range(0, 12, 2)]
        else:
            return None
    return ":".join(h.upper() for h in hexes)


def arp_table() -> List[Dict[str, str]]:
    """Parse the local ARP cache into [{ip, mac, type}] (cross-platform).

    Handles Windows (`192.168.0.1  aa-bb-cc-dd-ee-ff  dynamic`) and
    Unix/mac (`? (192.168.0.1) at aa:bb:cc:dd:ee:ff [ether] on en0`).
    """
    rows: List[Dict[str, str]] = []
    try:
        proc = subprocess.run(["arp", "-a"], capture_output=True, text=True,
                              timeout=8, check=False)
        out = proc.stdout or ""
    except Exception:
        return rows
    for line in out.splitlines():
        macs = re.findall(r"(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}", line)
        ips = re.findall(r"\d{1,3}(?:\.\d{1,3}){3}", line)
        if not macs or not ips:
            continue
        entry = {"ip": ips[0], "mac": normalize_mac(macs[0]) or macs[0]}
        low = line.lower()
        entry["type"] = "static" if "static" in low else "dynamic"
        rows.append(entry)
    return rows


def vendor_for_mac(mac: str) -> Optional[str]:
    """Offline vendor lookup from the bundled OUI table (no network call)."""
    norm = normalize_mac(mac)
    if not norm:
        return None
    first_octet = int(norm.split(":")[0], 16)
    if first_octet & 0x02:  # locally administered -> not a real vendor
        return None
    return COMMON_OUI.get(norm.replace(":", "")[:6])


class DeviceModule:
    name = "device"
    description = "Device lookup by MAC address (vendor, ARP, optional IP details)"
    operation_class = "passive"

    def __init__(self, config=None) -> None:
        self.config = config

    def run(self, target: str, auth: AuthorizationContext = None,
            ip: Optional[str] = None, **options: Any) -> ScanResult:
        mac = normalize_mac(target)
        result = ScanResult(module=self.name, target=mac or str(target),
                            profile=auth.profile if auth else "PASSIVE")
        case_id = auth.case_id if auth else ""
        if not mac:
            result.errors.append(
                f"'{target}' is not a valid MAC address "
                f"(expected 6 bytes, e.g. AA:BB:CC:DD:EE:FF)")
            return result

        self._analyze_mac(mac, result, case_id)
        self._vendor(mac, result, case_id)

        # Correlate with the local ARP table (finds the IP for a LAN device).
        arp = self._arp_lookup(mac)
        if arp:
            result.raw["arp"] = arp
            found_ip = arp[0]["ip"]
            result.add(make_finding(
                "Device located on local network (ARP)", "DEVICE", "INFO", "HIGH",
                target=mac, evidence=f"MAC {mac} is present in the local ARP cache as "
                                     f"{found_ip} ({arp[0].get('type', 'dynamic')}).",
                recommendation="Confirm this is an expected device on your network.",
                module=self.name, case_id=case_id))
            ip = ip or found_ip
        else:
            result.raw["arp"] = []

        if ip:
            self._ip_details(ip, mac, result, case_id)
        else:
            result.add(make_finding(
                "No IP available for deeper inspection", "DEVICE", "INFO", "MEDIUM",
                target=mac,
                evidence="The MAC was not found in the local ARP cache and no IP was "
                         "supplied.",
                impact="A MAC alone reveals the vendor only; it is not visible beyond the "
                       "local network segment.",
                recommendation="Provide the device's IP, or run this on the same LAN, for "
                               "reverse DNS / reachability / port details.",
                module=self.name, case_id=case_id))
        return result

    # -- MAC structure ---------------------------------------------------
    def _analyze_mac(self, mac: str, result: ScanResult, case_id: str) -> None:
        first_octet = int(mac.split(":")[0], 16)
        multicast = bool(first_octet & 0x01)
        local = bool(first_octet & 0x02)
        result.raw["mac"] = {
            "address": mac,
            "oui": mac.replace(":", "")[:6],
            "unicast": not multicast,
            "locally_administered": local,
        }
        if local:
            result.add(make_finding(
                "Locally administered (likely randomized/virtual) MAC", "DEVICE",
                "LOW", "MEDIUM", target=mac,
                evidence=f"The 'locally administered' bit is set in {mac}.",
                impact="This MAC is not a manufacturer-burned address. It is common for "
                       "privacy MAC randomization (phones/laptops), VMs, or spoofing, so "
                       "vendor lookup will not be meaningful.",
                recommendation="Treat vendor as unknown; identify the device by IP/behaviour.",
                module=self.name, case_id=case_id))
        if multicast:
            result.add(make_finding(
                "Multicast/broadcast MAC address", "DEVICE", "INFO", "HIGH", target=mac,
                evidence=f"The least-significant bit of the first octet is set in {mac}.",
                recommendation="This is a group address, not a single device.",
                module=self.name, case_id=case_id))

    # -- vendor ----------------------------------------------------------
    def _vendor(self, mac: str, result: ScanResult, case_id: str) -> None:
        oui = mac.replace(":", "")[:6]

        # A locally administered MAC is not a burned-in vendor address, so
        # vendor lookup (including any online call) is skipped as meaningless.
        if result.raw.get("mac", {}).get("locally_administered"):
            result.raw["mac"]["vendor"] = "n/a (locally administered)"
            return

        vendor = COMMON_OUI.get(oui)
        source = "bundled OUI table"

        if not vendor:
            vendor = self._vendor_from_file(oui)
            if vendor:
                source = "local IEEE OUI file"

        if not vendor:
            vendor = self._vendor_online(mac)
            if vendor:
                source = "online lookup (macvendors.com)"

        if vendor:
            result.raw["mac"]["vendor"] = vendor
            result.raw["mac"]["vendor_source"] = source
            result.add(make_finding(
                f"Device vendor: {vendor}", "DEVICE", "INFO", "HIGH", target=mac,
                evidence=f"OUI {oui} maps to '{vendor}' ({source}).",
                recommendation="The vendor identifies the hardware maker, not the exact model.",
                module=self.name, case_id=case_id))
        else:
            result.raw["mac"]["vendor"] = "unknown"
            result.add(make_finding(
                "Vendor not found for this OUI", "DEVICE", "INFO", "MEDIUM", target=mac,
                evidence=f"OUI {oui} is not in the bundled table and no lookup source "
                         f"resolved it.",
                recommendation="Configure a local IEEE oui.txt path or enable internet "
                               "access for full vendor coverage.",
                module=self.name, case_id=case_id))

    def _vendor_from_file(self, oui: str) -> Optional[str]:
        """Optionally read a full IEEE OUI file (tools.oui_file in config)."""
        if self.config is None:
            return None
        path = str(self.config.get("tools.oui_file", "") or "")
        if not path or not Path(path).exists():
            return None
        try:
            needle = "-".join(oui[i:i + 2] for i in range(0, 6, 2)).upper()
            for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
                if "(hex)" in line and line.strip().upper().startswith(needle):
                    return line.split("(hex)")[-1].strip()
        except Exception:
            return None
        return None

    def _vendor_online(self, mac: str) -> Optional[str]:
        try:
            import requests
            resp = requests.get(f"https://api.macvendors.com/{mac}", timeout=4)
            if resp.status_code == 200 and resp.text.strip():
                return resp.text.strip()
        except Exception:
            return None
        return None

    # -- ARP -------------------------------------------------------------
    def _arp_lookup(self, mac: str) -> List[Dict[str, str]]:
        target_norm = mac.lower().replace(":", "").replace("-", "")
        matches: List[Dict[str, str]] = []
        for entry in arp_table():
            if entry["mac"].lower().replace(":", "").replace("-", "") == target_norm:
                matches.append({"ip": entry["ip"], "mac": mac,
                                "type": entry.get("type", "dynamic")})
        return matches

    # -- IP details ------------------------------------------------------
    def _ip_details(self, ip: str, mac: str, result: ScanResult, case_id: str) -> None:
        info: Dict[str, Any] = {"ip": ip}
        try:
            addr = ipaddress.ip_address(ip)
            info["private"] = addr.is_private
            info["version"] = f"IPv{addr.version}"
        except ValueError:
            result.errors.append(f"'{ip}' is not a valid IP address")
            return

        try:
            hostname, aliases, _ = socket.gethostbyaddr(ip)
            info["hostname"] = hostname
            info["aliases"] = aliases
        except Exception:
            info["hostname"] = ""

        # lightweight reachability: try a couple of common TCP ports
        reachable_ports = []
        for port in (80, 443, 22, 445, 3389):
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(0.4)
                if s.connect_ex((ip, port)) == 0:
                    reachable_ports.append(port)
        info["reachable_tcp_ports"] = reachable_ports
        result.raw["ip_details"] = info

        detail = (f"IP {ip} ({info['version']}, "
                  f"{'private/LAN' if info.get('private') else 'public'})"
                  f"{', hostname ' + info['hostname'] if info.get('hostname') else ''}"
                  f"{', open TCP ' + str(reachable_ports) if reachable_ports else ''}.")
        result.add(make_finding(
            "Device IP details", "DEVICE", "INFO", "HIGH", target=f"{mac} / {ip}",
            evidence=detail,
            recommendation="For a full port/service picture, run: security-toolkit network "
                           f"--target {ip} --profile-auth ASSESSMENT (authorized targets only).",
            module=self.name, case_id=case_id))
