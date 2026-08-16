import pytest

from security_toolkit.core.authorization import AuthorizationContext
from security_toolkit.modules.device import normalize_mac, vendor_for_mac, DeviceModule


@pytest.mark.parametrize("raw,expected", [
    ("AA:BB:CC:DD:EE:FF", "AA:BB:CC:DD:EE:FF"),
    ("aa-bb-cc-dd-ee-ff", "AA:BB:CC:DD:EE:FF"),
    ("aabb.ccdd.eeff", "AA:BB:CC:DD:EE:FF"),
    ("aabbccddeeff", "AA:BB:CC:DD:EE:FF"),
])
def test_normalize_mac(raw, expected):
    assert normalize_mac(raw) == expected


def test_normalize_mac_invalid():
    assert normalize_mac("not-a-mac") is None
    assert normalize_mac("AA:BB:CC") is None


def test_invalid_mac_reports_error():
    result = DeviceModule().run("xyz", AuthorizationContext())
    assert result.errors
    assert not result.findings


def test_known_vendor_lookup():
    # 00:0C:29 is VMware in the bundled table.
    result = DeviceModule().run("00:0C:29:11:22:33", AuthorizationContext())
    assert result.raw["mac"]["vendor"] == "VMware"
    titles = " ".join(f.title for f in result.findings)
    assert "vendor" in titles.lower()


def test_vendor_for_mac_helper():
    assert vendor_for_mac("00:0C:29:11:22:33") == "VMware"
    assert vendor_for_mac("02:11:22:33:44:55") is None  # locally administered
    assert vendor_for_mac("bad") is None


def test_locally_administered_flagged():
    # 02:... has the locally-administered bit set.
    result = DeviceModule().run("02:11:22:33:44:55", AuthorizationContext())
    titles = " ".join(f.title for f in result.findings)
    assert "Locally administered" in titles
    assert result.raw["mac"]["locally_administered"] is True
