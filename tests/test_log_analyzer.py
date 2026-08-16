from security_toolkit.core.authorization import AuthorizationContext
from security_toolkit.modules.logs import LogAnalysisModule

SSH_LOG = """\
Jan 10 10:00:01 host sshd[1]: Failed password for invalid user admin from 203.0.113.9 port 22 ssh2
Jan 10 10:00:02 host sshd[1]: Failed password for invalid user root from 203.0.113.9 port 22 ssh2
Jan 10 10:00:03 host sshd[1]: Failed password for invalid user oracle from 203.0.113.9 port 22 ssh2
Jan 10 10:00:04 host sshd[1]: Failed password for invalid user test from 203.0.113.9 port 22 ssh2
Jan 10 10:00:05 host sshd[1]: Failed password for invalid user git from 203.0.113.9 port 22 ssh2
Jan 10 10:00:06 host sshd[1]: Failed password for admin from 203.0.113.9 port 22 ssh2
Jan 10 10:00:07 host sshd[1]: Failed password for admin from 203.0.113.9 port 22 ssh2
Jan 10 10:00:08 host sshd[1]: Failed password for admin from 203.0.113.9 port 22 ssh2
Jan 10 10:00:09 host sshd[1]: Accepted password for admin from 203.0.113.9 port 22 ssh2
Jan 10 10:05:00 host sshd[1]: Failed password for admin from 198.51.100.1 port 22 ssh2
"""


def test_detects_bruteforce_and_success(tmp_path):
    log = tmp_path / "auth.log"
    log.write_text(SSH_LOG)
    result = LogAnalysisModule().run(str(log), AuthorizationContext())
    titles = [f.title for f in result.findings]
    assert any("203.0.113.9" in t for t in titles)
    # the busy source has >=8 failures and a following success -> HIGH
    busy = [f for f in result.findings if "203.0.113.9" in f.title][0]
    assert busy.severity == "HIGH"
    assert result.raw["parsed_events"] >= 10


def test_no_findings_for_missing_file():
    result = LogAnalysisModule().run("/nonexistent/path.log", AuthorizationContext())
    assert result.errors
    assert not result.findings
