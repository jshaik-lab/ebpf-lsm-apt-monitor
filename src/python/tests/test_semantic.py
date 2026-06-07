"""Tests for SemanticLabeler — Core Novelty 2 (semantic security layer)."""
from __future__ import annotations


from sentinel.semantic import SemanticLabeler, SemanticLabel
from sentinel.models import KernelEvent, SyscallType


# ── helpers ───────────────────────────────────────────────────────────────────

def _evt(sc: SyscallType, resource: str, comm: str = "test", pid: int = 1000) -> KernelEvent:
    return KernelEvent(pid=pid, ppid=1, uid=1000, comm=comm, sc_type=int(sc),
                       resource=resource, ts_ns=0)


# ── SemanticLabel.compact() ───────────────────────────────────────────────────

class TestSemanticLabelCompact:
    def test_with_ttps(self):
        lbl = SemanticLabel(
            raw_syscall="openat(R)",
            resource="/etc/shadow",
            security_label="credential access: system password database",
            attack_relevance=["T1003"],
            risk_level="CRITICAL",
        )
        result = lbl.compact()
        assert "T1003" in result
        assert "CRITICAL" in result
        assert "credential access" in result

    def test_without_ttps_shows_benign(self):
        lbl = SemanticLabel(
            raw_syscall="openat(R)",
            resource="/var/www/html/index.html",
            security_label="web-root read: normal web server file serving",
            attack_relevance=[],
            risk_level="LOW",
            is_benign_hint=True,
        )
        result = lbl.compact()
        assert "BENIGN" in result
        assert "LOW" in result

    def test_multiple_ttps_joined(self):
        lbl = SemanticLabel(
            raw_syscall="openat(R)",
            resource="/.ssh/id_rsa",
            security_label="credential access: SSH private key read",
            attack_relevance=["T1003", "T1552"],
            risk_level="CRITICAL",
        )
        result = lbl.compact()
        assert "T1003" in result
        assert "T1552" in result


# ── SemanticLabeler.label() — CRITICAL rules ─────────────────────────────────

class TestCriticalRules:
    def setup_method(self):
        self.labeler = SemanticLabeler()

    def test_shadow_file_read(self):
        evt = _evt(SyscallType.FILE_R, "/etc/shadow")
        lbl = self.labeler.label(evt)
        assert lbl.risk_level == "CRITICAL"
        assert "T1003" in lbl.attack_relevance
        assert "credential" in lbl.security_label.lower()
        assert lbl.is_benign_hint is False

    def test_ssh_private_key_read(self):
        evt = _evt(SyscallType.FILE_R, "/home/user/.ssh/id_rsa")
        lbl = self.labeler.label(evt)
        assert lbl.risk_level == "CRITICAL"
        assert "T1003" in lbl.attack_relevance or "T1552" in lbl.attack_relevance

    def test_ssh_ed25519_key(self):
        evt = _evt(SyscallType.FILE_R, "/root/.ssh/id_ed25519")
        lbl = self.labeler.label(evt)
        assert lbl.risk_level == "CRITICAL"

    def test_aws_credentials(self):
        evt = _evt(SyscallType.FILE_R, "/home/user/.aws/credentials")
        lbl = self.labeler.label(evt)
        assert lbl.risk_level == "CRITICAL"
        assert "T1552" in lbl.attack_relevance or "T1003" in lbl.attack_relevance

    def test_ssl_private_key(self):
        evt = _evt(SyscallType.FILE_R, "/etc/ssl/private/server.key")
        lbl = self.labeler.label(evt)
        assert lbl.risk_level == "CRITICAL"

    def test_sudoers_read(self):
        evt = _evt(SyscallType.FILE_R, "/etc/sudoers")
        lbl = self.labeler.label(evt)
        assert lbl.risk_level == "CRITICAL"
        assert "T1003" in lbl.attack_relevance or "T1068" in lbl.attack_relevance


# ── SemanticLabeler.label() — HIGH rules ─────────────────────────────────────

class TestHighRules:
    def setup_method(self):
        self.labeler = SemanticLabeler()

    def test_exec_from_tmp(self):
        evt = _evt(SyscallType.EXEC, "/tmp/malware.sh")
        lbl = self.labeler.label(evt)
        assert lbl.risk_level == "HIGH"
        assert "T1059" in lbl.attack_relevance or "T1105" in lbl.attack_relevance

    def test_exec_from_dev_shm(self):
        evt = _evt(SyscallType.EXEC, "/dev/shm/exploit")
        lbl = self.labeler.label(evt)
        assert lbl.risk_level == "HIGH"

    def test_ptrace_inject(self):
        evt = _evt(SyscallType.PTRACE, "")
        lbl = self.labeler.label(evt)
        assert lbl.risk_level == "HIGH"
        assert "T1055" in lbl.attack_relevance

    def test_setuid_escalation(self):
        evt = _evt(SyscallType.SETUID, "")
        lbl = self.labeler.label(evt)
        assert lbl.risk_level == "HIGH"
        assert "T1068" in lbl.attack_relevance

    def test_c2_port_4444(self):
        evt = _evt(SyscallType.NET_CON, "185.220.101.1:4444")
        lbl = self.labeler.label(evt)
        assert lbl.risk_level == "HIGH"
        assert "T1071" in lbl.attack_relevance or "T1095" in lbl.attack_relevance

    def test_c2_port_1337(self):
        evt = _evt(SyscallType.NET_CON, "10.0.0.100:1337")
        lbl = self.labeler.label(evt)
        assert lbl.risk_level == "HIGH"

    def test_log_tampering(self):
        evt = _evt(SyscallType.FILE_W, "/var/log/auth.log")
        lbl = self.labeler.label(evt)
        assert lbl.risk_level == "HIGH"
        assert "T1562" in lbl.attack_relevance or "T1070" in lbl.attack_relevance

    def test_cron_persistence(self):
        evt = _evt(SyscallType.FILE_W, "/etc/cron.d/backdoor")
        lbl = self.labeler.label(evt)
        assert lbl.risk_level == "HIGH"
        assert "T1053" in lbl.attack_relevance or "T1562" in lbl.attack_relevance


# ── SemanticLabeler.label() — BENIGN hints ───────────────────────────────────

class TestBenignHints:
    def setup_method(self):
        self.labeler = SemanticLabeler()

    def test_web_root_read(self):
        evt = _evt(SyscallType.FILE_R, "/var/www/html/index.html")
        lbl = self.labeler.label(evt)
        assert lbl.is_benign_hint is True
        assert lbl.risk_level == "LOW"
        assert lbl.attack_relevance == []

    def test_nginx_log_write(self):
        evt = _evt(SyscallType.FILE_W, "/var/log/nginx/access.log")
        lbl = self.labeler.label(evt)
        assert lbl.is_benign_hint is True

    def test_http_port_listen(self):
        evt = _evt(SyscallType.NET_LIS, "0.0.0.0:80")
        lbl = self.labeler.label(evt)
        assert lbl.is_benign_hint is True
        assert lbl.risk_level == "LOW"

    def test_https_port_listen(self):
        evt = _evt(SyscallType.NET_LIS, "0.0.0.0:443")
        lbl = self.labeler.label(evt)
        assert lbl.is_benign_hint is True

    def test_ssh_listen_benign(self):
        evt = _evt(SyscallType.NET_LIS, "0.0.0.0:22")
        lbl = self.labeler.label(evt)
        assert lbl.is_benign_hint is True

    def test_postgres_port_listen(self):
        evt = _evt(SyscallType.NET_LIS, "127.0.0.1:5432")
        lbl = self.labeler.label(evt)
        assert lbl.is_benign_hint is True


# ── SemanticLabeler.label() — fallback / unknown ─────────────────────────────

class TestFallback:
    def setup_method(self):
        self.labeler = SemanticLabeler()

    def test_unknown_resource_returns_label(self):
        evt = _evt(SyscallType.FILE_R, "/etc/hostname")
        lbl = self.labeler.label(evt)
        assert lbl is not None
        assert isinstance(lbl.risk_level, str)
        assert isinstance(lbl.security_label, str)
        assert len(lbl.security_label) > 0

    def test_no_resource_returns_label(self):
        evt = _evt(SyscallType.FORK, "")
        lbl = self.labeler.label(evt)
        assert lbl is not None

    def test_label_always_returns_semanticlabel_instance(self):
        for sc in [SyscallType.FILE_R, SyscallType.EXEC, SyscallType.NET_CON, SyscallType.SETUID]:
            evt = _evt(sc, "/some/path")
            lbl = self.labeler.label(evt)
            assert isinstance(lbl, SemanticLabel)


# ── SemanticLabeler window helpers ────────────────────────────────────────────

class TestWindowHelpers:
    def setup_method(self):
        self.labeler = SemanticLabeler()
        self.attack_window = [
            _evt(SyscallType.FILE_R, "/etc/shadow"),      # CRITICAL
            _evt(SyscallType.NET_CON, "185.220.101.1:4444"),  # HIGH
            _evt(SyscallType.FILE_R, "/etc/hostname"),    # LOW
        ]
        self.benign_window = [
            _evt(SyscallType.FILE_R, "/var/www/html/index.html"),
            _evt(SyscallType.NET_LIS, "0.0.0.0:80"),
        ]

    def test_max_risk_attack_window_is_critical(self):
        assert self.labeler.max_risk(self.attack_window) == "CRITICAL"

    def test_max_risk_benign_window_is_low(self):
        assert self.labeler.max_risk(self.benign_window) == "LOW"

    def test_attack_ttps_deduplicated(self):
        window = [
            _evt(SyscallType.FILE_R, "/etc/shadow"),
            _evt(SyscallType.FILE_R, "/etc/shadow"),  # duplicate
            _evt(SyscallType.NET_CON, "10.0.0.1:4444"),
        ]
        ttps = self.labeler.attack_ttps(window)
        assert "T1003" in ttps
        # No duplicates
        assert len(ttps) == len(set(ttps))

    def test_benign_window_has_no_ttps(self):
        ttps = self.labeler.attack_ttps(self.benign_window)
        assert ttps == []

    def test_label_window_returns_one_label_per_event(self):
        labels = self.labeler.label_window(self.attack_window)
        assert len(labels) == len(self.attack_window)

    def test_max_risk_empty_window(self):
        # Should not raise
        risk = self.labeler.max_risk([])
        assert risk == "LOW"

    def test_attack_ttps_empty_window(self):
        ttps = self.labeler.attack_ttps([])
        assert ttps == []
