"""Hard-trigger resource patterns and flagged-PID TTL shared by agent tests and DetectorAgent."""

# Sensitive paths that always demand deep analysis (EVASION-01, EVASION-03).
HARD_TRIGGER_RESOURCES = (
    "/etc/shadow", "/etc/sudoers", "/.ssh/id_rsa", "/.ssh/id_ed25519",
    "/.ssh/authorized_keys", ".aws/credentials", "ssl/private",
    "/var/backups/shadow", "/proc/self/mem", "/dev/mem",
)

# Once MALICIOUS, PID and children bypass entropy gate for this many seconds (EVASION-04).
FLAGGED_PID_TTL_SECONDS = 120
