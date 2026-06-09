# IONOS VPS SSH Setup — <IONOS-VPS-IP>

> **⚠️ DEPRECATED (2026-06-08):** IONOS is no longer the authoritative evaluation platform.
> Use **GCP** (`sentinel-gpu-vm`, `<GCP-VM-IP>`) per [RUNME.md](RUNME.md).
> Do not cite `*_ionos.json` results in the paper.

> **Full runbook:** [RUNME.md](RUNME.md) — deployment, evals, and validation status.

SSH key generated on your Mac for this project. **Add it to the VPS once** (pick one method).

## Public key (paste into IONOS panel)

```
ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbUy5jtJl8/6c1Bi4XzcXNgPdvyJ1Vznxwd9ym54Ume sentinel-ionos
```

Private key: `~/.ssh/id_ed25519_sentinel`  
SSH config host: `sentinel-ionos` → `root@<IONOS-VPS-IP>`

## Method A — IONOS Cloud Panel (preferred)

1. Log in to [IONOS](https://my.ionos.com/) → **Servers & Cloud** → your VPS.
2. Open **Access** / **SSH key** / **Security** (wording varies).
3. **Add SSH key** → paste the public key above → save.
4. Reboot VPS if prompted.

## Method B — Serial / KVM console (if panel has no key UI)

1. IONOS panel → VPS → **Console** / **VNC**.
2. Log in as `root` (password from IONOS welcome email).
3. Run this **one line**:

```bash
mkdir -p /root/.ssh && chmod 700 /root/.ssh && echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbUy5jtJl8/6c1Bi4XzcXNgPdvyJ1Vznxwd9ym54Ume sentinel-ionos' >> /root/.ssh/authorized_keys && chmod 600 /root/.ssh/authorized_keys
```

## Test from Mac

```bash
ssh sentinel-ionos 'uname -a'
# or: ssh -i ~/.ssh/id_ed25519_sentinel root@<IONOS-VPS-IP> uname -a
```

## After SSH works

```bash
# From Mac — upload and run bootstrap (or clone from GitHub after push)
scp scripts/bootstrap_ionos.sh sentinel-ionos:/root/
ssh sentinel-ionos 'bash /root/bootstrap_ionos.sh'
```

SMTP port 25 blocked on IONOS is normal; ignore for this project.
