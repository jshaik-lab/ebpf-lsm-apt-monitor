# GCP GPU VM Setup and Operation Guide

This guide documents the configuration, pricing, SSH keys, and commands required to operate the GPU VM for the SENTINEL project on Google Cloud Platform.

---

## 1. Instance Specifications
*   **Instance Name**: `sentinel-gpu-vm`
*   **Zone**: `us-east1-c` (South Carolina)
*   **Machine Type**: `g2-standard-4` (4 vCPUs, 16 GB RAM)
*   **GPU**: 1x NVIDIA L4 (24 GB VRAM)
*   **Boot Disk**: 100 GB Balanced Persistent Disk
*   **Provisioning Model**: SPOT (Preemptible, auto-terminates to save cost)
*   **Termination Action**: STOP (Freezes the instance, preserves disk data)

---

## 2. Pricing & Cost Optimization (Budget: ~$20/month)
To stay within the $20.00/month budget, the compute resources (vCPU, RAM, GPU) must be stopped when not running active evaluations.

*   **Fixed Storage Cost**: ~$10.00/month for the 100 GB Balanced Disk (always kept alive).
*   **Compute Cost**: ~$0.30/hour when the VM is running.
*   **Running Capacity**: You get **~33 hours** of active GPU execution time per month for the remaining $10.00 of the budget.

---

## 3. SSH Configuration & Connection Details

### Connection Details
*   **Target IP**: `34.74.43.57`
*   **SSH User**: `sentinel`
*   **Local Private Key**: `/Users/jshaik/.ssh/id_ed25519_sentinel`

### How to SSH from your local Mac terminal:
```bash
ssh -i ~/.ssh/id_ed25519_sentinel sentinel@34.74.43.57
```

### How to add/update SSH keys via GCP Cloud Shell:
If you ever need to re-authorize the SSH key on the VM, run this command in GCP Cloud Shell:
```bash
gcloud compute instances add-metadata sentinel-gpu-vm \
    --zone=us-east1-c \
    --metadata=ssh-keys="sentinel:ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAILbUy5jtJl8/6c1Bi4XzcXNgPdvyJ1Vznxwd9ym54Ume sentinel-ionos"
```

### Sync evaluation results to Mac

```bash
rsync -avz -e "ssh -i ~/.ssh/id_ed25519_sentinel" \
  sentinel@34.74.43.57:~/Paper1_ZeroTrustAgent/results/evaluations_gcp/ \
  ./results/evaluations_gcp/
```

See [RUNME.md](RUNME.md) for the full eval chain and measured headline metrics (2026-06-08 run).

---

## 4. Operation Commands

### Start the VM
To turn on the VM and start working:
```bash
gcloud compute instances start sentinel-gpu-vm --zone=us-east1-c
```

### Stop the VM (Freeze Billing)
To turn off the VM and stop the hourly GPU compute charges:
```bash
gcloud compute instances stop sentinel-gpu-vm --zone=us-east1-c
```
*Alternatively, run `sudo poweroff` inside the SSH terminal, and GCP will automatically shut down the VM and stop billing.*

---

## 5. VM Setup Automation Script
Once logged into the VM, run these commands to configure the environment (Docker, NVIDIA L4 drivers, and Ollama):

```bash
# Update OS packages
sudo apt-get update && sudo apt-get upgrade -y

# Install Docker
sudo apt-get install -y docker.io
sudo usermod -aG docker sentinel

# Install NVIDIA Drivers & Container Toolkit (for GPU inside Docker/Ollama)
sudo apt-get install -y ubuntu-drivers-common
sudo ubuntu-drivers install
sudo apt-get install -y nvidia-container-toolkit
sudo systemctl restart docker

# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Pull required models
ollama pull llama3.1:8b
ollama pull llama3.2:1b
```

### Sync evaluation results to Mac

```bash
rsync -avz -e "ssh -i ~/.ssh/id_ed25519_sentinel" \
  sentinel@34.74.43.57:~/Paper1_ZeroTrustAgent/results/evaluations_gcp/ \
  ./results/evaluations_gcp/
```

See [RUNME.md](RUNME.md) for the full eval chain and measured headline metrics (2026-06-08 run).
