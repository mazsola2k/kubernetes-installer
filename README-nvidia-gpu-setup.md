# NVIDIA GPU Support for Kubernetes on Fedora

This document outlines the steps required to enable NVIDIA GPU support in a Kubernetes cluster running on Fedora with containerd runtime.

## Prerequisites

- Fedora-based system with Kubernetes installed
- NVIDIA GPU hardware installed
- NVIDIA drivers already installed on the host (`nvidia-smi` working)
- containerd as the container runtime
- `kubectl` configured and working

## Manual Setup Steps

The following steps were required to configure NVIDIA GPU support:

### 1. Verify NVIDIA GPU and Drivers

```bash
# Check GPU hardware
lspci | grep -i nvidia

# Verify drivers are loaded
nvidia-smi
```

### 2. Add NVIDIA Container Toolkit Repository

```bash
curl -s -L https://nvidia.github.io/libnvidia-container/stable/rpm/nvidia-container-toolkit.repo | \
  sudo tee /etc/yum.repos.d/nvidia-container-toolkit.repo
```

### 3. Remove Conflicting Packages

```bash
# Remove Fedora's older package that conflicts
sudo dnf remove -y golang-github-nvidia-container-toolkit
```

### 4. Install NVIDIA Container Toolkit

```bash
sudo dnf install -y nvidia-container-toolkit
```

### 5. Configure Containerd Runtime

```bash
# Configure containerd to use NVIDIA runtime as default
sudo nvidia-ctk runtime configure --runtime=containerd --set-as-default

# Restart containerd
sudo systemctl restart containerd

# Restart kubelet
sudo systemctl restart kubelet
```

### 6. Generate NVIDIA CDI Specification

```bash
sudo mkdir -p /etc/cdi
sudo nvidia-ctk cdi generate --output=/etc/cdi/nvidia.yaml
```

### 7. Deploy NVIDIA Device Plugin

```bash
kubectl apply -f https://raw.githubusercontent.com/NVIDIA/k8s-device-plugin/v0.16.2/deployments/static/nvidia-device-plugin.yml
```

### 8. Verify Device Plugin is Running

```bash
# Check the device plugin pods
kubectl get pods -n kube-system -l name=nvidia-device-plugin-ds

# Wait for it to be ready
kubectl wait --for=condition=ready --timeout=60s pod -n kube-system -l name=nvidia-device-plugin-ds
```

### 9. Verify GPU is Detected by Kubernetes

```bash
# Check node capacity
kubectl get nodes -o json | jq '.items[].status.capacity | select(.["nvidia.com/gpu"])'

# Should show something like:
# {
#   "nvidia.com/gpu": "1"
# }
```

### 10. Deploy and Test GPU Pod

```bash
# Apply the GPU test pod
kubectl apply -f manifest-controller/nvidia-gpu-pod-cr.yaml

# Wait for it to be ready
kubectl wait --for=condition=ready --timeout=60s pod gpu-pod

# Check logs
kubectl logs gpu-pod

# Run GPU test
kubectl exec gpu-pod -- nvidia-smi
```

## Automated Setup with Ansible

An Ansible playbook is provided to automate all the above steps:

### Prerequisites

```bash
# Install Ansible if not already installed
sudo dnf install -y ansible

# Install required Python packages
pip install jmespath  # for json_query filter
```

### Usage

1. Update the inventory file with your node details:

```bash
vi inventory-example.ini
```

2. Run the playbook:

```bash
ansible-playbook -i inventory-example.ini setup-nvidia-gpu-k8s.yaml
```

3. Verify the setup:

```bash
kubectl get nodes -o json | jq '.items[].status.capacity'
```

## Testing GPU Access

Deploy the test pod:

```bash
kubectl apply -f manifest-controller/nvidia-gpu-pod-cr.yaml
kubectl logs gpu-pod
```

Expected output should show:
- GPU detected via `nvidia-smi`
- GPU name: NVIDIA RTX A3000 12GB Laptop GPU
- Driver version: 580.119.02
- Available GPU memory

## Troubleshooting

### Device Plugin Not Detecting GPU

```bash
# Check device plugin logs
kubectl logs -n kube-system -l name=nvidia-device-plugin-ds

# Common issues:
# - "could not load NVML library" → NVIDIA drivers not installed
# - "Incompatible platform detected" → Container runtime not configured
```

### Containerd Configuration Issues

```bash
# Check containerd config
sudo cat /etc/containerd/conf.d/99-nvidia.toml

# Should contain nvidia runtime configuration
# Restart containerd if needed
sudo systemctl restart containerd
```

### Pod Stuck in Pending

```bash
# Check pod events
kubectl describe pod gpu-pod

# Common errors:
# - "Insufficient nvidia.com/gpu" → Device plugin not running or GPU not detected
```

### Verify Runtime Configuration

```bash
# Test NVIDIA runtime with a simple container
sudo ctr run --rm --runtime io.containerd.runc.v2 \
  --runc-binary /usr/bin/nvidia-container-runtime \
  docker.io/nvidia/cuda:12.3.2-base-ubuntu22.04 \
  test-gpu nvidia-smi
```

## Key Files and Locations

- **Containerd NVIDIA config**: `/etc/containerd/conf.d/99-nvidia.toml`
- **CDI specification**: `/etc/cdi/nvidia.yaml`
- **NVIDIA Container Toolkit repo**: `/etc/yum.repos.d/nvidia-container-toolkit.repo`
- **Device plugin manifest**: Applied from GitHub, runs in `kube-system` namespace

## Resources

- [NVIDIA Container Toolkit Documentation](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/latest/index.html)
- [NVIDIA k8s-device-plugin](https://github.com/NVIDIA/k8s-device-plugin)
- [Kubernetes Device Plugins](https://kubernetes.io/docs/concepts/extend-kubernetes/compute-storage-net/device-plugins/)
