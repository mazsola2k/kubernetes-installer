# NVIDIA GPU LLM - Operator Integration

## Architecture Overview

This implementation follows the kopf operator pattern for managing NVIDIA GPU-accelerated LLM workloads in Kubernetes.

## Files Created

### 1. Custom Resource Definition (CRD)
- **File**: `manifest-controller/nvidia-gpu-llm-crd.yaml`
- **API Group**: `infra.example.com/v1`
- **Kind**: `NvidiaGpuLlm`
- **Short Names**: `gpullm`, `llm`

### 2. Custom Resource Example
- **File**: `manifest-controller/nvidia-gpu-llm-cr.yaml`
- **Purpose**: Example CR for deploying TinyLlama model

### 3. Controller Playbook
- **File**: `nvidia-gpu-llm-controller.yaml`
- **Actions**: install, status, uninstall

### 4. Task Files
- **Install**: `nvidia-gpu/nvidia-gpu-llm-install-tasks.yaml`
- **Status**: `nvidia-gpu/nvidia-gpu-llm-status-tasks.yaml`
- **Uninstall**: `nvidia-gpu/nvidia-gpu-llm-uninstall-tasks.yaml`

### 5. Operator Handlers
- **File**: `modules/kopf_handlers.py` (updated)
- **Handlers**: 
  - `handle_nvidiagpullm()` - Create/Update
  - `delete_nvidiagpullm()` - Delete

## Usage

### 1. Register CRD
```bash
kubectl apply -f manifest-controller/nvidia-gpu-llm-crd.yaml
```

### 2. Deploy LLM via Operator
```bash
kubectl apply -f manifest-controller/nvidia-gpu-llm-cr.yaml
```

### 3. Check Status
```bash
kubectl get nvidiagpullms
kubectl get gpullm tinyllama-demo -o yaml
```

### 4. Monitor Operator Logs
```bash
tail -f /tmp/operator.log
```

### 5. Interactive with LLM
```bash
kubectl exec -it gpu-llm-pod -- ollama run tinyllama
```

### 6. Delete Deployment
```bash
kubectl delete nvidiagpullm tinyllama-demo
```

## CR Specification

### Required Fields
- `action`: install | status | uninstall
- `llmName`: Pod name for the LLM deployment

### Optional Fields
- `model`: tinyllama | llama2 | mistral | phi | codellama (default: tinyllama)
- `gpuCount`: Number of GPUs (default: 1)
- `memory`: Memory limit (default: 4Gi)
- `cpuCores`: CPU cores (default: 2)
- `serviceEnabled`: Expose as service (default: false)
- `prompts`: Array of initial prompts to run
- `persistentStorage`: Enable PVC (default: false)
- `keepAlive`: Keep pod running (default: true)

## Status Fields

The operator updates these status fields:
- `phase`: Pending | InProgress | Ready | Failed | Terminating
- `message`: Human-readable status
- `podName`: Name of deployed pod
- `modelLoaded`: Currently loaded model
- `gpuAssigned`: Boolean GPU assignment status
- `conditions`: Array of condition objects

## Workflow

1. User applies NvidiaGpuLlm CR
2. Kopf operator detects the CR
3. Operator calls `handle_nvidiagpullm()`
4. Handler updates CR status to "InProgress"
5. Handler runs `nvidia-gpu-llm-controller.yaml` playbook
6. Playbook includes appropriate task file (install/status/uninstall)
7. Tasks deploy Pod with Ollama + model
8. Handler updates CR status to "Ready" or "Failed"
9. User can interact with deployed LLM

## Integration with Existing Infrastructure

- Uses same patterns as Oracle DB and Windows Server operators
- Follows `infra.example.com` API group convention
- Status tracking with phases and conditions
- Terminal phase guards prevent re-execution
- Full lifecycle management (create, update, delete)

## Prerequisites

- NVIDIA GPU device plugin installed (via `nvidia-gpu-controller.yaml`)
- GPU capacity available in cluster
- Kubernetes collection for Ansible
- jq installed for JSON parsing

## Example CR Variations

### Large Model with Service
```yaml
apiVersion: infra.example.com/v1
kind: NvidiaGpuLlm
metadata:
  name: llama2-service
spec:
  action: install
  llmName: llama2-pod
  model: llama2:7b
  gpuCount: 1
  memory: "8Gi"
  serviceEnabled: true
  servicePort: 11434
  persistentStorage: true
  storageSize: "20Gi"
```

### Status Check
```yaml
apiVersion: infra.example.com/v1
kind: NvidiaGpuLlm
metadata:
  name: check-status
spec:
  action: status
  llmName: gpu-llm-pod
```

### Uninstall
```yaml
apiVersion: infra.example.com/v1
kind: NvidiaGpuLlm
metadata:
  name: cleanup
spec:
  action: uninstall
  llmName: gpu-llm-pod
```
