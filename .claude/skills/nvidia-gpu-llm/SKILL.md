---
name: nvidia-gpu-llm
description: >-
  Deploy, check, or remove an Ollama-style GPU LLM inference pod via
  nvidia-gpu-llm-controller.yaml (install / status / uninstall), with model,
  GPU count, resources, optional Service and persistent storage. Use when the
  user wants to run an LLM on a Kubernetes GPU pod.
---

# NVIDIA GPU LLM pod (Ollama) — lifecycle

Controller: **`nvidia-gpu-llm-controller.yaml`** (variable `action` → internal `llm_action`).
Defaults target Ollama (`model=tinyllama`, service port `11434`).

```bash
ansible-playbook nvidia-gpu-llm-controller.yaml -e action=<install|status|uninstall> \
  [ -e model=tinyllama ] [ -e llmName=gpu-llm-pod ] [ -e gpuCount=1 ] \
  [ -e serviceEnabled=true -e servicePort=11434 ] [ -e persistentStorage=true -e storageSize=10Gi ]
```

| action | Task file | What it does |
|--------|-----------|--------------|
| `install` | `nvidia-gpu/nvidia-gpu-llm-install-tasks.yaml` | Create the GPU LLM pod (+ optional Service/PVC). |
| `status` | `nvidia-gpu/nvidia-gpu-llm-status-tasks.yaml` | Report pod state; runs sample `prompts`. |
| `uninstall` | `nvidia-gpu/nvidia-gpu-llm-uninstall-tasks.yaml` | Remove the pod (confirm). |

Tunable vars (camelCase): `model`, `llmName`, `namespace`, `gpuCount` (1), `memory` (4Gi),
`cpuCores` (2), `serviceEnabled` (false), `servicePort` (11434), `prompts` (list),
`persistentStorage` (false), `storageSize` (10Gi), `imagePullPolicy`, `keepAlive`.

Prereqs: cluster + the NVIDIA GPU device-plugin stack (`nvidia-gpu` skill) so the pod can claim a GPU.

Reference: `nvidia-gpu-llm-controller.yaml`, `manifest-controller/nvidia-gpu-llm-*.yaml`,
`README-nvidia-gpu-llm-operator.md`. Report actual results; confirm before `uninstall`.
