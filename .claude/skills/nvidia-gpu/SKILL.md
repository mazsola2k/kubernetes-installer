---
name: nvidia-gpu
description: >-
  Install, check, or uninstall the NVIDIA GPU stack (device plugin + CDI +
  containerd config) so Kubernetes pods can request GPUs, via
  nvidia-gpu-controller.yaml. Fedora host with host NVIDIA drivers already
  installed. Use for container GPU scheduling — NOT VM passthrough.
---

# NVIDIA GPU for Kubernetes (device plugin / CDI) — lifecycle

Controller: **`nvidia-gpu-controller.yaml`** (`become: yes`, **Fedora-only** — it asserts
`ansible_distribution == "Fedora"`). Installs the NVIDIA device plugin (`v0.16.2`), writes
containerd config (`/etc/containerd/conf.d`) and CDI (`/etc/cdi/nvidia.yaml`).

**Reliable invocation — drive with `gpu_action`** (the task `when:` conditions key off
`action = gpu_action | default('install')`):
```bash
ansible-playbook nvidia-gpu-controller.yaml -e gpu_action=install
ansible-playbook nvidia-gpu-controller.yaml -e gpu_action=status
ansible-playbook nvidia-gpu-controller.yaml -e gpu_action=uninstall
```
The header documents `--tags install|status|uninstall`; `--tags install` works because the
default action is `install`, but `--tags status`/`uninstall` alone will be skipped by the
`when` unless you also pass `-e gpu_action=...`. Prefer the `-e gpu_action=` form.

| gpu_action | Task file |
|------------|-----------|
| `install` | `nvidia-gpu/nvidia-gpu-install-tasks.yaml` |
| `status` | `nvidia-gpu/nvidia-gpu-status-tasks.yaml` |
| `uninstall` | `nvidia-gpu/nvidia-gpu-uninstall-tasks.yaml` (confirm first) |

Prereqs: NVIDIA hardware, **host NVIDIA drivers already installed**, cluster running with
containerd. This is for **pods** that request GPUs. For passing a GPU into a Windows VM, use
`windows-client` (`gpu-setup`/`gpu-claim`/`gpu-release`); to run an LLM pod, use `nvidia-gpu-llm`.

Reference: `nvidia-gpu-controller.yaml`, `nvidia-gpu/`, `README-nvidia-gpu-setup.md`.
Confirm before `uninstall`; report actual results.
