---
name: kubernetes
description: >-
  Install, uninstall, or check status of the upstream Kubernetes control plane on
  a RHEL/Fedora host via k8s-redhat-kubernetes-controller.yaml. Foundation layer
  that KubeVirt, the GPU stack, Vault, OTel and all VMs depend on. Use to set up,
  tear down, or inspect the base cluster.
---

# Kubernetes (host control plane) — lifecycle

Controller: **`k8s-redhat-kubernetes-controller.yaml`** — runs `become: yes`, uses the
**`k8s_action`** variable, and has a **`vars_prompt`**: if you don't pass `k8s_action` it will
**prompt interactively**. Always pass `-e k8s_action=...` for non-interactive/automated runs.

```bash
ansible-playbook k8s-redhat-kubernetes-controller.yaml -e k8s_action=<install|uninstall|status>
```

| k8s_action | Task file | What it does |
|------------|-----------|--------------|
| `install` | `kubernetes/k8s-redhat-kubernetes-install-tasks.yaml` | Bring up the upstream cluster on the host. |
| `uninstall` | `…-uninstall-tasks.yaml` | Tear down (destructive — confirm). |
| `status` | `…-status-tasks.yaml` | Report cluster/node/component state. |

This is the **base layer**. Typical bring-up order:
`kubernetes` → `kubevirt` → (nvidia-gpu / vault / otel / VMs).

Reference: `k8s-redhat-kubernetes-controller.yaml`, `kubernetes/`, `README.md`.
Confirm before `uninstall`; report actual results.
