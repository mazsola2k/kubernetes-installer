---
name: kubevirt
description: >-
  Install, uninstall, or check status of KubeVirt (VM virtualization on
  Kubernetes) via k8s-redhat-kubevirt-controller.yaml. Required before any VM
  skill (windows-client, windows-server, redhat-server VM, oracle*). Use to
  enable, remove, or inspect KubeVirt.
---

# KubeVirt — lifecycle

Controller: **`k8s-redhat-kubevirt-controller.yaml`** (`become: yes`, variable
**`kubevirt_action`**, and a **`vars_prompt`** — pass `-e kubevirt_action=...` to stay
non-interactive).

```bash
ansible-playbook k8s-redhat-kubevirt-controller.yaml -e kubevirt_action=<install|uninstall|status>
```

| kubevirt_action | Task file | What it does |
|-----------------|-----------|--------------|
| `install` | `kubevirt/k8s-redhat-kubevirt-install-tasks.yaml` | Deploy the KubeVirt operator + CR (and CDI); wait for virt-api/controller/handler. |
| `uninstall` | `…-uninstall-tasks.yaml` | Remove KubeVirt (destructive — confirm). |
| `status` | `…-status-tasks.yaml` | Report KubeVirt CR/component state. |

Requires the base cluster first (`kubernetes` skill). Everything that boots a VM
(`windows-client`, `windows-server`, `redhat-server` with `kind=VirtualMachine`, `oracle`,
`oracle-rac`) depends on this.

Reference: `k8s-redhat-kubevirt-controller.yaml`, `kubevirt/`, `README.md`.
Confirm before `uninstall`; report actual results.
