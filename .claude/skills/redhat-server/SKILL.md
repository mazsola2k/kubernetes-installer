---
name: redhat-server
description: >-
  Deploy RHEL 9 as either a KubeVirt VM or a container via
  redhat-server-controller.yaml — install / uninstall / status — with Red Hat
  registry secret, subscription registration, and Vault-backed credentials. Use
  when the user wants to build, remove, or check a RHEL guest (VM or container).
---

# Red Hat Server (RHEL 9, VM **or** container) — lifecycle

Controller: **`redhat-server-controller.yaml`**. Two dimensions: **`action`** and **`kind`**.

```bash
ansible-playbook redhat-server-controller.yaml -e action=<install|uninstall|status> \
  -e kind=<Container|VirtualMachine>
```

- **`kind`** (default **`Container`**) selects the deployment form:
  - `Container` → `redhat-server/redhat-container-{install,uninstall,status}.yaml`
  - `VirtualMachine` → `redhat-server/redhat-vm-{install,uninstall,status}.yaml`
- **`action`**: `install` | `uninstall` (destructive — confirm) | `status`.

**Prerequisite (both kinds):** a `redhat-registry-secret` is created from env vars if missing —
export `REDHAT_REGISTRY_USERNAME`, `REDHAT_REGISTRY_TOKEN`, `REDHAT_REGISTRY_EMAIL` before running
`install`. The VM form also supports subscription-manager registration + Vault seeding (see the
repo `README.md` "Red Hat Server automation").

Notes / gotchas:
- The default is a **container**, not a VM — if the user means a RHEL *VM*, pass `-e kind=VirtualMachine`.
- VM kind requires KubeVirt (`kubevirt` skill). Oracle DB/RAC run on RHEL VMs (`oracle`, `oracle-rac`).
- Don't echo registry/subscription/Vault secrets.

Reference: `redhat-server-controller.yaml`, `redhat-server/`, `README.md`.
Report the actual result; confirm before `uninstall`.
