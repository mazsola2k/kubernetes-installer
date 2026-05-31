---
name: oracle
description: >-
  Manage a single-instance Oracle Database on a RHEL KubeVirt VM via
  oracle-controller.yaml — install, uninstall, status (variable oracle_action).
  Use when the user wants to deploy, remove, or check a standalone Oracle DB. For
  clustered Oracle (RAC/Data Guard/FSFO) use the oracle-rac skill instead.
---

# Oracle Database (single instance) — lifecycle

Controller: **`oracle-controller.yaml`** — variable **`oracle_action`** (falls back to `action`
for backward compat; default `status`). It `import_playbook`s the matching
`oracle/oracle-db-{install,uninstall,status}.yaml`.

```bash
ansible-playbook oracle-controller.yaml -e oracle_action=<install|uninstall|status> \
  -e vm_name=<rhel9-vm> -e kubevirt_namespace=<default>
# Clean local artifacts without touching a VM:
ansible-playbook oracle-controller.yaml -e oracle_action=uninstall -e oracle_local_uninstall=true
```

| oracle_action | What it does |
|---------------|--------------|
| `install` | Install Oracle DB onto the target RHEL VM. |
| `uninstall` | Remove the Oracle deployment (destructive — confirm). |
| `status` | Report Oracle/VM state. |

**Required for VM actions** (unless `oracle_local_uninstall=true`): `vm_name` **and**
`kubevirt_namespace` — the controller hard-fails without them.

Prereqs: a running RHEL VM (`redhat-server` with `kind=VirtualMachine`) + KubeVirt.
For RAC/Data Guard/FSFO topologies, AWR/perf diagnostics → use **`oracle-rac`**.

Reference: `oracle-controller.yaml`, `oracle/`, `README.md`.
Report actual results; confirm before `uninstall`.
