---
name: oracle-rac
description: >-
  Provision and operate configurable Oracle RAC topologies (RAC / Data Guard /
  FSFO) on KubeVirt VMs via oracle-rac-controller.yaml — install, uninstall,
  status, plus AWR/ASH/ADDM diagnostics and synthetic performance tests. Use for
  clustered Oracle, standby/Data Guard, observer/FSFO, or RAC perf/AWR work.
---

# Oracle RAC / Data Guard / FSFO — lifecycle + diagnostics

Controller: **`oracle-rac-controller.yaml`** — variable **`rac_action`** (default `status`).
Topology is chosen by `rac_nodes` / `rac_dataguard` / `rac_fsfo`:

| Topology | rac_nodes | rac_dataguard | rac_fsfo | VMs |
|----------|-----------|---------------|----------|-----|
| A RAC only | 2 | false | false | 2 |
| B RAC + Data Guard | 2 | true | false | 3 |
| C RAC + DG + FSFO | 2 | true | true | 4 |
| D DG only (no RAC) | 0 | true | false | 2 |
| E DG + FSFO (no RAC) | 0 | true | true | 3 |
| F single node | 0 | false | false | — use the **`oracle`** skill instead (controller aborts) |

Validation enforced: `rac_nodes ∈ {0,2}`; `rac_fsfo=true` requires `rac_dataguard=true`.

```bash
ansible-playbook oracle-rac-controller.yaml -e rac_action=install                 # full (defaults: 2 nodes, DG, FSFO)
ansible-playbook oracle-rac-controller.yaml -e rac_action=install -e rac_dataguard=false   # RAC only
ansible-playbook oracle-rac-controller.yaml -e rac_action=status
ansible-playbook oracle-rac-controller.yaml -e rac_action=uninstall
ansible-playbook oracle-rac-controller.yaml -e rac_action=awr                      # AWR/ASH/ADDM/SQL Monitor/health
ansible-playbook oracle-rac-controller.yaml -e rac_action=awr -e "awr_begin_time='2026-03-21 10:00'" -e "awr_end_time='2026-03-21 12:00'"
ansible-playbook oracle-rac-controller.yaml -e rac_action=perftest                 # synthetic workload
ansible-playbook oracle-rac-controller.yaml -e rac_action=perftest -e perf_duration=600 -e perf_parallel=8
```

| rac_action | What it does (install runs these in order, gated by topology) |
|------------|----------------------------------------------------------------|
| `install` | preflight → L2 VXLAN interconnect → shared ASM disks → node VMs → Grid+ASM → RAC DB → standby+RMAN duplicate (DG) → DG Broker → FSFO observer. |
| `status` | `oracle-rac/rac-status.yaml`. |
| `awr` | Diagnostics (`rac-diagnostics.yaml`): AWR/ASH/ADDM/SQL Monitor/SQL Tuning/health. Time range (`awr_begin_time`/`awr_end_time`), snap IDs (`awr_begin_snap`/`awr_end_snap`), or fresh (`awr_wait_secs`). |
| `perftest` | Synthetic workload (`rac-performance-test.yaml`): `perf_duration`, `perf_parallel`, `perf_cleanup`. |
| `uninstall` | Reverse order: observer → standby → node VMs → shared disks → VXLAN network (destructive — confirm). |

Key vars: VM sizing (`rac_node_cpu/memory/disk`, standby/observer), ASM disk sizes
(`rac_asm_data_size`/`fra`/`vote`, `rac_shared_disk_path`), interconnect
(`rac_interconnect_subnet` 192.168.10.0/24, `rac_vxlan_id` 100, bridge `br-vm`), Oracle
(`rac_db_name`, `rac_pdb_name`, `rac_scan_name`, `rac_oracle_password`, `rac_vault_secret`),
base image `qcow2_image_path` (`./rhel-9.6-x86_64-kvm.qcow2`), and `subscription_username`/
`subscription_password` (env). Static IPs in `192.168.10.0/24` (nodes .11/.12, standby .13,
observer .14, SCAN .100).

Prereqs: KubeVirt + RHEL base image + (for subscribed guests) Red Hat creds. Shares the `br-vm`
bridge with the Windows streaming stack.

Reference: `oracle-rac-controller.yaml`, `oracle-rac/`, `README-oracle-rac.md`.
Confirm topology and `rac_action` before install/uninstall; report actual results; don't echo secrets.
