# CLAUDE.md — project orientation

Read this first. It maps how the repo works so you can act fast. Deep dives live in the
per-area `README*.md` and in `.claude/skills/<name>/SKILL.md` (one skill per controller —
prefer invoking the matching skill).

## What this is
A single-host platform that runs **containers and KubeVirt VMs side-by-side** on upstream
Kubernetes over RHEL/Fedora. Control-plane services (Vault, OTel), GPU workloads, and Windows/
RHEL/Oracle guests are all reconciled from declarative manifests. Everything is driven two ways:

1. **Ansible controllers** (primary) — root-level `*-controller.yaml` playbooks, each
   action-driven (`-e action=...`), delegating to a same-named task subfolder.
2. **Kopf operator + TUI** (`kopf_opeartor.py`, `modules/`, `manifest-controller/`) — an
   intent-based operator that watches Custom Resources (CRDs/CRs in `manifest-controller/`) and
   invokes the same underlying logic. The urwid TUI manages CRDs/CRs interactively.

## The four layers (how a request flows)
```
CRDs/CRs (manifest-controller/)        ← declarative intent: kind + spec.action + vars
        ↓  reconciled by
Kopf operator + urwid TUI (kopf_opeartor.py, modules/)
        ↓  invokes
Ansible controllers (<area>-controller.yaml)   ← -e action=… dispatch
        ↓  include_tasks
Task playbooks (<area>/ subfolders)            ← the actual kubectl/virtctl/WinRM/Helm work
```
You can enter at **either** the operator level (apply a CR) **or** the controller level (run the
playbook directly). Both converge on the same task playbooks. For ad-hoc/agent work, the
controller level is usually most direct; the operator level is for declarative/GitOps management.

### Operator + manifest layer (`manifest-controller/`, `modules/`)
- **CRDs** define custom kinds under group **`infra.example.com/v1`**:
  `WindowsVM`, `RedHatVM`, `OracleDB`, `OracleRAC`, `NvidiaGpuLlm`, `MSSQLServer`, `OTelTelemetry`.
- **CRs** carry `spec.action` (install/uninstall/status/…) **plus the same variables** the matching
  controller accepts (e.g. `WindowsVM` spec ≈ `windows-server-controller.yaml` vars).
- **`kopf_opeartor.py`** boots the Kopf operator (in a thread) + an **urwid TUI** to create/manage
  CRDs/CRs. `modules/kopf_handlers.py` = reconcile handlers; `modules/service_managers.py` maps a
  CR ↔ its controller and reports drift (Local CR vs Deployed CR `action` vs actual VM/pod status);
  `modules/tui_interface.py` = the TUI; `modules/utils/` = k8s client, logging, var helpers.
- So: **kind → controller** mapping mirrors the component table below (WindowsVM→windows-server,
  RedHatVM→redhat-server, OracleDB→oracle, OracleRAC→oracle-rac, NvidiaGpuLlm→nvidia-gpu-llm,
  OTelTelemetry→otel, MSSQLServer→windows-automation MSSQL path).

## Controller pattern
`ansible-playbook <area>-controller.yaml -e <action_var>=<install|uninstall|status|...> [ -e k=v ]`
- Controllers run on `hosts: localhost` (the host IS the cluster node). Many use `become: yes`.
- The action variable name varies per controller (see table). Validation fails on bad actions.
- Task files live in the same-named subfolder (e.g. `kubevirt/`, `windows-client/`, `oracle-rac/`).

## Component map (controller → skill → action var → notes)
| Area | Controller | Skill | Action var | Notes / gotchas |
|------|-----------|-------|-----------|-----------------|
| Base cluster | `k8s-redhat-kubernetes-controller.yaml` | `kubernetes` | `k8s_action` | interactive `vars_prompt` — always pass `-e`. Foundation. |
| Virtualization | `k8s-redhat-kubevirt-controller.yaml` | `kubevirt` | `kubevirt_action` | needs base cluster; required by all VMs. |
| GPU for pods | `nvidia-gpu-controller.yaml` | `nvidia-gpu` | `gpu_action` | Fedora-only; drive with `-e gpu_action=` (not just `--tags`). Host NVIDIA drivers req'd. |
| GPU LLM pod | `nvidia-gpu-llm-controller.yaml` | `nvidia-gpu-llm` | `action`→`llm_action` | Ollama (`model`, port 11434). |
| Vault | `hashicorp-vault-service-controller.yaml` | `vault` | `action` | `install/uninstall/status/otel` (Helm). Backs creds for VMs. Alt: `vault-hashicorp-controller.yaml`. |
| Telemetry | `otel-controller.yaml` | `otel` | `action` | component select: collector/vault/redhat/windows/oracle. |
| Windows 11 GPU client | `windows-client-controller.yaml` | `windows-client` | `action` | GPU passthrough + Sunshine/Moonlight streaming (see below). |
| Windows Server | `windows-server-controller.yaml` | `windows-server` | `action` | `windows_version=2019\|2025` required. |
| Windows in-guest automation | `windows-automation-controller.yaml` | `windows-automation` | tags/vars | MSSQL + OTel(os/mssql) + Selenium over WinRM, Vault-backed. |
| RHEL guest | `redhat-server-controller.yaml` | `redhat-server` | `action` | `kind=Container`(default)\|`VirtualMachine`; `REDHAT_REGISTRY_*` env. |
| Oracle (single) | `oracle-controller.yaml` | `oracle` | `oracle_action` | `vm_name`+`kubevirt_namespace` required. |
| Oracle RAC/DG/FSFO | `oracle-rac-controller.yaml` | `oracle-rac` | `rac_action` | topology matrix; also `awr`/`perftest`. |

## Dependency / bring-up order
`kubernetes` → `kubevirt` → then in parallel as needed: `vault`, `otel`, `nvidia-gpu`
(+`nvidia-gpu-llm`), and the VMs (`windows-client`, `windows-server`, `redhat-server`,
`oracle`/`oracle-rac`). Vault should exist before guests that store creds in it.

## Cross-cutting layers
- **Kubernetes (base):** upstream kubeadm cluster on the Fedora host, containerd runtime, Calico
  CNI (`10.244.x` pod net). Everything else sits on top. → `kubernetes` skill.
- **KubeVirt (virtualization):** operator + CDI; turns CRs/VM specs into libvirt/QEMU domains.
  KubeVirt **IS QEMU** — a VM = a `virt-launcher` pod wrapping `qemu-system-x86_64` (+ a
  `hook-sidecar` for ROM/firmware tweaks on GPU VMs). → `kubevirt` skill.
- **Containers vs VMs:** container workloads (operators, collectors, RHEL container) run as pods;
  guests (Windows/RHEL/Oracle) run as KubeVirt VMs. `redhat-server` can do **either** via `kind=`.
- **Networking:** pod net (Calico) for cluster traffic; **`br-vm` (Multus `win-lan`,
  192.168.100.1/24)** gives VMs a real LAN NIC for direct access/streaming; Oracle RAC adds an L2
  **VXLAN** interconnect (192.168.10.0/24). GSO/offload state on the VM→bridge path is fragile and
  resets on VM restart (see streaming section).
- **Storage:** VM disks/PVCs under `/var/lib/kubevirt` and `/data/vms`; CDI imports media; large
  media (ISOs/VHDX/qcow2/Oracle RPMs) sit at repo root and are git-ignored where huge.
- **Secrets:** **Vault** (Helm) holds admin passwords/policies; controllers read/seed it and
  port-forward `:8200`. Red Hat registry/subscription creds come from env vars. Never echo secrets.
- **Telemetry / observability:** the **`otel`** controller deploys an OpenTelemetry Collector and
  wires per-target exporters (`collector`, `vault`, `redhat`, `windows`, `oracle`) to external
  endpoints/tokens; Vault can also self-attach telemetry (`vault` action `otel`); Windows in-guest
  OS/MSSQL counters are installed by `windows-automation`. CR-driven via the `OTelTelemetry` kind.

## Host / environment facts
- Single node: `k8sp.modernhackers.com`, Fedora, KubeVirt v1.3.x, Calico pod net `10.244.x`.
- **`br-vm` bridge `192.168.100.1/24`** — Multus `win-lan` NAD gives VMs a real LAN NIC (`eth1`,
  e.g. `192.168.100.10`). Shared with Oracle RAC (which adds a VXLAN interconnect `192.168.10.0/24`).
- GPU: RTX 3090 at PCI `0000:03:00.0`, switched between host (`nvidia`) and VM (`vfio-pci`).
- Two Python venvs exist: repo `.venv` (windows-server/automation use it) and
  `/opt/kubevirt-ansible-venv` (windows-client controller sets this interpreter). Use the venv
  that a given controller references.

## Conventions you'll need
- **WinRM into Windows guests:** HTTP port 5985, `Administrator` / `SecureP@ssw0rd!` (default),
  basic transport. Reach via the bridge IP directly (`http://192.168.100.10:5985/wsman`) once
  `br-vm` has its host IP, or port-forward: `kubectl -n default port-forward service/<vm>-winrm 5985:5985`.
- **Port-forward helper:** `library/start_portforward.sh <svc> <port> <ns> <log> <pid>` (detached, survives task exit).
- **Vault:** secrets/admin passwords live in Vault; port-forward `vault` `:8200`. Never print tokens/passwords.
- **VM control:** `virtctl start|stop|vnc|console <vm> -n <ns>`. `virtctl vnc` shows only the
  emulated QEMU display, never a passthrough-GPU / virtual-display head.

## GPU streaming stack (windows-client) — the most-worked, most-subtle area
Goal: stream the passed-through RTX 3090 desktop from the Win11 VM to Moonlight. Working state
required **all** of:
1. `SunshineService` = Running / Automatic / **LocalSystem**.
2. **Virtual Display Driver** head bound to the 3090, **set as primary** (re-asserted each boot by
   the `VddSetPrimary` logon task) → Sunshine captures the 3090 with **NVENC** (else it grabs the
   WARP/QEMU 1280×800 software display).
3. `sunshine.conf`: `encoder=nvenc`, `dd_configuration_option=disabled` (+ `audio_sink`).
4. **VB-CABLE** virtual audio sink (default device) for sound.
5. **GSO/offloads OFF on the WHOLE path** (br-vm + veths + pod-netns `tap*`/`k6t-*`/`*-nic`) — else
   UDP 47998 video arrives `truncated-udplength 0` and Moonlight drops it.
Automated by: `action=sunshine-install` (turnkey: Sunshine + capture stack), `action=sunshine-fix`
(repair), `action=network-install` (full-path offload fix), and `action=gpu-claim` (re-applies the
offload fix after every VM start). Full write-up: `windows-client/README.md`. Driver-signing note:
VDD + VB-CABLE are MS-cross-signed (no test-signing); the MTT audio driver is not (Code 52).

## Working rules
- Prefer the matching skill in `.claude/skills/`. Confirm `vm_name`/namespace/version before
  destructive (`uninstall`/`reinstall`) or GPU-switching actions.
- After a VM/pod restart, re-run `network-install` (offloads reset) — or rely on `gpu-claim`.
- Report real playbook output; if a step is skipped or fails, say so. Don't echo secrets.

## Key references
- `README.md` (top-level overview), `windows-client/README.md` (GPU + streaming, deepest doc),
  `README-nvidia-gpu-setup.md`, `README-nvidia-gpu-llm-operator.md`, `README-oracle-rac.md`,
  `windows-client/kubevirt-gpu-wiki.md`, `fedora44-upgrade.md`.
- Operator/TUI: `kopf_opeartor.py`, `modules/`, CRDs/CRs in `manifest-controller/`.
