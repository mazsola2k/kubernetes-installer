---
name: windows-client
description: >-
  Drive and orchestrate the Windows 11 KubeVirt VM lifecycle in this repo
  (windows-client-controller.yaml): install / reinstall / uninstall / status,
  GPU passthrough setup and switchover (claim/release between Windows and
  Fedora/CUDA), NVIDIA driver install, bridge networking, and the
  Sunshine/Moonlight RTX-3090 streaming stack (Virtual Display Driver, NVENC,
  VB-CABLE audio) — including end-to-end troubleshooting of "no video / no audio"
  streaming faults. Use whenever the user wants to build, repair, switch, or
  debug the win11client GPU VM or its Moonlight streaming.
---

# Windows 11 KubeVirt GPU VM — orchestrator

You orchestrate the Windows 11 VM via **`windows-client-controller.yaml`** (Ansible)
plus host-side checks and WinRM diagnostics. Always run from the repo root
(`/home/mazsola/kubernetes-installer`). The Ansible venv is `.venv`
(`/opt/kubevirt-ansible-venv` may also exist — the controller sets its own interpreter).

Command pattern:
```bash
ansible-playbook windows-client-controller.yaml -e action=<ACTION> [ -e key=value ... ]
```

## Decide what the user wants, then pick the action(s)

| Intent | action | Notes |
|--------|--------|-------|
| Build the VM **with GPU** | `install` | Builds VM, firewall rules, Sunshine externalIPs svc. Needs the bridge NAD to exist first (`network-install`) and GPU bound (`gpu-setup`+`gpu-claim`). |
| Build the VM **without GPU** | `install-nogpu` | Plain VM, no passthrough. |
| Rebuild | `reinstall` / `reinstall-nogpu` | uninstall → install. |
| Remove the VM (+PVCs) | `uninstall` | Destructive — confirm with the user first. |
| Show state | `status` | VMI/pod/IP, connect hints. |
| One-time GPU host prep | `gpu-setup` | vfio/IOMMU config; usually needs `sudo reboot` after. Add `-e gpu_confirm=yes` to skip the prompt. |
| **Switchover → Windows** | `gpu-claim` | nvidia→vfio-pci, starts the VM, **auto-reapplies the full-path GSO/offload fix + br-vm host IP** (so streaming works after every claim). |
| **Switchover → Fedora/CUDA** | `gpu-release` | stops the VM, vfio-pci→nvidia (no reboot). |
| Install NVIDIA driver in guest | `nvidia-driver` | over WinRM. |
| Bridge + Multus NAD + offload fix | `network-install` | Creates `br-vm` (192.168.100.1/24) + `win-lan` NAD, and disables offloads on the **whole** VM→br-vm path (br-vm, veths, pod-netns tap/k6t/nic). **Re-run after any VM/pod restart** (offloads reset). |
| Remove NAD | `network-uninstall` | bridge kept if shared with RAC. |
| Install Sunshine **+ streaming capture stack (turnkey)** | `sunshine-install` | Installs Sunshine **and** runs the capture stack (VDD + primary display + VB-CABLE audio + NVENC + hardened service). `-e sunshine_configure_capture=false` = binary only. |
| Repair/(re)configure streaming | `sunshine-fix` | Service→LocalSystem, VDD + `VddSetPrimary` logon task, VB-CABLE audio, `sunshine.conf` (nvenc, dd_configuration_option=disabled, audio_sink). Idempotent. |

Useful overrides (pass with `-e`): `vm_name` (default `win11client`), `kubevirt_namespace`
(default `default`), `windows_admin_password` (default `SecureP@ssw0rd!`),
`sunshine_install_vdd`, `sunshine_install_audio`, `sunshine_reboot` (auto|true|false),
`sunshine_stream_width`/`sunshine_stream_height`, `sunshine_vdd_gpu`,
`gpu_pci_slot` (default `0000:03:00.0`), `nvidia_driver_version`.

## Orchestration recipes

**Fresh end-to-end GPU streaming deploy (from nothing):**
```bash
ansible-playbook windows-client-controller.yaml -e action=gpu-setup -e gpu_confirm=yes   # then: sudo reboot (one-time host prep)
ansible-playbook windows-client-controller.yaml -e action=network-install                # bridge + NAD (BEFORE the VM)
ansible-playbook windows-client-controller.yaml -e action=install                        # build the GPU VM
ansible-playbook windows-client-controller.yaml -e action=nvidia-driver                  # GPU driver in guest
ansible-playbook windows-client-controller.yaml -e action=sunshine-install               # Sunshine + capture stack (turnkey)
ansible-playbook windows-client-controller.yaml -e action=network-install                # re-run: full-path offload fix now the VM is up
```
Why `network-install` twice: the NAD must exist *before* the VM (so it gets `eth1`), but the
GSO/offload fix on the tap/k6t/veth hops can only be applied *after* the VM's pod netns exists.

**Switch the GPU between Windows and Fedora/AI:**
```bash
ansible-playbook windows-client-controller.yaml -e action=gpu-claim     # → Windows (auto-fixes offloads)
ansible-playbook windows-client-controller.yaml -e action=gpu-release   # → Fedora/CUDA
```

**Repair streaming only:** `sunshine-fix` (guest) + `network-install` (host offloads).

Confirm intent and the active `vm_name`/namespace before destructive actions (`uninstall`,
`reinstall`). Stream/connect to Moonlight at **`192.168.100.10`** (the bridge IP) — not the node IP.

## Connecting / verifying a stream
- Sunshine web UI: `https://192.168.100.10:47990` (set user/pass, enter Moonlight PIN).
- Moonlight (host): `flatpak run com.moonlight_stream.Moonlight`, add `192.168.100.10`.
- `virtctl vnc win11client -n default` shows only the emulated QEMU display, **never** the
  streamed VDD/3090 head — that's expected, not a fault.

## Troubleshooting playbook (Moonlight "no video / no audio")

Diagnosed/verified faults, in order. The capture/encode happens in the guest; the wire is br-vm.

**WinRM into the guest** (host can reach the VM directly once br-vm has its IP):
```python
# /tmp/wq.py — pipe PowerShell on stdin
import sys, winrm
s = winrm.Session('http://192.168.100.10:5985/wsman',
                  auth=('Administrator','SecureP@ssw0rd!'), transport='basic')
r = s.run_ps(sys.stdin.read()); sys.stdout.write(r.std_out.decode(errors='replace'))
sys.exit(r.status_code)
```
Run with `.venv/bin/python /tmp/wq.py <<'PS' ... PS`. If unreachable, ensure br-vm has its host
IP (`action=network-install`) or start a port-forward:
`kubectl -n default port-forward service/win11client-winrm 5985:5985` and target `localhost:5985`.

1. **Service** — must be Running / Automatic / LocalSystem:
   `Get-CimInstance Win32_Service -Filter "Name='SunshineService'" | ft State,StartMode,StartName`
   Fix: `action=sunshine-fix`.

2. **Capture / encoder** — `C:\Program Files\Sunshine\config\sunshine.log` during a stream:
   - WRONG: `Microsoft Basic Render Driver … 1280x800 … encoder [libx264]` → VDD not primary.
   - RIGHT: `NVIDIA GeForce RTX 3090 … 1920x1080 … encoder [hevc_nvenc]`.
   Probe topology in the interactive session: `C:\Program Files\Sunshine\tools\dxgi-info.exe`
   (the 3090 must list an attached OUTPUT). Fix: `action=sunshine-fix` (sets VDD primary +
   re-asserts it via the `VddSetPrimary` logon task).

3. **Network GSO truncation** — VM sends UDP 47998 but packets arrive on br-vm as
   `truncated-udplength 0` and Moonlight drops them. Offloads must be off on the **whole** path
   (br-vm + veths + pod-netns tap/k6t/nic), not just br-vm:
   ```bash
   sudo tcpdump -ni br-vm 'udp port 47998' -c 20   # want "UDP, length ~1100", NOT truncated
   ```
   Fix: `action=network-install` (also auto-applied by `gpu-claim`). Reapply after VM restarts.

4. **Audio (no sound)** — `sunshine.log` shows `Couldn't get default audio endpoint [0x80070490]`
   (headless VM has no active render endpoint). Fix: VB-CABLE virtual sink (installed by
   `sunshine-install`/`sunshine-fix`). Verify:
   `& 'C:\Program Files\Sunshine\tools\audio-info.exe'` → expect one Active "Speakers
   (VB-Audio Virtual Cable)". App audio routes into VB-CABLE and is heard on the Moonlight client,
   not the VM.

**Definitive in-VM packet check** (avoids host-side timing/interface ambiguity): use Windows
`pktmon` filtered by the client IP (`pktmon filter add -i 192.168.100.1`), start
`pktmon start --capture`, stream, stop, `pktmon etl2txt`. If the VM sends 47998 but br-vm shows
truncated → offload path; if it sends nothing → capture/encoder.

## Driver-signing notes (when adding virtual devices)
- VDD (VirtualDrivers signed 25.5.2) and VB-CABLE (VB-Audio) are Microsoft-cross-signed → load
  **without** test-signing. Just import the publisher cert so `pnputil` accepts the catalog.
- The MTT *audio* driver is SignPath-signed → hits **Code 52** under Driver Signature
  Enforcement and would need test-signing (which paints a "Test Mode" watermark *into the
  stream*). Prefer VB-CABLE. Root device nodes are created with `nefconw`; defaults set with `nircmd`.

## References
- Controller: `windows-client-controller.yaml`
- Playbooks: `windows-client/windows11-install.yaml`, `windows11-gpu-setup.yaml`,
  `windows11-sunshine-install.yaml`, `windows11-sunshine-fix.yaml`,
  `windows-network-install.yaml`, `windows11-status.yaml`, `windows11-uninstall.yaml`
- Full write-up (architecture, config table, troubleshooting): `windows-client/README.md`

Always report what you ran and its real result; if a step is skipped or fails, say so with the
output. Confirm before destructive or GPU-switching actions.
