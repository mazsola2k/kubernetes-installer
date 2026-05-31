---
name: windows-server
description: >-
  Manage Windows Server 2019/2025 KubeVirt VMs via windows-server-controller.yaml
  — install, uninstall, reinstall, status — with version-specific sizing, VHD
  download, Vault-backed admin password, and optional product key. Use when the
  user wants to build, remove, rebuild, or check a Windows Server guest VM.
---

# Windows Server 2019 / 2025 (KubeVirt) — lifecycle

Controller: **`windows-server-controller.yaml`**. **`windows_version` (2019|2025) is required.**

```bash
ansible-playbook windows-server-controller.yaml -e action=<install|uninstall|reinstall|status> \
  -e windows_version=<2019|2025> [ -e key=value ]
```

| action | What it does |
|--------|--------------|
| `install` | Build the VM from the version's VHD (downloads if absent). |
| `uninstall` | Remove the VM (destructive — confirm). |
| `reinstall` | uninstall → 15s pause → install. |
| `status` | Report VM/VMI state (uses the Vault secret for creds). |

Version-specific defaults (auto-set by the controller):
- **2019** → 4 vCPU / 8Gi / 25Gi disk, `win2019server.vhd`, default `vm_name=win2019server`.
- **2025** → 6 vCPU / 12Gi / 30Gi disk, `win2025server.vhdx`, default `vm_name=win2025server`.

Common overrides: `vmName`, `admin_password` (default `SecureP@ssw0rd!`), `vhd_url`
(custom VHD), `product_key`, `vault_secret` (default `secret/data/windows-server-2025/admin`),
`kubevirt_namespace`.

Notes:
- Requires KubeVirt (`kubevirt` skill).
- Post-provisioning automation (MSSQL, OTel telemetry, Selenium) → `windows-automation` skill.
- For the **GPU streaming Windows 11 client**, use the `windows-client` skill instead.

Reference: `windows-server-controller.yaml`, `windows-server/`. Confirm `windows_version`/`vm_name`
before destructive actions; report actual results; don't echo passwords/keys.
