---
name: windows-automation
description: >-
  Post-provisioning automation for an existing Windows Server VM via
  windows-automation-controller.yaml — installs MSSQL, OS/MSSQL OTel telemetry,
  and Selenium browser automation, driven over WinRM with Vault-backed
  credentials. Use to configure/instrument a Windows Server guest after it is built.
---

# Windows Server post-provisioning automation

Controller: **`windows-automation-controller.yaml`**. This runs *against an already-built*
Windows Server VM (default `vm_name=win2025server`). It port-forwards **Vault** (`:8200`) for
credentials, connects to the guest over **WinRM**, and applies automation: **MSSQL** install,
**OTel** telemetry (OS and/or MSSQL counters), and **Selenium** browser automation (creates a
`seleniumuser`).

```bash
# OTel telemetry (OS + MSSQL) on an existing Windows VM
ansible-playbook windows-automation-controller.yaml \
  -e vm_name=win2025server -e otel=true -e otel_config="os,mssql" \
  -e otel_endpoint="https://observe.example.com/v2/otel" -e otel_token="<token>"
```

Key vars:
- `vm_name` (default `win2025server`), `kubevirt_namespace` (default `default`).
- `otel` (bool), `otel_config` — `os`, `mssql`, `os,mssql`, or empty.
- `otel_endpoint`, `otel_token`.
- MSSQL install flags and Selenium tasks are tag-gated (see the controller's tasks).

Prereqs: the Windows VM exists and WinRM is reachable (build it with the `windows-server` skill),
KubeVirt running, and Vault deployed (`vault` skill) for credential retrieval. The Vault
port-forward helper is `library/start_portforward.sh`.

Relationship to other skills:
- Build/lifecycle of the Windows Server VM itself → `windows-server`.
- Cluster-side / multi-target telemetry → `otel`.
- This skill is the **in-guest Windows** automation/telemetry layer.

Reference: `windows-automation-controller.yaml`, `library/start_portforward.sh`, `README.md`.
Report actual results; confirm before changes to a live VM; never print Vault tokens/passwords.
