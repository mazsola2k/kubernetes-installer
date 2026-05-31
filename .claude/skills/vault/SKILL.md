---
name: vault
description: >-
  Install, uninstall, check status of, or attach OTel telemetry to HashiCorp
  Vault (Helm) via hashicorp-vault-service-controller.yaml — actions
  install/uninstall/status/otel. Use when the user wants to deploy, remove,
  inspect, or instrument Vault, which backs admin credentials across this stack.
---

# HashiCorp Vault (Helm) — lifecycle

Controller: **`hashicorp-vault-service-controller.yaml`** — variable **`action`**
(default `install`), namespace `vault_namespace` (default `default`).

```bash
ansible-playbook hashicorp-vault-service-controller.yaml -e action=<install|uninstall|status|otel>
```

| action | Task file | What it does |
|--------|-----------|--------------|
| `install` | `hashicorp-vault-service/hashicorp-vault-service-install.yaml` | Deploy Vault via Helm. |
| `uninstall` | `…-uninstall.yaml` | Remove Vault (destructive — confirm; this wipes secrets other components rely on). |
| `status` | `…-status.yaml` | Report Vault pod/seal/service state. |
| `otel` | `…-otel.yaml` | Attach the OTel sidecar/telemetry to Vault. |

Why it matters: Vault stores admin passwords/policies used by the Windows Server, RHEL, and
Oracle deployments. Removing it can strand those credentials — confirm before `uninstall`.

There is also a thin alternate entrypoint, `vault-hashicorp-controller.yaml`, with the same
`install`/`uninstall`/`status`/`otel` actions. Prefer `hashicorp-vault-service-controller.yaml`.
Broader telemetry (collector + multi-target endpoints) is the `otel` skill.

Reference: `hashicorp-vault-service-controller.yaml`, `hashicorp-vault-service/`,
`test-vault-access.yaml`. Report actual results; confirm before `uninstall`; never print tokens.
