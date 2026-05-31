---
name: otel
description: >-
  Install, uninstall, or check status of OpenTelemetry collection via
  otel-controller.yaml, selecting components (collector, vault, redhat, windows,
  oracle) and wiring their endpoints/tokens. Use when the user wants to deploy or
  manage telemetry/observability export across the stack.
---

# OpenTelemetry collection — lifecycle

Controller: **`otel-controller.yaml`** — variable **`action`** (`install|uninstall|status`),
with **component selection**. Components install telemetry for different targets.

```bash
# component list as JSON, comma string, or YAML list (any of these forms work)
ansible-playbook otel-controller.yaml -e action=install -e otel_install_components='["collector","vault"]'
ansible-playbook otel-controller.yaml -e action=install -e component="collector,vault"
ansible-playbook otel-controller.yaml -e action=uninstall
ansible-playbook otel-controller.yaml -e action=status
```

Components (default `collector`):
- `collector` — the OTel Collector (`otel/opentelemetry-collector-contrib`, image overridable via `otel_collector_image`).
- `vault` — Vault telemetry (`vault_otel_endpoint`, `vault_otel_token`/`vault_metrics_token`; token can come from `/root/.vault-token`).
- `redhat` — RHEL VM telemetry (`redhat_vm_name`, `redhat_vm_namespace`, `redhat_otel_endpoint`, `redhat_otel_token`).
- `windows` — Windows VM telemetry (`windows_vm_name`/`vmName`, endpoint/token).
- `oracle` — Oracle telemetry (`oracle_otel_endpoint`, `oracle_otel_token`).

Namespace: `otel_namespace` (default `default`). Endpoint/token vars default to placeholder
strings — supply real values per selected component for a working export.

Notes:
- Vault-specific telemetry can also be attached via the `vault` skill's `action=otel`.
- Windows in-guest telemetry (OS/MSSQL counters) is installed by the `windows-automation` skill.

Reference: `otel-controller.yaml`, `otel/`, `manifest-controller/otel-telemetry-*.yaml`.
Report actual results; confirm before `uninstall`; never print endpoints' tokens.
