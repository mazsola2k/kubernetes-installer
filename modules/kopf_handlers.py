from modules.utils.var_helpers import get_var


# Global log queue for TUI (import from canonical source)
from modules.utils.logging_config import log_queue

import logging
logger = logging.getLogger(__name__)

# Unified logging helper for TUI and file logger
def log_event(msg):
    logger.info(msg)
    if log_queue:
        log_queue.put(msg)

"""
Kopf handlers for Windows services management
"""


import kopf
import logging
import subprocess
import os
import yaml
import json
from pathlib import Path
from datetime import datetime
from kubernetes import client
from kubernetes.client.rest import ApiException

# Global log queue for TUI (import from canonical source)
from modules.utils.logging_config import log_queue

logger = logging.getLogger(__name__)

REPO_ROOT = Path(__file__).resolve().parents[1]

# Set up operator file logger
operator_log_path = "/tmp/operator.log"
operator_file_handler = logging.FileHandler(operator_log_path, mode='a')
operator_file_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
operator_file_handler.setLevel(logging.INFO)
logger.addHandler(operator_file_handler)

# Optionally suppress noisy Kopf inconsistency logs (set env KOPF_SUPPRESS_INCONSISTENCIES=1)
try:
    if os.getenv('KOPF_SUPPRESS_INCONSISTENCIES', '0') == '1':
        for name in ('kopf.objects', 'kopf.activities', 'kopf.clients.patching'):
            logging.getLogger(name).setLevel(logging.WARNING)
except Exception:
    pass

# Resource definitions
RESOURCES = {
    'windowsvm': {
        'group': 'infra.example.com',
        'version': 'v1',
        'plural': 'windowsvms'
    },
    'mssqlserver': {
        'group': 'infra.example.com', 
        'version': 'v1',
        'plural': 'mssqlservers'
    },
    'windowsotelcollector': {
        'group': 'infra.example.com',
        'version': 'v1', 
        'plural': 'windowsotelcollectors'
    },
    'oteltelemetry': {
        'group': 'infra.example.com',
        'version': 'v1',
        'plural': 'oteltelemetries'
    }
}

# Configure Kopf persistence to reduce status conflicts
@kopf.on.startup()
def configure_kopf(settings: kopf.OperatorSettings, **_):
    try:
        # Move Kopf's internal progress/diffbase storage to annotations to avoid touching .status
        settings.persistence.progress_storage = kopf.AnnotationsProgressStorage(prefix='kopf.windowsvm.dev')
        settings.persistence.diffbase_storage = kopf.AnnotationsDiffBaseStorage(prefix='kopf.windowsvm.dev')
        # Keep posting/info defaults; adjust if you want quieter logs
        log_event("[OPERATOR] Kopf persistence configured to use annotations for progress/diffbase")
    except Exception as e:
        log_event(f"[OPERATOR] Failed to configure Kopf persistence: {e}")

# WindowsVM Handlers
@kopf.on.create('infra.example.com', 'v1', 'windowsvms')
@kopf.on.update('infra.example.com', 'v1', 'windowsvms')
def handle_windowsvm(body, meta, spec, status, namespace, diff, old, new, patch, **kwargs):
    # Guard: skip if already terminal phase
    terminal_phases = ['Ready', 'Failed', 'Skipped']
    if status and status.get('phase') in terminal_phases and status.get('observedGeneration') == meta.get('generation'):
        msg = f"[OPERATOR] Skipping execution for {meta.get('name')} (phase={status.get('phase')})"
        log_event(msg)
        patch.status['phase'] = status.get('phase')
        patch.status['message'] = status.get('message', '')
        patch.status['observedGeneration'] = status.get('observedGeneration')
        return
    log_event("[OPERATOR] handle_windowsvm triggered!")
    name = meta.get('name')
    action = get_var('action', spec, 'install')
    # Always log and run uninstall if action changed to uninstall
    if diff:
        for d in diff:
            if d[1] == ('spec', 'action'):
                log_event(f"[OPERATOR] Detected spec.action change: {d}")
    vm_name = get_var('vmName', spec, name)
    log_event(f"[OPERATOR] CR received: name={name}, action={action}, vm_name={vm_name}")
    # Mark as InProgress at the beginning of processing
    try:
        patch.status['phase'] = 'InProgress'
        patch.status['message'] = f"{action.title()} in progress for VM {vm_name}"
        patch.status['reason'] = 'Processing'
        patch.status['observedGeneration'] = meta.get('generation')
        now = datetime.utcnow().isoformat() + 'Z'
        cond = {
            'type': 'Ready',
            'status': 'False',
            'reason': 'Processing',
            'message': f"{action.title()} in progress for VM {vm_name}",
            'lastTransitionTime': now,
        }
        existing = status.get('conditions', []) if status else []
        patch.status['conditions'] = [c for c in existing if c.get('type') != 'Ready'] + [cond]
    except Exception:
        pass
    try:
        log_event(f"[OPERATOR] Deciding what to do for action={action} on VM {vm_name}")
        kopf.info(body, reason='Processing', message=f'Starting {action} for VM {vm_name}')
        log_event(f"[OPERATOR] Starting {action} for VM {vm_name}")
        playbook_path = str(REPO_ROOT / 'windows-server-controller.yaml')
        # Collect all relevant variables from spec for playbook
        playbook_vars = {
            'action': action,
            'vm_name': vm_name,
            'windows_version': get_var('windows_version', spec, '2025'),
            'kubevirt_namespace': get_var('kubevirt_namespace', spec, namespace),
            'storage_dir': get_var('storage_dir', spec, '/var/lib/kubevirt'),
            'system_disk_size': get_var('system_disk_size', spec, '40Gi'),
            'vhdx_path': get_var('vhdx_path', spec, '/data/vms/win2025server.vhdx'),
            'virtio_iso_size': get_var('virtio_iso_size', spec, '500Mi'),
            'vm_cpu_cores': get_var('vm_cpu_cores', spec, 4),
            'vm_memory': get_var('vm_memory', spec, '8Gi'),
            'windows_admin_password': get_var('windows_admin_password', spec, 'Secret123%%'),
            'windows_product_key': get_var('windows_product_key', spec, ''),
            'image': get_var('image', spec, 'win2025server.vhdx'),
            'installer_disk_size': get_var('installer_disk_size', spec, '15Gi'),
            'vault_secret': get_var('vault_secret', spec, 'secret/data/windows-server-2025/admin'),
        }
        if action == 'install':
            log_event(f"[OPERATOR] Running Ansible playbook for install on VM {vm_name}")
            result = run_ansible_playbook(playbook_path, playbook_vars)
        elif action == 'uninstall':
            log_event(f"[OPERATOR] Running Ansible playbook for uninstall on VM {vm_name}")
            result = run_ansible_playbook(playbook_path, playbook_vars)
        else:
            log_event(f"[OPERATOR] Unknown action: {action}, skipping.")
            return {'phase': 'Skipped', 'message': f'Unknown action: {action}'}

        # Kopf expects a dict with top-level status keys to patch .status
        if result['success']:
            log_event(f"[OPERATOR] Playbook succeeded for {action} on VM {vm_name}")
            patch.status['phase'] = 'Ready'
            patch.status['message'] = f"VM {vm_name} {action} completed successfully"
            patch.status['reason'] = 'Completed'
            patch.status['observedGeneration'] = meta.get('generation')
            now = datetime.utcnow().isoformat() + 'Z'
            cond = {
                'type': 'Ready',
                'status': 'True',
                'reason': 'Completed',
                'message': f"VM {vm_name} {action} completed successfully",
                'lastTransitionTime': now,
            }
            existing = status.get('conditions', []) if status else []
            patch.status['conditions'] = [c for c in existing if c.get('type') != 'Ready'] + [cond]
            return
        else:
            log_event(f"[OPERATOR] Playbook failed for {action} on VM {vm_name}: {result['error']}")
            patch.status['phase'] = 'Failed'
            patch.status['message'] = f"Failed to {action} VM: {result['error']}"
            patch.status['reason'] = 'Error'
            patch.status['observedGeneration'] = meta.get('generation')
            now = datetime.utcnow().isoformat() + 'Z'
            cond = {
                'type': 'Ready',
                'status': 'False',
                'reason': 'Error',
                'message': f"Failed to {action} VM: {result['error']}",
                'lastTransitionTime': now,
            }
            existing = status.get('conditions', []) if status else []
            patch.status['conditions'] = [c for c in existing if c.get('type') != 'Ready'] + [cond]
            return
    except Exception as e:
        error_msg = f"[OPERATOR] Error processing WindowsVM {name}: {e}"
        log_event(error_msg)
        try:
            kopf.exception(body, reason='Error', message=error_msg)
        except Exception as patch_err:
            log_event(f"[OPERATOR] Failed to patch CR status due to: {patch_err}")
        patch.status['phase'] = 'Failed'
        patch.status['message'] = error_msg
        patch.status['reason'] = 'Exception'
        patch.status['observedGeneration'] = meta.get('generation')
        return


# Resume handler to refresh status after operator restarts
@kopf.on.resume('infra.example.com', 'v1', 'windowsvms')
def resume_windowsvm(body, meta, spec, status, namespace, patch, **kwargs):
    name = meta.get('name')
    vm_name = get_var('vmName', spec, name)
    vm_ns = get_var('kubevirt_namespace', spec, namespace)
    try:
        st = check_target_vm_status(vm_name, vm_ns)
        now = datetime.utcnow().isoformat() + 'Z'
        if st['ready']:
            patch.status['phase'] = 'Ready'
            patch.status['message'] = f"VM {vm_name} is running ({st['message']})"
            patch.status['reason'] = 'Resumed'
            patch.status['observedGeneration'] = meta.get('generation')
            cond = {
                'type': 'Ready', 'status': 'True', 'reason': 'Resumed',
                'message': patch.status['message'], 'lastTransitionTime': now,
            }
        else:
            patch.status['phase'] = 'Pending'
            patch.status['message'] = st['message']
            patch.status['reason'] = 'Resumed'
            patch.status['observedGeneration'] = meta.get('generation')
            cond = {
                'type': 'Ready', 'status': 'False', 'reason': 'Resumed',
                'message': st['message'], 'lastTransitionTime': now,
            }
        existing = status.get('conditions', []) if status else []
        patch.status['conditions'] = [c for c in existing if c.get('type') != 'Ready'] + [cond]
    except Exception as e:
        patch.status['phase'] = 'Unknown'
        patch.status['message'] = f"Error on resume: {e}"
        patch.status['reason'] = 'Exception'
        patch.status['observedGeneration'] = meta.get('generation')


# Delete handler to mark terminating status
@kopf.on.delete('infra.example.com', 'v1', 'windowsvms')
def delete_windowsvm(body, meta, spec, status, namespace, patch, **kwargs):
    name = meta.get('name')
    vm_name = get_var('vmName', spec, name)
    patch.status['phase'] = 'Terminating'
    patch.status['message'] = f"Delete requested for VM {vm_name}"
    patch.status['reason'] = 'DeleteRequested'
    patch.status['observedGeneration'] = meta.get('generation')

    # Run uninstall playbook
    playbook_path = str(REPO_ROOT / 'windows-server-controller.yaml')
    log_event(f"[OPERATOR] Running uninstall playbook for VM {vm_name}")
    result = run_ansible_playbook(playbook_path, {
        'action': 'uninstall',
        'vm_name': vm_name,
        'kubevirt_namespace': namespace
    })
    if result['success']:
        log_event(f"[OPERATOR] Uninstall playbook completed for VM {vm_name}")
    else:
        log_event(f"[OPERATOR] Uninstall playbook failed for VM {vm_name}: {result.get('error')}")

# MSSQLServer Handlers
@kopf.on.create('infra.example.com', 'v1', 'mssqlservers')
@kopf.on.update('infra.example.com', 'v1', 'mssqlservers')
def handle_mssqlserver(body, meta, spec, status, namespace, **kwargs):
    """Handle MSSQLServer resource changes"""
    name = meta.get('name')
    target_vm = get_var('vmName', spec['targetVM'])
    enabled = get_var('enabled', spec, True)
    msg = f"Processing MSSQLServer {name}: target_vm={target_vm}, enabled={enabled}"
    log_event(msg)
    try:
        kopf.info(body, reason='Processing', message=f'Starting MSSQL installation on VM {target_vm}')
        log_event(f"Operator: Starting MSSQL installation on VM {target_vm}")
        if not enabled:
            log_event(f"MSSQLServer {name} is disabled, skipping playbook run.")
            return
        # Use kubevirt_namespace from spec.targetVM or spec, fallback to resource namespace
        vm_ns = spec['targetVM'].get('kubevirt_namespace') or spec.get('kubevirt_namespace') or namespace
        vm_status = check_target_vm_status(target_vm, vm_ns)
        if not vm_status['ready']:
            log_event(f"Target VM {target_vm} is not ready: {vm_status['message']}. Skipping playbook run.")
            return
        # Run the appropriate Ansible playbook (windows-automation-controller.yaml)
        playbook_path = str(REPO_ROOT / 'windows-automation-controller.yaml')
        log_event(f"Operator: Running Ansible playbook for MSSQL install on VM {target_vm}")
        playbook_vars = {
            'vm_name': target_vm,
            'kubevirt_namespace': vm_ns,
            'otel': False,
            'otel_config': '',
            'otel_token': '',
            'otel_endpoint': '',
            'install': 'mssql',  # Main invoking action for MSSQL install
        }
        # Add MSSQL-specific vars from spec if present
        if 'credentials' in spec:
            playbook_vars['adminUser'] = spec['credentials'].get('adminUser', '')
            playbook_vars['adminPasswordVaultPath'] = spec['credentials'].get('adminPasswordVaultPath', '')
            playbook_vars['saPasswordVaultPath'] = spec['credentials'].get('saPasswordVaultPath', '')
        if 'version' in spec:
            playbook_vars['mssql_version'] = spec['version']
        if 'installerPath' in spec:
            playbook_vars['installerPath'] = spec['installerPath']
        if 'installPath' in spec:
            playbook_vars['installPath'] = spec['installPath']
        if 'acceptLicense' in spec:
            playbook_vars['acceptLicense'] = spec['acceptLicense']
        if 'quietInstall' in spec:
            playbook_vars['quietInstall'] = spec['quietInstall']
        #log_event(f"[DEBUG] playbook_vars for MSSQLServer: {playbook_vars}")
        result = run_ansible_playbook(playbook_path, playbook_vars, stream_to_tui=True)
        if result['success']:
            log_event(f"Operator: Successfully installed MSSQL on VM {target_vm}")
            if result.get('output'):
                log_event(f"Playbook output:\n{result['output']}")
            return {'phase': 'Ready', 'message': f'MSSQL install completed successfully on {target_vm}'}
        else:
            log_event(f"Operator: Failed to install MSSQL on VM {target_vm}: {result['error']}")
            if result.get('output'):
                log_event(f"Playbook output:\n{result['output']}")
            return {'phase': 'Failed', 'message': f"Failed to install MSSQL: {result['error']}"}
    except Exception as e:
        error_msg = f"Error processing MSSQLServer {name}: {e}"
        logger.error(error_msg)
        log_event(error_msg)
        kopf.exception(body, reason='Error', message=error_msg)
        return {'phase': 'Failed', 'message': error_msg}


def _build_oteltelemetry_playbook(spec, namespace, action):
    spec = spec or {}

    def resolve_param(name, spec_value, default=None):
        local_spec = {name: spec_value} if spec_value is not None else {}
        return get_var(name, local_spec, default)

    def to_bool(value, default=False):
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        text = str(value).strip().lower()
        if text in ('1', 'true', 'yes', 'on'):
            return True
        if text in ('0', 'false', 'no', 'off'):
            return False
        return default

    def sanitize_placeholder(value, *placeholders):
        if value is None:
            return value
        trimmed = str(value).strip()
        if not trimmed:
            return ''
        normalized = trimmed.upper()
        placeholder_set = {p.upper() for p in placeholders if isinstance(p, str)}
        if normalized in placeholder_set:
            return ''
        return trimmed

    def apply_env_overrides(playbook_vars, component_string):
        """Ensure shell exports take precedence even when spec provided placeholders."""
        override_sources = {
            'component': ['component', 'otel_install_components'],
            'otel_namespace': ['otel_namespace'],
            'redhat_vm_name': ['redhat_vm_name'],
            'redhat_vm_namespace': ['redhat_vm_namespace'],
            'redhat_vm_username': ['redhat_vm_username'],
            'redhat_vm_password': ['redhat_vm_password'],
            'redhat_otel_endpoint': ['redhat_otel_endpoint'],
            'redhat_otel_token': ['redhat_otel_token'],
            'vault_otel_endpoint': ['vault_otel_endpoint'],
            'vault_otel_token': ['vault_otel_token'],
            'vault_metrics_token': ['vault_metrics_token'],
            'vault_token': ['vault_token', 'VAULT_TOKEN'],
            'vault_token_file': ['vault_token_file'],
            'oracle_vm_name': ['oracle_vm_name'],
            'oracle_vm_namespace': ['oracle_vm_namespace'],
            'oracle_listener_port': ['oracle_listener_port'],
            'oracle_pdb_name': ['oracle_pdb_name'],
            'oracle_admin_password': ['oracle_admin_password'],
            'oracle_otel_endpoint': ['oracle_otel_endpoint'],
            'oracle_otel_token': ['oracle_otel_token'],
            'oracle_metrics_username': ['oracle_metrics_username'],
            'oracle_metrics_password': ['oracle_metrics_password'],
            'windows_vm_name': ['windows_vm_name'],
            'windows_vm_namespace': ['windows_vm_namespace'],
            'windows_admin_username': ['windows_admin_username'],
            'windows_admin_password': ['windows_admin_password'],
            'windows_admin_password_vault_path': ['windows_admin_password_vault_path'],
            'windows_admin_password_vault_field': ['windows_admin_password_vault_field'],
            'windows_otel_endpoint': ['windows_otel_endpoint'],
            'windows_otel_token': ['windows_otel_token'],
            'vault_addr': ['vault_addr', 'VAULT_ADDR'],
            'vault_namespace': ['vault_namespace', 'VAULT_NAMESPACE'],
            'vault_validate_certs': ['vault_validate_certs'],
            'otel_windows_debug': ['otel_windows_debug'],
            'mssql_otel_endpoint': ['mssql_otel_endpoint'],
            'mssql_otel_token': ['mssql_otel_token'],
        }
        bool_keys = {'vault_validate_certs', 'otel_windows_debug'}
        applied_keys = []

        def _lookup_env(names):
            for candidate in names:
                value = os.environ.get(candidate)
                if value is None:
                    value = os.environ.get(candidate.upper())
                if value is not None and str(value).strip() != '':
                    return str(value).strip()
            return None

        for key, names in override_sources.items():
            env_val = _lookup_env(names)
            if env_val is None:
                continue
            if key in bool_keys:
                playbook_vars[key] = to_bool(env_val, playbook_vars.get(key))
            else:
                playbook_vars[key] = env_val
            if key not in applied_keys:
                applied_keys.append(key)

        generic_token = _lookup_env(['otel_token'])
        if generic_token:
            token_placeholders = {
                'redhat_otel_token': {'OTELTOKEN', 'REDHAT_PIPELINE_TOKEN'},
                'vault_otel_token': {'OTELTOKEN', 'VAULT_PIPELINE_TOKEN'},
                'oracle_otel_token': {'OTELTOKEN', 'ORACLE_PIPELINE_TOKEN'},
                'windows_otel_token': {'OTELTOKEN', 'WINDOWS_PIPELINE_TOKEN'},
                'mssql_otel_token': {'OTELTOKEN', 'MSSQL_PIPELINE_TOKEN'},
            }
            for token_key, placeholders in token_placeholders.items():
                current = playbook_vars.get(token_key)
                if not isinstance(current, str):
                    continue
                if current.strip().upper() in {p.upper() for p in placeholders} and token_key not in applied_keys:
                    playbook_vars[token_key] = generic_token
                    applied_keys.append(token_key)

        if playbook_vars.get('component') and component_string != playbook_vars['component']:
            component_string = playbook_vars['component']

        return applied_keys, component_string

    telemetry_namespace = resolve_param('otel_namespace', spec.get('namespace', namespace), spec.get('namespace', namespace))

    collector_cfg = spec.get('collector') or {}
    vault_cfg = spec.get('vault') or {}
    redhat_cfg = spec.get('redhat') or {}
    oracle_cfg = spec.get('oracle') or {}
    windows_cfg = spec.get('windows') or {}
    mssql_cfg = spec.get('mssql') or {}

    collector_enabled = collector_cfg.get('enabled', True)
    vault_enabled = vault_cfg.get('enabled', True)
    redhat_enabled = redhat_cfg.get('enabled', True)
    oracle_enabled = oracle_cfg.get('enabled', True)
    windows_enabled = windows_cfg.get('enabled', True)
    mssql_enabled = mssql_cfg.get('enabled', True)

    component_list = []
    if collector_enabled:
        component_list.append('collector')
    if vault_enabled:
        component_list.append('vault')
    if redhat_enabled:
        component_list.append('redhat')
    if oracle_enabled:
        component_list.append('oracle')
    if windows_enabled:
        component_list.append('windows')
    if mssql_enabled:
        component_list.append('mssql')
    if not component_list:
        component_list.append('collector')

    component_string = ','.join(component_list)
    component_string = resolve_param('component', component_string, component_string)

    redhat_vm_name = resolve_param('redhat_vm_name', redhat_cfg.get('vmName'), 'rhel9-vm')
    redhat_vm_namespace = resolve_param('redhat_vm_namespace', redhat_cfg.get('namespace'), 'default')
    redhat_vm_username = resolve_param('redhat_vm_username', redhat_cfg.get('username'), 'redhat')
    redhat_vm_password = resolve_param('redhat_vm_password', redhat_cfg.get('password'), 'redhat')
    redhat_otel_endpoint = resolve_param('redhat_otel_endpoint', redhat_cfg.get('otelEndpoint'), 'OTELENDPOINT')
    redhat_otel_token = resolve_param('redhat_otel_token', redhat_cfg.get('otelToken'), 'OTELTOKEN')

    vault_otel_endpoint = resolve_param('vault_otel_endpoint', vault_cfg.get('otelEndpoint'), 'OTELENDPOINT')
    vault_otel_token = resolve_param('vault_otel_token', vault_cfg.get('otelToken'), 'OTELTOKEN')
    vault_metrics_token = resolve_param('vault_metrics_token', vault_cfg.get('metricsToken'), '')
    vault_token = resolve_param('vault_token', vault_cfg.get('token'), '')
    vault_token = sanitize_placeholder(vault_token, 'VAULT_ACCESS_TOKEN', 'VAULT_TOKEN', 'TOKEN')
    vault_token_file = resolve_param('vault_token_file', vault_cfg.get('tokenFile'), '/root/.vault-token')
    env_vault_token = sanitize_placeholder(os.environ.get('VAULT_TOKEN', ''), 'VAULT_ACCESS_TOKEN', 'VAULT_TOKEN', 'TOKEN')
    if not vault_token and env_vault_token:
        vault_token = env_vault_token

    oracle_vm_name = resolve_param('oracle_vm_name', oracle_cfg.get('vmName'), 'rhel9-vm')
    oracle_vm_namespace = resolve_param('oracle_vm_namespace', oracle_cfg.get('namespace'), 'default')
    oracle_listener_port = resolve_param('oracle_listener_port', oracle_cfg.get('listenerPort'), 1521)
    oracle_pdb_name = resolve_param('oracle_pdb_name', oracle_cfg.get('pdbName'), 'FREEPDB1')
    oracle_admin_password = resolve_param('oracle_admin_password', oracle_cfg.get('adminPassword'), 'Oracle123')
    oracle_otel_endpoint = resolve_param('oracle_otel_endpoint', oracle_cfg.get('otelEndpoint'), 'OTELENDPOINT')
    oracle_otel_token = resolve_param('oracle_otel_token', oracle_cfg.get('otelToken'), 'OTELTOKEN')
    oracle_metrics_username = resolve_param('oracle_metrics_username', oracle_cfg.get('metricsUsername'), 'system')
    oracle_metrics_password = resolve_param('oracle_metrics_password', oracle_cfg.get('metricsPassword'), 'Oracle123')

    windows_vm_name = resolve_param('windows_vm_name', windows_cfg.get('vmName'), 'windows2025')
    windows_vm_namespace = resolve_param('windows_vm_namespace', windows_cfg.get('namespace'), 'default')
    windows_admin_username = resolve_param('windows_admin_username', windows_cfg.get('adminUsername'), 'Administrator')
    windows_admin_password = resolve_param('windows_admin_password', windows_cfg.get('adminPassword'), '')
    windows_admin_password_vault_path = resolve_param('windows_admin_password_vault_path', windows_cfg.get('adminPasswordVaultPath'), 'secret/data/windows-server-2025/admin')
    windows_admin_password_vault_field = resolve_param('windows_admin_password_vault_field', windows_cfg.get('adminPasswordVaultField'), 'password')
    windows_otel_endpoint = resolve_param('windows_otel_endpoint', windows_cfg.get('otelEndpoint'), 'OTELENDPOINT')
    windows_otel_token = resolve_param('windows_otel_token', windows_cfg.get('otelToken'), 'OTELTOKEN')
    env_vault_addr = os.environ.get('VAULT_ADDR', '').strip()
    windows_vault_addr = resolve_param('vault_addr', windows_cfg.get('vaultAddr'), env_vault_addr or 'http://localhost:8200')
    windows_vault_addr = sanitize_placeholder(windows_vault_addr) or 'http://localhost:8200'
    windows_vault_token = resolve_param('vault_token', windows_cfg.get('vaultToken'), '')
    windows_vault_token = sanitize_placeholder(windows_vault_token, 'VAULT_ACCESS_TOKEN', 'VAULT_TOKEN', 'TOKEN')
    if not windows_vault_token and vault_token:
        windows_vault_token = vault_token
    if not windows_vault_token and env_vault_token:
        windows_vault_token = env_vault_token
    windows_vault_namespace = resolve_param('vault_namespace', windows_cfg.get('vaultNamespace'), '')
    env_vault_namespace = sanitize_placeholder(os.environ.get('VAULT_NAMESPACE', ''))
    if not windows_vault_namespace and env_vault_namespace:
        windows_vault_namespace = env_vault_namespace

    mssql_otel_endpoint = resolve_param('mssql_otel_endpoint', mssql_cfg.get('otelEndpoint'), 'OTELENDPOINT')
    mssql_otel_token = resolve_param('mssql_otel_token', mssql_cfg.get('otelToken'), 'OTELTOKEN')

    otel_windows_debug = to_bool(resolve_param('otel_windows_debug', windows_cfg.get('debug'), False))
    vault_validate_certs = to_bool(resolve_param('vault_validate_certs', windows_cfg.get('vaultValidateCerts'), False))

    def bool_flag(val):
        return 'yes' if val else 'no'

    log_event(
        "[OPERATOR] Resolved OTel telemetry inputs: "
        f"components={component_string}; "
        f"vault_addr={windows_vault_addr}; "
        f"vault_token_provided={bool_flag(bool(windows_vault_token))}; "
        f"vault_token_file={vault_token_file}; "
        f"vault_namespace={windows_vault_namespace or '(none)'}; "
        f"windows_admin_password_vault_path={windows_admin_password_vault_path}; "
    f"windows_admin_password_vault_field={windows_admin_password_vault_field}; "
        f"windows_admin_password_supplied={bool_flag(bool(windows_admin_password))}; "
        f"otel_windows_debug={bool_flag(otel_windows_debug)}"
    )

    playbook_vars = {
        'action': action,
        'component': component_string,
        'otel_namespace': telemetry_namespace,
        'redhat_vm_name': redhat_vm_name,
        'redhat_vm_namespace': redhat_vm_namespace,
        'redhat_vm_username': redhat_vm_username,
        'redhat_vm_password': redhat_vm_password,
        'redhat_otel_endpoint': redhat_otel_endpoint,
        'redhat_otel_token': redhat_otel_token,
        'vault_otel_endpoint': vault_otel_endpoint,
        'vault_otel_token': vault_otel_token,
        'vault_metrics_token': vault_metrics_token,
    'vault_token': vault_token,
    'vault_token_file': vault_token_file,
        'oracle_vm_name': oracle_vm_name,
        'oracle_vm_namespace': oracle_vm_namespace,
        'oracle_listener_port': oracle_listener_port,
        'oracle_pdb_name': oracle_pdb_name,
        'oracle_admin_password': oracle_admin_password,
        'oracle_otel_endpoint': oracle_otel_endpoint,
        'oracle_otel_token': oracle_otel_token,
        'oracle_metrics_username': oracle_metrics_username,
        'oracle_metrics_password': oracle_metrics_password,
        'windows_vm_name': windows_vm_name,
        'windows_vm_namespace': windows_vm_namespace,
        'windows_admin_username': windows_admin_username,
        'windows_admin_password': windows_admin_password,
        'windows_admin_password_vault_path': windows_admin_password_vault_path,
        'windows_admin_password_vault_field': windows_admin_password_vault_field,
        'windows_otel_endpoint': windows_otel_endpoint,
        'windows_otel_token': windows_otel_token,
        'vault_addr': windows_vault_addr,
        'vault_token': windows_vault_token,
        'vault_namespace': windows_vault_namespace,
        'vault_validate_certs': vault_validate_certs,
        'otel_windows_debug': otel_windows_debug,
        'mssql_otel_endpoint': mssql_otel_endpoint,
        'mssql_otel_token': mssql_otel_token,
    }

    applied_env_keys, component_string = apply_env_overrides(playbook_vars, component_string)
    if applied_env_keys:
        summary_keys = ', '.join(sorted(applied_env_keys))
        log_event(f"[OPERATOR] Applied environment overrides for OTel keys: {summary_keys}")

    return component_string, playbook_vars


# OTelCollector Handlers
@kopf.on.create('infra.example.com', 'v1', 'windowsotelcollectors')
@kopf.on.update('infra.example.com', 'v1', 'windowsotelcollectors')
def handle_windowsotelcollector(body, meta, spec, status, namespace, **kwargs):
    """Handle OTelCollector resource changes"""
    name = meta.get('name')
    target_vm = get_var('vmName', spec['targetVM'])
    enabled = get_var('enabled', spec, True)
    metrics_type = get_var('metricsType', spec, 'os')
    msg = f"Processing OTelCollector {name}: target_vm={target_vm}, metrics_type={metrics_type}, enabled={enabled}"
    log_event(msg)
    try:
        kopf.info(body, reason='Processing', message=f'Starting OpenTelemetry Collector installation on VM {target_vm}')
        log_event(f"Operator: Starting OpenTelemetry Collector installation on VM {target_vm}")
        if not enabled:
            log_event(f"OTelCollector {name} is disabled, skipping playbook run.")
            return
        # Use the namespace from the CR spec or fallback to the resource namespace
        vm_ns = spec['targetVM'].get('namespace', namespace)
        vm_status = check_target_vm_status(target_vm, vm_ns)
        if not vm_status['ready']:
            log_event(f"Target VM {target_vm} is not ready: {vm_status['message']}. Skipping playbook run.")
            return

        # Check MSSQL prerequisite if collecting MSSQL metrics
        if 'mssql' in metrics_type and spec.get('prerequisites', {}).get('requireMSSQLForMetrics', True):
            mssql_status = check_mssql_availability(target_vm)
            if not mssql_status['available']:
                logger.info(f"MSSQL is required for metrics type '{metrics_type}' but not available on VM {target_vm}. Skipping playbook run.")
                return
        # Run the appropriate Ansible playbook (windows-automation-controller.yaml)
        playbook_path = str(REPO_ROOT / 'windows-automation-controller.yaml')
        log_event(f"Operator: Running Ansible playbook for WindowsOTelCollector install on VM {target_vm}")
        playbook_vars = {
            'vm_name': target_vm,
            'kubevirt_namespace': vm_ns,
            'otel': True,
            'otel_config': spec.get('metricsType', ''),
            'otel_token': spec.get('token', ''),
            'otel_endpoint': spec.get('endpoint', ''),
        }
        # Add additional OTel-specific vars if present
        if 'collectorVersion' in spec:
            playbook_vars['collectorVersion'] = spec['collectorVersion']
        if 'configPath' in spec:
            playbook_vars['configPath'] = spec['configPath']
        if 'installPath' in spec:
            playbook_vars['installPath'] = spec['installPath']
        if 'tempPath' in spec:
            playbook_vars['tempPath'] = spec['tempPath']
        if 'serviceConfig' in spec:
            for k, v in spec['serviceConfig'].items():
                playbook_vars[k] = v
        if 'credentials' in spec:
            playbook_vars['adminUser'] = spec['credentials'].get('adminUser', '')
            playbook_vars['adminPasswordVaultPath'] = spec['credentials'].get('adminPasswordVaultPath', '')
        result = run_ansible_playbook(playbook_path, playbook_vars, stream_to_tui=True)
        if result['success']:
            log_event(f"Operator: Successfully installed OTelCollector on VM {target_vm}")
            if result.get('output'):
                log_event(f"Playbook output:\n{result['output']}")
            return {'phase': 'Ready', 'message': f'OTelCollector install completed successfully on {target_vm}'}
        else:
            log_event(f"Operator: Failed to install OTelCollector on VM {target_vm}: {result['error']}")
            if result.get('output'):
                log_event(f"Playbook output:\n{result['output']}")
            return {'phase': 'Failed', 'message': f"Failed to install OTelCollector: {result['error']}"}
    except Exception as e:
        error_msg = f"Error processing OTelCollector {name}: {e}"
        logger.error(error_msg)
        log_event(error_msg)
        kopf.exception(body, reason='Error', message=error_msg)
        return {'phase': 'Failed', 'message': error_msg}


# OTelTelemetry Handlers (Combined telemetry stack)
@kopf.on.create('infra.example.com', 'v1', 'oteltelemetries')
@kopf.on.update('infra.example.com', 'v1', 'oteltelemetries')
def handle_oteltelemetry(body, meta, spec, status, namespace, diff, old, new, patch, **kwargs):
    """Handle combined OTel telemetry deployments via otel-controller playbook"""

    terminal_phases = ['Ready', 'Failed', 'Skipped']
    if status and status.get('phase') in terminal_phases and status.get('observedGeneration') == meta.get('generation'):
        msg = f"[OPERATOR] Skipping execution for {meta.get('name')} (phase={status.get('phase')})"
        log_event(msg)
        return

    name = meta.get('name')
    action = get_var('action', spec, 'install')
    component_string, playbook_vars = _build_oteltelemetry_playbook(spec, namespace, action)

    patch.status['phase'] = 'InProgress'
    patch.status['componentsSummary'] = component_string
    patch.status['message'] = f"{action.title()} requested for OTelTelemetry {name}"
    patch.status['reason'] = 'Processing'
    observed_generation = meta.get('generation')
    if observed_generation is None and status:
        observed_generation = status.get('observedGeneration')
    if observed_generation is not None:
        patch.status['observedGeneration'] = observed_generation

    try:
        kopf.info(body, reason='Processing', message=f"Starting {action} for OTel telemetry stack {name}")
        log_event(f"[OPERATOR] Running otel-controller playbook for {name} with action={action} components={component_string}")
        playbook_path = str(REPO_ROOT / 'otel-controller.yaml')
        result = run_ansible_playbook(playbook_path, playbook_vars, stream_to_tui=True)
        if result['success']:
            log_event(f"[OPERATOR] OTel telemetry stack {name} {action} completed successfully")
            patch.status['phase'] = 'Ready'
            patch.status['message'] = f"OTel telemetry {action} completed successfully"
            patch.status['reason'] = 'Completed'
            patch.status['componentsSummary'] = component_string
            observed_generation = meta.get('generation')
            if observed_generation is None and status:
                observed_generation = status.get('observedGeneration')
            if observed_generation is not None:
                patch.status['observedGeneration'] = observed_generation
            now = datetime.utcnow().isoformat() + 'Z'
            cond = {
                'type': 'Ready',
                'status': 'True',
                'reason': 'Completed',
                'message': patch.status['message'],
                'lastTransitionTime': now,
            }
            existing = status.get('conditions', []) if status else []
            patch.status['conditions'] = [c for c in existing if c.get('type') != 'Ready'] + [cond]
            return
        else:
            error_message = result.get('error', 'unknown failure')
            log_event(f"[OPERATOR] OTel telemetry stack {name} {action} failed: {error_message}")
            patch.status['phase'] = 'Failed'
            patch.status['message'] = f"OTel telemetry {action} failed: {error_message}"
            patch.status['reason'] = 'Error'
            patch.status['componentsSummary'] = component_string
            observed_generation = meta.get('generation')
            if observed_generation is None and status:
                observed_generation = status.get('observedGeneration')
            if observed_generation is not None:
                patch.status['observedGeneration'] = observed_generation
            now = datetime.utcnow().isoformat() + 'Z'
            cond = {
                'type': 'Ready',
                'status': 'False',
                'reason': 'Error',
                'message': patch.status['message'],
                'lastTransitionTime': now,
            }
            existing = status.get('conditions', []) if status else []
            patch.status['conditions'] = [c for c in existing if c.get('type') != 'Ready'] + [cond]
            return
    except Exception as e:
        error_msg = f"[OPERATOR] Error processing OTel telemetry {name}: {e}"
        log_event(error_msg)
        try:
            kopf.exception(body, reason='Error', message=error_msg)
        except Exception as patch_err:
            log_event(f"[OPERATOR] Failed to patch CR status due to: {patch_err}")
        patch.status['phase'] = 'Failed'
        patch.status['message'] = error_msg
        patch.status['reason'] = 'Exception'
        patch.status['componentsSummary'] = component_string
        observed_generation = meta.get('generation')
        if observed_generation is None and status:
            observed_generation = status.get('observedGeneration')
        if observed_generation is not None:
            patch.status['observedGeneration'] = observed_generation
        return


@kopf.on.delete('infra.example.com', 'v1', 'oteltelemetries')
def delete_oteltelemetry(body, meta, spec, status, namespace, patch, **kwargs):
    name = meta.get('name')
    action = 'uninstall'

    try:
        component_string, playbook_vars = _build_oteltelemetry_playbook(spec, namespace, action)
        patch.status['phase'] = 'Terminating'
        patch.status['message'] = f"Delete requested for OTelTelemetry {name}"
        patch.status['reason'] = 'DeleteRequested'
        if component_string:
            patch.status['componentsSummary'] = component_string
        elif status and status.get('componentsSummary'):
            patch.status['componentsSummary'] = status.get('componentsSummary')
        generation = meta.get('generation')
        if generation is not None:
            patch.status['observedGeneration'] = generation
        kopf.info(body, reason='DeleteRequested', message=f'Starting uninstall for OTel telemetry stack {name}')
        log_event(f"[OPERATOR] Running otel-controller playbook for uninstall of {name} with components={component_string}")
        playbook_path = str(REPO_ROOT / 'otel-controller.yaml')
        result = run_ansible_playbook(playbook_path, playbook_vars, stream_to_tui=True)
        if result['success']:
            log_event(f"[OPERATOR] OTel telemetry stack {name} uninstall completed successfully")
        else:
            error_message = result.get('error', 'unknown failure')
            log_event(f"[OPERATOR] OTel telemetry stack {name} uninstall failed: {error_message}")
    except Exception as e:
        error_msg = f"[OPERATOR] Error processing OTel telemetry delete {name}: {e}"
        log_event(error_msg)
        try:
            kopf.exception(body, reason='Error', message=error_msg)
        except Exception as patch_err:
            log_event(f"[OPERATOR] Failed to patch CR status during delete due to: {patch_err}")


def run_ansible_playbook(playbook_path, variables, stream_to_tui=False):
    """Run Ansible playbook with given variables and stream output line by line"""
    import shlex
    try:
        # Use log_queue for streaming output if available
        # Create temporary inventory
        inventory_content = "localhost ansible_connection=local\n"
        with open('/tmp/ansible_inventory', 'w') as f:
            f.write(inventory_content)
        # Build ansible-playbook command
        cmd = ['ansible-playbook', '-i', '/tmp/ansible_inventory', playbook_path]
        extra_vars_payload = {}
        for key, value in variables.items():
            if value is None:
                continue
            if isinstance(value, bool):
                extra_vars_payload[key] = value
            elif isinstance(value, (dict, list)):
                extra_vars_payload[key] = value
            else:
                string_value = str(value)
                if string_value.strip() == '':
                    continue
                extra_vars_payload[key] = string_value

        if extra_vars_payload:
            logger.debug(f"[OPERATOR] Prepared Ansible extra-vars: {extra_vars_payload}")
            if log_queue:
                log_queue.put(f"[OPERATOR] Prepared Ansible extra-vars: {extra_vars_payload}")
            cmd.extend(['--extra-vars', json.dumps(extra_vars_payload)])
        logger.info(f"[OPERATOR] Running command: {' '.join(shlex.quote(str(c)) for c in cmd)}")
        if log_queue:
            log_queue.put(f"[OPERATOR] Running command: {' '.join(shlex.quote(str(c)) for c in cmd)}")
        output_lines = []
        playbook_completed = False
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        for line in process.stdout:
            line = line.rstrip()
            logger.info(f"[PLAYBOOK] {line}")
            output_lines.append(line)
            # Detect playbook completion by looking for the final task and PLAY RECAP
            if 'TASK [Display completion message]' in line or 'PLAY RECAP' in line:
                playbook_completed = True
                if 'PLAY RECAP' in line:
                    logger.info("[PLAYBOOK] --- End of playbook execution detected ---")
        # No direct log_queue.put for playbook lines; logger handles all log routing
        if playbook_completed:
            logger.info("[PLAYBOOK] Playbook execution has completed. Check above for summary.")
        process.wait()
        if process.returncode == 0:
            logger.info("[OPERATOR] Ansible playbook completed successfully")
            return {'success': True, 'output': '\n'.join(output_lines)}
        else:
            logger.error(f"[OPERATOR] Ansible playbook failed with code {process.returncode}")
            return {'success': False, 'error': f'Playbook failed with code {process.returncode}', 'output': '\n'.join(output_lines)}
    except subprocess.TimeoutExpired:
        error_msg = "[OPERATOR] Ansible playbook timed out after 30 minutes"
        logger.error(error_msg)
        return {'success': False, 'error': error_msg}
    except Exception as e:
        error_msg = f"[OPERATOR] Error running Ansible playbook: {e}"
        logger.error(error_msg)
        return {'success': False, 'error': error_msg}

def check_target_vm_status(vm_name, kubevirt_namespace):
    """Check if target VM is ready for service installation"""
    try:
        from utils.k8s_client import get_vm_status
        vm_status = get_vm_status(vm_name, kubevirt_namespace)
        
        if not vm_status['exists']:
            return {'ready': False, 'message': f'VM {vm_name} does not exist in namespace {kubevirt_namespace}'}
        
        if not vm_status['is_running']:
            return {'ready': False, 'message': f'VM {vm_name} is not running (phase: {vm_status["vmi_phase"]})'}
        
        return {'ready': True, 'message': f'VM {vm_name} is ready (phase: {vm_status["vmi_phase"]})'}
        
    except Exception as e:
        return {'ready': False, 'message': f'Error checking VM status: {e}'}

def check_mssql_availability(vm_name):
    """Check if MSSQL is available on the target VM"""
    try:
        # This is a placeholder - in reality, you would check if MSSQL service is running
        # For now, we'll assume it's available if we can't determine otherwise
        return {'available': True, 'message': 'MSSQL availability check not implemented'}
    except Exception as e:
        return {'available': False, 'message': f'Error checking MSSQL availability: {e}'}


# RedHatVM Handlers (KubeVirt)
@kopf.on.create('infra.example.com', 'v1', 'redhatvms')
@kopf.on.update('infra.example.com', 'v1', 'redhatvms')
def handle_redhatvm(body, meta, spec, status, namespace, diff, old, new, patch, **kwargs):
    """Handle Red Hat VM resource changes via unified controller playbook"""
    terminal_phases = ['Ready', 'Failed', 'Skipped']
    if status and status.get('phase') in terminal_phases and status.get('observedGeneration') == meta.get('generation'):
        msg = f"[OPERATOR] Skipping execution for {meta.get('name')} (phase={status.get('phase')})"
        log_event(msg)
        patch.status['phase'] = status.get('phase')
        patch.status['message'] = status.get('message', '')
        patch.status['observedGeneration'] = status.get('observedGeneration')
        return
    log_event("[OPERATOR] handle_redhatvm triggered!")
    name = meta.get('name')
    action = get_var('action', spec, 'install')
    vm_name = get_var('vm_name', spec, name)
    kind = get_var('kind', spec, 'VirtualMachine')
    manifest_path = get_var('manifest_path', spec, str(REPO_ROOT / 'manifest-controller' / 'rhel9-vm-cr.yaml'))
    kubevirt_namespace = get_var('kubevirt_namespace', spec, namespace)
    vm_image = get_var('vm_image', spec, 'registry.redhat.io/rhel9/rhel-guest-image:9.6')
    vm_cpu_cores = get_var('vm_cpu_cores', spec, 2)
    vm_memory = get_var('vm_memory', spec, '4Gi')
    root_password = get_var('root_password', spec, 'redhat')
    user_password = get_var('user_password', spec, 'redhat')
    subscription_username = get_var('subscription_username', spec, 'XXXXX')
    subscription_password = get_var('subscription_password', spec, 'XXXX')
    syspurpose_usage = get_var('syspurpose_usage', spec, 'Development/Test')
    disk_bus = get_var('disk_bus', spec, 'virtio')
    log_event(f"[OPERATOR] CR received: name={name}, action={action}, vm_name={vm_name}, kind={kind}")
    try:
        patch.status['phase'] = 'InProgress'
        patch.status['message'] = f"{action.title()} in progress for Red Hat VM {vm_name}"
        patch.status['reason'] = 'Processing'
        patch.status['observedGeneration'] = meta.get('generation')
        now = datetime.utcnow().isoformat() + 'Z'
        cond = {
            'type': 'Ready',
            'status': 'False',
            'reason': 'Processing',
            'message': f"{action.title()} in progress for Red Hat VM {vm_name}",
            'lastTransitionTime': now,
        }
        existing = status.get('conditions', []) if status else []
        patch.status['conditions'] = [c for c in existing if c.get('type') != 'Ready'] + [cond]
    except Exception:
        pass
    try:
        kopf.info(body, reason='Processing', message=f'Starting {action} for Red Hat VM {vm_name}')
        playbook_path = str(REPO_ROOT / 'redhat-server-controller.yaml')
        playbook_vars = {
            'action': action,
            'kind': kind,
            'manifest_path': manifest_path,
            'kubevirt_namespace': kubevirt_namespace,
            'vm_name': vm_name,
            'vm_image': vm_image,
            'vm_cpu_cores': vm_cpu_cores,
            'vm_memory': vm_memory,
            'system_disk_size': get_var('system_disk_size', spec, '20Gi'),
            'storage_dir': get_var('storage_dir', spec, '/data/vms'),
            'qcow2_image_path': get_var('qcow2_image_path', spec, './rhel-9.6-x86_64-kvm.qcow2'),
            'root_password': root_password,
            'user_password': user_password,
            'subscription_username': subscription_username,
            'subscription_password': subscription_password,
            'syspurpose_usage': syspurpose_usage,
            'disk_bus': disk_bus,
            'redhat_vault_secret': get_var('redhat_vault_secret', spec, 'secret/redhat-vm-admin'),
            'redhat_user': get_var('redhat_user', spec, 'redhat'),
        }
        log_event(f"[OPERATOR] Running controller playbook for {action} on Red Hat VM {vm_name}")
        result = run_ansible_playbook(playbook_path, playbook_vars)
        if result['success']:
            log_event(f"[OPERATOR] Playbook succeeded for {action} on Red Hat VM {vm_name}")
            patch.status['phase'] = 'Ready'
            patch.status['message'] = f"Red Hat VM {vm_name} {action} completed successfully"
            patch.status['reason'] = 'Completed'
            patch.status['observedGeneration'] = meta.get('generation')
            now = datetime.utcnow().isoformat() + 'Z'
            cond = {
                'type': 'Ready',
                'status': 'True',
                'reason': 'Completed',
                'message': f"Red Hat VM {vm_name} {action} completed successfully",
                'lastTransitionTime': now,
            }
            existing = status.get('conditions', []) if status else []
            patch.status['conditions'] = [c for c in existing if c.get('type') != 'Ready'] + [cond]
            return
        else:
            log_event(f"[OPERATOR] Playbook failed for {action} on Red Hat VM {vm_name}: {result['error']}")
            patch.status['phase'] = 'Failed'
            patch.status['message'] = f"Failed to {action} Red Hat VM: {result['error']}"
            patch.status['reason'] = 'Error'
            patch.status['observedGeneration'] = meta.get('generation')
            now = datetime.utcnow().isoformat() + 'Z'
            cond = {
                'type': 'Ready',
                'status': 'False',
                'reason': 'Error',
                'message': f"Failed to {action} Red Hat VM: {result['error']}",
                'lastTransitionTime': now,
            }
            existing = status.get('conditions', []) if status else []
            patch.status['conditions'] = [c for c in existing if c.get('type') != 'Ready'] + [cond]
            return
    except Exception as e:
        error_msg = f"[OPERATOR] Error processing Red Hat VM {name}: {e}"
        log_event(error_msg)
        try:
            kopf.exception(body, reason='Error', message=error_msg)
        except Exception as patch_err:
            log_event(f"[OPERATOR] Failed to patch CR status due to: {patch_err}")
        patch.status['phase'] = 'Failed'
        patch.status['message'] = error_msg
        patch.status['reason'] = 'Exception'
        patch.status['observedGeneration'] = meta.get('generation')
        return
    

@kopf.on.delete('infra.example.com', 'v1', 'redhatvms')
def delete_redhatvm(body, meta, spec, status, namespace, patch, **kwargs):
    """Handle Red Hat VM resource deletion via unified controller playbook"""
    name = meta.get('name')
    vm_name = get_var('vmName', spec, name)
    kind = get_var('kind', spec, 'VirtualMachine')
    manifest_path = get_var('manifest_path', spec, str(REPO_ROOT / 'manifest-controller' / 'rhel9-vm-cr.yaml'))
    kubevirt_namespace = get_var('kubevirt_namespace', spec, namespace)
    patch.status['phase'] = 'Terminating'
    patch.status['message'] = f"Delete requested for Red Hat VM {vm_name}"
    patch.status['reason'] = 'DeleteRequested'
    patch.status['observedGeneration'] = meta.get('generation')
    playbook_path = str(REPO_ROOT / 'redhat-server-controller.yaml')
    log_event(f"[OPERATOR] Running uninstall playbook for Red Hat VM {vm_name}")
    result = run_ansible_playbook(playbook_path, {
        'action': 'uninstall',
        'kind': kind,
        'manifest_path': manifest_path,
        'kubevirt_namespace': kubevirt_namespace,
        'vm_name': vm_name,
    })
    if result['success']:
        log_event(f"[OPERATOR] Uninstall playbook completed for Red Hat VM {vm_name}")
    else:
        log_event(f"[OPERATOR] Uninstall playbook failed for Red Hat VM {vm_name}: {result.get('error')}")


# OracleDB Handlers (Oracle Database Service on existing VMs)
@kopf.on.create('infra.example.com', 'v1', 'oracledbs')
@kopf.on.update('infra.example.com', 'v1', 'oracledbs')
def handle_oracledb(body, meta, spec, status, namespace, diff, old, new, patch, **kwargs):
    """Handle Oracle DB service installation on existing VMs"""
    terminal_phases = ['Ready', 'Failed', 'Skipped']
    if status and status.get('phase') in terminal_phases and status.get('observedGeneration') == meta.get('generation'):
        msg = f"[OPERATOR] Skipping execution for {meta.get('name')} (phase={status.get('phase')})"
        log_event(msg)
        patch.status['phase'] = status.get('phase')
        patch.status['message'] = status.get('message', '')
        patch.status['observedGeneration'] = status.get('observedGeneration')
        return
    
    log_event("[OPERATOR] handle_oracledb triggered!")
    name = meta.get('name')
    action = get_var('action', spec, 'install')
    vm_name = get_var('vm_name', spec, name)
    kind = get_var('kind', spec, 'VirtualMachine')
    kubevirt_namespace = get_var('kubevirt_namespace', spec, namespace)
    oracle_vault_secret = get_var('oracle_vault_secret', spec, 'secret/data/oracle-vm/admin')
    oracle_user = get_var('oracle_user', spec, 'oracle')
    oracle_password = get_var('oracle_password', spec, 'Oracle123')
    oracle_admin_password = get_var('oracle_admin_password', spec, 'Oracle123')
    oracle_sid = get_var('oracle_sid', spec, 'FREE')
    oracle_home = get_var('oracle_home', spec, '/opt/oracle/product/23ai/dbhomeFree')
    oracle_listener_port = get_var('oracle_listener_port', spec, 1521)
    oracle_app_username = get_var('oracle_app_username', spec, 'appuser')
    oracle_app_grants = get_var('oracle_app_grants', spec, 'CREATE SESSION, CREATE TABLE, CREATE VIEW, CREATE SEQUENCE, CREATE SYNONYM, UNLIMITED TABLESPACE')
    oracle_pdb_name = get_var('oracle_pdb_name', spec, 'FREEPDB1')
    oracle_dbca_template = get_var('oracle_dbca_template', spec, 'FREE_Database.dbc')
    oracle_dbca_memory_mb = get_var('oracle_dbca_memory_mb', spec, 0)
    skip_system_update = get_var('skip_system_update', spec, True)
    oracle_fast_install = get_var('oracle_fast_install', spec, True)

    oracle_env_spec = get_var('oracle_env', spec, {}) or {}
    if isinstance(oracle_env_spec, str):
        try:
            parsed_env = yaml.safe_load(oracle_env_spec)
            if isinstance(parsed_env, dict):
                oracle_env_spec = parsed_env
            else:
                oracle_env_spec = {}
        except Exception:
            oracle_env_spec = {}
    elif not isinstance(oracle_env_spec, dict):
        oracle_env_spec = {}

    default_oracle_env = {
        'ORACLE_HOME': oracle_home,
        'ORACLE_SID': oracle_sid,
        'ORACLE_BASE': '/opt/oracle',
        'TNS_ADMIN': f"{oracle_home}/network/admin",
        'PATH': f"{oracle_home}/bin:/usr/local/bin:/usr/bin:/bin:/sbin",
    }

    oracle_env = {**default_oracle_env, **oracle_env_spec}
    
    log_event(f"[OPERATOR] Oracle DB CR received: name={name}, action={action}, vm_name={vm_name}")
    
    try:
        patch.status['phase'] = 'InProgress'
        patch.status['message'] = f"Oracle DB {action} in progress on VM {vm_name}"
        patch.status['reason'] = 'Processing'
        patch.status['observedGeneration'] = meta.get('generation')
        now = datetime.utcnow().isoformat() + 'Z'
        cond = {
            'type': 'Ready',
            'status': 'False',
            'reason': 'Processing',
            'message': f"Oracle DB {action} in progress on VM {vm_name}",
            'lastTransitionTime': now,
        }
        existing = status.get('conditions', []) if status else []
        patch.status['conditions'] = [c for c in existing if c.get('type') != 'Ready'] + [cond]
    except Exception:
        pass

    try:
        kopf.info(body, reason='Processing', message=f'Starting Oracle DB {action} on VM {vm_name}')
        playbook_path = str(REPO_ROOT / 'oracle-controller.yaml')
        playbook_vars = {
            'action': action,
            'kind': kind,
            'vm_name': vm_name,
            'kubevirt_namespace': kubevirt_namespace,
            'oracle_vault_secret': oracle_vault_secret,
            'oracle_user': oracle_user,
            'oracle_password': oracle_password,
            'oracle_admin_password': oracle_admin_password,
            'oracle_sid': oracle_sid,
            'oracle_home': oracle_home,
            'oracle_listener_port': oracle_listener_port,
            'oracle_app_username': oracle_app_username,
            'oracle_app_grants': oracle_app_grants,
            'oracle_pdb_name': oracle_pdb_name,
            'oracle_dbca_template': oracle_dbca_template,
            'oracle_dbca_memory_mb': oracle_dbca_memory_mb,
            'skip_system_update': skip_system_update,
            'oracle_fast_install': oracle_fast_install,
            'oracle_env': oracle_env,
        }
        
        log_event(f"[OPERATOR] Running Oracle DB playbook for {action} on VM {vm_name}")
        result = run_ansible_playbook(playbook_path, playbook_vars)
        
        if result['success']:
            log_event(f"[OPERATOR] Playbook succeeded for Oracle DB {action} on VM {vm_name}")
            patch.status['phase'] = 'Ready'
            patch.status['message'] = f"Oracle DB {action} completed successfully on VM {vm_name}"
            patch.status['reason'] = 'Completed'
            patch.status['observedGeneration'] = meta.get('generation')
            now = datetime.utcnow().isoformat() + 'Z'
            cond = {
                'type': 'Ready',
                'status': 'True',
                'reason': 'Completed',
                'message': f"Oracle DB {action} completed successfully on VM {vm_name}",
                'lastTransitionTime': now,
            }
            existing = status.get('conditions', []) if status else []
            patch.status['conditions'] = [c for c in existing if c.get('type') != 'Ready'] + [cond]
            return
        else:
            log_event(f"[OPERATOR] Playbook failed for Oracle DB {action} on VM {vm_name}: {result['error']}")
            patch.status['phase'] = 'Failed'
            patch.status['message'] = f"Oracle DB {action} failed on VM {vm_name}: {result['error']}"
            patch.status['reason'] = 'Failed'
            patch.status['observedGeneration'] = meta.get('generation')
            now = datetime.utcnow().isoformat() + 'Z'
            cond = {
                'type': 'Ready',
                'status': 'False',
                'reason': 'Failed',
                'message': f"Oracle DB {action} failed on VM {vm_name}",
                'lastTransitionTime': now,
            }
            existing = status.get('conditions', []) if status else []
            patch.status['conditions'] = [c for c in existing if c.get('type') != 'Ready'] + [cond]
            return
    
    except Exception as e:
        error_message = str(e)
        log_event(f"[OPERATOR] Error processing Oracle DB CR: {error_message}")
        try:
            kopf.exception(body, reason='Error', message=error_message)
        except Exception as patch_err:
            log_event(f"[OPERATOR] Failed to patch CR status due to: {patch_err}")
        patch.status['phase'] = 'Failed'
        patch.status['message'] = f"Oracle DB operation failed: {error_message}"
        patch.status['reason'] = 'Error'
        patch.status['observedGeneration'] = meta.get('generation')
        return


@kopf.on.delete('infra.example.com', 'v1', 'oracledbs')
def delete_oracledb(body, meta, spec, status, namespace, patch, **kwargs):
    """Handle Oracle DB service deletion"""
    name = meta.get('name')
    vm_name = get_var('vm_name', spec, name)
    kubevirt_namespace = get_var('kubevirt_namespace', spec, namespace)
    oracle_vault_secret = get_var('oracle_vault_secret', spec, 'secret/data/oracle-vm/admin')
    oracle_user = get_var('oracle_user', spec, 'oracle')
    oracle_password = get_var('oracle_password', spec, 'Oracle123')
    oracle_admin_password = get_var('oracle_admin_password', spec, 'Oracle123')
    
    log_event(f"[OPERATOR] Oracle DB CR deletion triggered: {name}")
    patch.status['phase'] = 'Terminating'
    patch.status['message'] = f"Delete requested for Oracle DB on VM {vm_name}"
    patch.status['reason'] = 'DeleteRequested'
    patch.status['observedGeneration'] = meta.get('generation')

    try:
        kopf.info(body, reason='Cleanup', message=f'Starting Oracle DB cleanup on VM {vm_name}')
        playbook_path = str(REPO_ROOT / 'oracle-controller.yaml')
        playbook_vars = {
            'action': 'uninstall',
            'vm_name': vm_name,
            'kubevirt_namespace': kubevirt_namespace,
            'oracle_vault_secret': oracle_vault_secret,
            'oracle_user': oracle_user,
            'oracle_password': oracle_password,
            'oracle_admin_password': oracle_admin_password,
        }
        
        log_event(f"[OPERATOR] Running Oracle DB cleanup for VM {vm_name}")
        result = run_ansible_playbook(playbook_path, playbook_vars)
        
        if result['success']:
            log_event(f"[OPERATOR] Oracle DB cleanup succeeded for VM {vm_name}")
        else:
            log_event(f"[OPERATOR] Oracle DB cleanup failed for VM {vm_name}: {result.get('error')}")
    
    except Exception as e:
        error_message = str(e)
        log_event(f"[OPERATOR] Error during Oracle DB cleanup: {error_message}")


# NVIDIA GPU LLM Handlers
@kopf.on.create('infra.example.com', 'v1', 'nvidiagpullms')
@kopf.on.update('infra.example.com', 'v1', 'nvidiagpullms')
def handle_nvidiagpullm(body, meta, spec, status, namespace, diff, old, new, patch, **kwargs):
    """Handle NVIDIA GPU LLM deployment"""
    terminal_phases = ['Ready', 'Failed', 'Skipped']
    if status and status.get('phase') in terminal_phases and status.get('observedGeneration') == meta.get('generation'):
        msg = f"[OPERATOR] Skipping execution for {meta.get('name')} (phase={status.get('phase')})"
        log_event(msg)
        patch.status['phase'] = status.get('phase')
        patch.status['message'] = status.get('message', '')
        patch.status['observedGeneration'] = status.get('observedGeneration')
        return
    
    log_event("[OPERATOR] handle_nvidiagpullm triggered!")
    name = meta.get('name')
    action = get_var('action', spec, 'install')
    llm_name = get_var('llmName', spec, name)
    llm_namespace = get_var('namespace', spec, namespace)
    model = get_var('model', spec, 'tinyllama')
    gpu_count = get_var('gpuCount', spec, 1)
    
    log_event(f"[OPERATOR] NVIDIA GPU LLM CR received: name={name}, action={action}, llm_name={llm_name}, model={model}")
    
    try:
        patch.status['phase'] = 'InProgress'
        patch.status['message'] = f"NVIDIA GPU LLM {action} in progress for {llm_name}"
        patch.status['reason'] = 'Processing'
        patch.status['observedGeneration'] = meta.get('generation')
        patch.status['podName'] = llm_name
        patch.status['modelLoaded'] = model
        now = datetime.utcnow().isoformat() + 'Z'
        cond = {
            'type': 'Ready',
            'status': 'False',
            'reason': 'Processing',
            'message': f"NVIDIA GPU LLM {action} in progress for {llm_name}",
            'lastTransitionTime': now,
        }
        existing = status.get('conditions', []) if status else []
        patch.status['conditions'] = [c for c in existing if c.get('type') != 'Ready'] + [cond]
    except Exception:
        pass

    try:
        kopf.info(body, reason='Processing', message=f'Starting NVIDIA GPU LLM {action} for {llm_name}')
        playbook_path = str(REPO_ROOT / 'nvidia-gpu-llm-controller.yaml')
        playbook_vars = {
            'action': action,
            'llmName': llm_name,
            'namespace': llm_namespace,
            'model': model,
            'gpuCount': gpu_count,
            'memory': get_var('memory', spec, '4Gi'),
            'cpuCores': get_var('cpuCores', spec, 2),
            'serviceEnabled': get_var('serviceEnabled', spec, False),
            'servicePort': get_var('servicePort', spec, 11434),
            'prompts': get_var('prompts', spec, ['Explain what is Kubernetes in one sentence.']),
            'persistentStorage': get_var('persistentStorage', spec, False),
            'storageSize': get_var('storageSize', spec, '10Gi'),
            'imagePullPolicy': get_var('imagePullPolicy', spec, 'IfNotPresent'),
            'keepAlive': get_var('keepAlive', spec, True),
        }
        
        log_event(f"[OPERATOR] Running NVIDIA GPU LLM playbook for {action} on {llm_name}")
        result = run_ansible_playbook(playbook_path, playbook_vars)
        
        if result['success']:
            log_event(f"[OPERATOR] Playbook succeeded for NVIDIA GPU LLM {action} on {llm_name}")
            patch.status['phase'] = 'Ready'
            patch.status['message'] = f"NVIDIA GPU LLM {action} completed successfully for {llm_name}"
            patch.status['reason'] = 'Completed'
            patch.status['observedGeneration'] = meta.get('generation')
            patch.status['gpuAssigned'] = True
            now = datetime.utcnow().isoformat() + 'Z'
            cond = {
                'type': 'Ready',
                'status': 'True',
                'reason': 'Completed',
                'message': f"NVIDIA GPU LLM {action} completed successfully for {llm_name}",
                'lastTransitionTime': now,
            }
            existing = status.get('conditions', []) if status else []
            patch.status['conditions'] = [c for c in existing if c.get('type') != 'Ready'] + [cond]
            return
        else:
            log_event(f"[OPERATOR] Playbook failed for NVIDIA GPU LLM {action} on {llm_name}: {result['error']}")
            patch.status['phase'] = 'Failed'
            patch.status['message'] = f"NVIDIA GPU LLM {action} failed for {llm_name}: {result['error']}"
            patch.status['reason'] = 'Failed'
            patch.status['observedGeneration'] = meta.get('generation')
            patch.status['gpuAssigned'] = False
            now = datetime.utcnow().isoformat() + 'Z'
            cond = {
                'type': 'Ready',
                'status': 'False',
                'reason': 'Failed',
                'message': f"NVIDIA GPU LLM {action} failed for {llm_name}",
                'lastTransitionTime': now,
            }
            existing = status.get('conditions', []) if status else []
            patch.status['conditions'] = [c for c in existing if c.get('type') != 'Ready'] + [cond]
            return
    
    except Exception as e:
        error_message = str(e)
        log_event(f"[OPERATOR] Error processing NVIDIA GPU LLM CR: {error_message}")
        try:
            kopf.exception(body, reason='Error', message=error_message)
        except Exception as patch_err:
            log_event(f"[OPERATOR] Failed to patch CR status due to: {patch_err}")
        patch.status['phase'] = 'Failed'
        patch.status['message'] = f"NVIDIA GPU LLM operation failed: {error_message}"
        patch.status['reason'] = 'Error'
        patch.status['observedGeneration'] = meta.get('generation')
        return


@kopf.on.delete('infra.example.com', 'v1', 'nvidiagpullms')
def delete_nvidiagpullm(body, meta, spec, status, namespace, patch, **kwargs):
    """Handle NVIDIA GPU LLM deletion"""
    name = meta.get('name')
    llm_name = get_var('llmName', spec, name)
    llm_namespace = get_var('namespace', spec, namespace)
    
    log_event(f"[OPERATOR] NVIDIA GPU LLM CR deletion triggered: {name}")
    patch.status['phase'] = 'Terminating'
    patch.status['message'] = f"Delete requested for NVIDIA GPU LLM {llm_name}"
    patch.status['reason'] = 'DeleteRequested'
    patch.status['observedGeneration'] = meta.get('generation')

    try:
        kopf.info(body, reason='Cleanup', message=f'Starting NVIDIA GPU LLM cleanup for {llm_name}')
        playbook_path = str(REPO_ROOT / 'nvidia-gpu-llm-controller.yaml')
        playbook_vars = {
            'action': 'uninstall',
            'llmName': llm_name,
            'namespace': llm_namespace,
        }
        
        log_event(f"[OPERATOR] Running NVIDIA GPU LLM cleanup for {llm_name}")
        result = run_ansible_playbook(playbook_path, playbook_vars)
        
        if result['success']:
            log_event(f"[OPERATOR] NVIDIA GPU LLM cleanup succeeded for {llm_name}")
        else:
            log_event(f"[OPERATOR] NVIDIA GPU LLM cleanup failed for {llm_name}: {result.get('error')}")
    
    except Exception as e:
        error_message = str(e)
        log_event(f"[OPERATOR] Error during NVIDIA GPU LLM cleanup: {error_message}")

