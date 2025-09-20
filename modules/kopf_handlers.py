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
from datetime import datetime
from kubernetes import client
from kubernetes.client.rest import ApiException

# Global log queue for TUI (import from canonical source)
from modules.utils.logging_config import log_queue

logger = logging.getLogger(__name__)

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
    }
}

def setup_kopf_handlers():
    """Set up all Kopf handlers for different resource types"""
    log_event("Setting up Kopf handlers for Windows services...")


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
    import time
    max_retries = 5
    retry_delay = 1  # seconds
    try:
        log_event(f"[OPERATOR] Deciding what to do for action={action} on VM {vm_name}")
        kopf.info(body, reason='Processing', message=f'Starting {action} for VM {vm_name}')
        log_event(f"[OPERATOR] Starting {action} for VM {vm_name}")
        playbook_path = "/root/kubernetes-installer/windows-server-controller.yaml"
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
    playbook_path = "/root/kubernetes-installer/windows-server-controller.yaml"
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
        playbook_path = "/root/kubernetes-installer/windows-automation-controller.yaml"
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
        playbook_path = "/root/kubernetes-installer/windows-automation-controller.yaml"
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
        for key, value in variables.items():
            cmd.extend(['--extra-vars', f'{key}={value}'])
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
    manifest_path = get_var('manifest_path', spec, '/root/kubernetes-installer/manifest-controller/rhel9-vm-cr.yaml')
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
        playbook_path = "/root/kubernetes-installer/redhat-server-controller.yaml"
        playbook_vars = {
            'action': action,
            'kind': kind,
            'manifest_path': manifest_path,
            'kubevirt_namespace': kubevirt_namespace,
            'vm_name': vm_name,
            'vm_image': vm_image,
            'vm_cpu_cores': vm_cpu_cores,
            'vm_memory': vm_memory,
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
    manifest_path = get_var('manifest_path', spec, '/root/kubernetes-installer/manifest-controller/rhel9-vm-cr.yaml')
    kubevirt_namespace = get_var('kubevirt_namespace', spec, namespace)
    patch.status['phase'] = 'Terminating'
    patch.status['message'] = f"Delete requested for Red Hat VM {vm_name}"
    patch.status['reason'] = 'DeleteRequested'
    patch.status['observedGeneration'] = meta.get('generation')
    playbook_path = "/root/kubernetes-installer/redhat-server-controller.yaml"
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
