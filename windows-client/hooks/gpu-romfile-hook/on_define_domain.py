#!/usr/bin/env python3
"""
KubeVirt Hook Sidecar - GPU VBIOS ROM file injector
====================================================
Implements the KubeVirt hooks v1alpha2 gRPC interface.

OnDefineDomain: locates the passthrough GPU's <hostdev> element in the
libvirt domain XML and injects:
    <rom file='/var/lib/kubevirt/gpu-03-00-0-legacyrom.rom'/>

This is the KubeVirt equivalent of QEMU's
  -device vfio-pci,...,romfile=/var/lib/kubevirt/gpu-03-00-0-legacyrom.rom

Environment variables (all optional, have sensible defaults):
  GPU_ROM_FILE   Path to the .rom file inside the sidecar container
                 Default: /var/lib/kubevirt/gpu-03-00-0-legacyrom.rom
  GPU_BUS        PCI bus  (hex with 0x prefix)  Default: 0x03
  GPU_SLOT       PCI slot (hex with 0x prefix)  Default: 0x00
  GPU_FUNCTION   PCI func (hex with 0x prefix)  Default: 0x0
  GPU_AUDIO_FUNCTION  PCI func of the companion HDMI audio device  Default: 0x1
                      Set to empty string to disable audio passthrough
  HOOK_SOCKET    Unix socket path               Default: /var/run/kubevirt-hooks/gpu-romfile.sock
  LOG_LEVEL      Logging level                  Default: INFO
"""

import os
import sys
import logging
import xml.etree.ElementTree as ET
from concurrent import futures

import grpc
# Two separate proto packages — matching official KubeVirt v1.3.1 definitions:
#   api_info.proto     → package kubevirt.hooks.info    → /kubevirt.hooks.info.Info/Info
#   api_v1alpha2.proto → package kubevirt.hooks.v1alpha2 → /kubevirt.hooks.v1alpha2.Callbacks/OnDefineDomain
import api_info_pb2
import api_info_pb2_grpc
import api_v1alpha2_pb2
import api_v1alpha2_pb2_grpc

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
ROM_FILE           = os.environ.get("GPU_ROM_FILE",       "/var/lib/kubevirt/gpu-03-00-0-legacyrom.rom")
GPU_BUS            = os.environ.get("GPU_BUS",           "0x03").lower()
GPU_SLOT           = os.environ.get("GPU_SLOT",          "0x00").lower()
GPU_FUNCTION       = os.environ.get("GPU_FUNCTION",       "0x0").lower()
# Companion HDMI audio device — same bus/slot, different function.
# Set GPU_AUDIO_FUNCTION='' to disable audio passthrough.
GPU_AUDIO_FUNCTION = os.environ.get("GPU_AUDIO_FUNCTION", "0x1").lower()
HOOK_SOCKET        = os.environ.get("HOOK_SOCKET",        "/var/run/kubevirt-hooks/gpu-romfile.sock")
LOG_LEVEL          = os.environ.get("LOG_LEVEL",          "INFO")
# The hook-sidecar-sockets emptyDir is shared between ALL containers in the pod.
# QEMU (in the compute container) can read files from this directory.
# We copy the ROM there at startup so QEMU can find it.
SHARED_HOOKS_DIR = "/var/run/kubevirt-hooks"
# virt-launcher scans /var/run/kubevirt-hooks/ (including subdirs) for sockets
# and tries to dial ANY entry it finds there as a gRPC socket, causing errors.
# Use /dev/shm/ instead — it is shared across all containers in the same pod
# via the shared IPC namespace, but is invisible to the hook socket scanner.
SHARED_ROM_PATH  = os.path.join("/dev/shm", os.path.basename(ROM_FILE))
logging.basicConfig(
    level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s %(levelname)-8s [gpu-romfile-hook] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("gpu-romfile-hook")


# ---------------------------------------------------------------------------
# XML patching logic
# ---------------------------------------------------------------------------
def _normalise_hex(val: str) -> str:
    """Normalise a hex PCI address component to lowercase 0x-prefixed form."""
    val = val.strip().lower()
    if not val.startswith("0x"):
        val = "0x" + val
    return val


def patch_domain_xml(domain_xml_bytes: bytes) -> bytes:
    """
    Parse the libvirt domain XML and apply all patches needed for NVIDIA GPU passthrough:

      1. <rom file='...'/>       on the GPU hostdev  (romfile from shared /dev/shm)
      2. multifunction='on'      on the GPU hostdev  (matches -device vfio-pci,...,multifunction=on)
      3. <ioapic driver='kvm'/> in <features>        (kernel-irqchip=on equivalent)
      4. <qemu:commandline>      adds -device vfio-pci,host=03:00.1  for the HDMI audio
                                 companion device.  Injecting it as a <hostdev> causes
                                 virt-launcher to nil-pointer panic (it didn't allocate it);
                                 qemu:commandline bypasses virt-launcher's device tracker.

    Returns the modified XML as bytes.
    """
    domain_xml = domain_xml_bytes.decode("utf-8")

    try:
        # Parse while preserving the namespace declarations that libvirt emits
        root = ET.fromstring(domain_xml)
    except ET.ParseError as exc:
        log.error("Failed to parse domain XML: %s", exc)
        return domain_xml_bytes

    devices = root.find("devices")
    if devices is None:
        log.warning("No <devices> section in domain XML — skipping romfile injection")
        return domain_xml_bytes

    target_bus  = _normalise_hex(GPU_BUS)
    target_slot = _normalise_hex(GPU_SLOT)
    target_func = _normalise_hex(GPU_FUNCTION)

    patched = False
    audio_already_present = False
    target_audio_func = _normalise_hex(GPU_AUDIO_FUNCTION) if GPU_AUDIO_FUNCTION else None

    # Scan existing hostdevs: patch GPU romfile and check if audio is already there
    for hostdev in devices.findall("hostdev"):
        if hostdev.get("type") != "pci":
            continue
        source = hostdev.find("source")
        if source is None:
            continue
        addr = source.find("address")
        if addr is None:
            continue

        bus  = _normalise_hex(addr.get("bus",      ""))
        slot = _normalise_hex(addr.get("slot",     ""))
        func = _normalise_hex(addr.get("function", ""))

        if bus == target_bus and slot == target_slot and func == target_func:
            # Add multifunction=on — matches  -device vfio-pci,...,multifunction=on
            # in the working KVM config; groups GPU + audio under one PCI slot.
            hostdev.set("multifunction", "on")

            existing_rom = hostdev.find("rom")
            if existing_rom is not None:
                log.info("Updating existing <rom> element: file=%s", SHARED_ROM_PATH)
                existing_rom.set("file", SHARED_ROM_PATH)
                existing_rom.attrib.pop("bar", None)
            else:
                log.info("Injecting <rom file='%s'/> into GPU hostdev [%s:%s.%s]",
                         SHARED_ROM_PATH, bus, slot, func)
                rom_elem = ET.SubElement(hostdev, "rom")
                rom_elem.set("file", SHARED_ROM_PATH)
            patched = True

        if target_audio_func and bus == target_bus and slot == target_slot and func == target_audio_func:
            audio_already_present = True
            log.debug("GPU HDMI audio hostdev [%s:%s.%s] already present", bus, slot, func)

    if not patched:
        log.warning(
            "GPU hostdev %s:%s.%s NOT found in domain XML — romfile not injected!",
            target_bus, target_slot, target_func,
        )
        log.debug("Full domain XML:\n%s", domain_xml)

    # Always log the domain XML at DEBUG level for inspection
    log.debug("Input domain XML:\n%s", domain_xml)

    # -----------------------------------------------------------------------
    # Inject the GPU companion HDMI audio (e.g. 03:00.1) via <qemu:commandline>.
    #
    # Why NOT <hostdev>: virt-launcher tracks every <hostdev> against its
    # allocation pool.  A device it never allocated causes a nil-pointer panic.
    #
    # <qemu:commandline> appends raw QEMU -device args that bypass libvirt's
    # device model entirely — exactly how the working KVM playbook does it:
    #   -device vfio-pci,host=03:00.1
    #
    # KubeVirt calls OnDefineDomain TWICE per VM start.  Call 2 redefines the
    # domain in libvirt, overwriting call 1.  We MUST inject on every call so
    # the final domain definition (from call 2) includes the audio device.
    # The injection is idempotent: we first strip any existing qemu:commandline
    # audio args to avoid duplicates.
    # -----------------------------------------------------------------------
    if target_audio_func and not audio_already_present:
        QEMU_NS = "http://libvirt.org/schemas/domain/qemu/1.0"
        ET.register_namespace("qemu", QEMU_NS)
        audio_host_full = (f"0000:{int(target_bus, 16):02x}:{int(target_slot, 16):02x}"
                           f".{int(target_audio_func, 16)}")
        cmdline_tag = f"{{{QEMU_NS}}}commandline"
        arg_tag     = f"{{{QEMU_NS}}}arg"

        # --- Idempotency: strip any prior audio args from qemu:commandline ---
        existing_cmdline = root.find(cmdline_tag)
        if existing_cmdline is not None:
            args_list = list(existing_cmdline)
            i = 0
            while i < len(args_list) - 1:
                if (args_list[i].get("value") == "-device" and
                        audio_host_full in args_list[i + 1].get("value", "")):
                    log.info("Removing stale audio arg from prior hook call")
                    existing_cmdline.remove(args_list[i])
                    existing_cmdline.remove(args_list[i + 1])
                    args_list = list(existing_cmdline)
                    continue
                i += 1
            # If commandline block is now empty, remove it entirely
            if len(list(existing_cmdline)) == 0:
                root.remove(existing_cmdline)

        # ---- Find a free pcie-root-port bus for the audio device ----
        # Passthrough <hostdev> elements contain TWO <address> elements:
        #   <source><address bus='0x03'.../> — the PHYSICAL PCI address (NOT a VM bus)
        #   <address type='pci' bus='0x09'.../> — the VM placement bus
        # Build a parent map to skip source-block addresses.
        parent_map = {child: parent for parent in root.iter() for child in parent}

        used_buses: set[int] = set()
        for addr in root.iter("address"):
            elem = addr
            in_source = False
            while elem in parent_map:
                elem = parent_map[elem]
                if elem.tag == "source":
                    in_source = True
                    break
            if in_source:
                continue
            bus_val = addr.get("bus", "")
            if bus_val:
                try:
                    used_buses.add(int(bus_val, 16) if bus_val.startswith("0x") else int(bus_val))
                except ValueError:
                    pass

        pcie_port_indices: list[int] = []
        for ctrl in root.iter("controller"):
            if ctrl.get("type") == "pci" and ctrl.get("model") == "pcie-root-port":
                idx = ctrl.get("index")
                if idx is not None:
                    pcie_port_indices.append(int(idx))

        log.info("DEBUG pcie-root-port indices: %s", sorted(pcie_port_indices))
        log.info("DEBUG used PCI bus numbers (placement only): %s", sorted(used_buses))

        # Pick HIGHEST-indexed root-port bus that has no device attached.
        # We pick highest (not lowest) because libvirt auto-assigns addresses
        # to devices that don't have explicit <address> in the XML AFTER our
        # hook returns.  Those auto-assigned addresses fill from the low end
        # (pci.1, pci.2, ...), so we avoid collisions by using the top end.
        free_port = None
        for idx in sorted(pcie_port_indices, reverse=True):
            if idx > 0 and idx not in used_buses:
                free_port = idx
                break

        if free_port is None:
            log.warning("No free pcie-root-port found among %s; falling back to pci.2",
                        pcie_port_indices)
            free_port = 2  # pci.2 is always created by KubeVirt

        # Use JSON format — plain-text 'key=val' format cannot resolve bus
        # names that were created by JSON -device args in this QEMU version.
        import json as _json
        audio_dev_arg = _json.dumps({
            "driver": "vfio-pci",
            "host":   audio_host_full,
            "bus":    f"pci.{free_port}",
            "addr":   "0x0",
        }, separators=(",", ":"))
        log.info("Audio device bus: pci.%d (free root-port), host=%s", free_port, audio_host_full)

        cmdline = root.find(cmdline_tag)
        if cmdline is None:
            cmdline = ET.SubElement(root, cmdline_tag)

        ET.SubElement(cmdline, arg_tag, value="-device")
        ET.SubElement(cmdline, arg_tag, value=audio_dev_arg)
        log.info("Injected <qemu:commandline> -device %s (GPU HDMI audio)", audio_dev_arg)
    elif target_audio_func:
        log.debug("GPU HDMI audio already present as hostdev — skipping qemu:commandline injection")

    # -----------------------------------------------------------------------
    # Inject <ioapic driver='kvm'/> into <features> if not already present.
    # This is the libvirt equivalent of QEMU's -machine kernel-irqchip=on,
    # which is required for NVIDIA GPU passthrough (prevents Code 43).
    # KubeVirt v1.3.1 silently drops this field from its CRD, so we must
    # inject it via the hook.
    # -----------------------------------------------------------------------
    features = root.find("features")
    if features is not None:
        if features.find("ioapic") is None:
            ioapic_elem = ET.SubElement(features, "ioapic")
            ioapic_elem.set("driver", "kvm")
            log.info("Injected <ioapic driver='kvm'/> into <features> (kernel-irqchip=on)")
        else:
            log.debug("<ioapic> already present in <features>")
    else:
        log.warning("No <features> section found — ioapic not injected")

    # Serialise back; skip the XML declaration to keep libvirt happy
    return ET.tostring(root, encoding="unicode").encode("utf-8")


# ---------------------------------------------------------------------------
# gRPC service implementations
# ---------------------------------------------------------------------------
class InfoServicer(api_info_pb2_grpc.InfoServicer):
    def Info(self, request, context):
        log.debug("Info() called")
        return api_info_pb2.InfoResult(
            name="gpu-romfile-hook",
            hookPoints=[api_info_pb2.HookPoint(name="OnDefineDomain", priority=0)],
            versions=["v1alpha2"],
        )


class CallbacksServicer(api_v1alpha2_pb2_grpc.CallbacksServicer):
    def OnDefineDomain(self, request, context):
        log.info("OnDefineDomain() called — patching domain XML")
        try:
            patched = patch_domain_xml(request.domainXML)
        except Exception as exc:
            log.error("Unexpected error while patching domain XML: %s", exc, exc_info=True)
            patched = request.domainXML
        return api_v1alpha2_pb2.OnDefineDomainResult(domainXML=patched)

    def PreCloudInitIso(self, request, context):
        log.debug("PreCloudInitIso() — passthrough")
        return api_v1alpha2_pb2.PreCloudInitIsoResult(
            cloudInitData=request.cloudInitData
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
def main():
    sock_dir = os.path.dirname(HOOK_SOCKET)
    os.makedirs(sock_dir, exist_ok=True)

    # Copy ROM to /dev/shm so the compute container (QEMU) can also read it.
    # /dev/shm is shared across all containers in a pod via the IPC namespace.
    # We cannot use /var/run/kubevirt-hooks/ because virt-launcher scans that
    # directory (and all entries in it) for gRPC sockets and would try to dial
    # any file or directory it finds there, causing context-deadline errors.
    if not os.path.exists(ROM_FILE):
        log.error("ROM file not found at %s — cannot copy to /dev/shm!", ROM_FILE)
    else:
        import shutil
        shutil.copy2(ROM_FILE, SHARED_ROM_PATH)
        os.chmod(SHARED_ROM_PATH, 0o644)
        log.info("Copied ROM file to /dev/shm: %s", SHARED_ROM_PATH)

    # Remove stale socket from a previous run
    if os.path.exists(HOOK_SOCKET):
        os.remove(HOOK_SOCKET)

    server = grpc.server(futures.ThreadPoolExecutor(max_workers=4))
    api_info_pb2_grpc.add_InfoServicer_to_server(InfoServicer(), server)
    api_v1alpha2_pb2_grpc.add_CallbacksServicer_to_server(CallbacksServicer(), server)
    server.add_insecure_port(f"unix://{HOOK_SOCKET}")
    server.start()

    log.info("GPU romfile hook sidecar started")
    log.info("  Socket  : %s", HOOK_SOCKET)
    log.info("  ROM file: %s → %s", ROM_FILE, SHARED_ROM_PATH)
    log.info("  GPU PCI : bus=%s slot=%s function=%s", GPU_BUS, GPU_SLOT, GPU_FUNCTION)

    server.wait_for_termination()


if __name__ == "__main__":
    main()
