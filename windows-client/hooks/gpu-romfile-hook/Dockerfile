# KubeVirt GPU VBIOS ROM file hook sidecar
# ===========================================
# Implements v1alpha2 gRPC service that injects a <rom file='...'/>
# into the GPU hostdev entry of the libvirt domain XML before the VM starts.
#
# Build:  podman build -t localhost/gpu-romfile-hook:latest .
# Load:   podman save localhost/gpu-romfile-hook:latest | sudo ctr -n k8s.io images import -
# Verify: sudo ctr -n k8s.io images ls | grep gpu-romfile

FROM python:3.12-alpine

# Install grpcio + grpcio-tools (for proto compilation) + lxml
RUN pip install --no-cache-dir grpcio grpcio-tools

WORKDIR /hooks

# Copy proto files and compile gRPC stubs at image build time
# Two separate protos matching official KubeVirt v1.3.1 hook API:
#   api_info.proto     → kubevirt.hooks.info   (Info/Info)
#   api_v1alpha2.proto → kubevirt.hooks.v1alpha2 (Callbacks/OnDefineDomain)
COPY api_info.proto api_v1alpha2.proto ./
RUN python -m grpc_tools.protoc \
    -I. \
    --python_out=. \
    --grpc_python_out=. \
    api_info.proto api_v1alpha2.proto

# Remove grpcio-tools (only needed at build time) to keep image small
RUN pip uninstall -y grpcio-tools

# Copy the hook server
COPY on_define_domain.py .

# Bundle the 63 KB VBIOS ROM directly into the image — no host volume mount needed at runtime.
# Override GPU_ROM_FILE at deploy time if the ROM ever changes.
COPY gpu-03-00-0-legacyrom.rom .

# The socket directory is a shared emptyDir between virt-launcher and this sidecar
# KubeVirt mounts it at /var/run/kubevirt-hooks
VOLUME ["/var/run/kubevirt-hooks"]

ENV GPU_ROM_FILE="/hooks/gpu-03-00-0-legacyrom.rom" \
    GPU_BUS="0x03" \
    GPU_SLOT="0x00" \
    GPU_FUNCTION="0x0" \
    HOOK_SOCKET="/var/run/kubevirt-hooks/gpu-romfile.sock" \
    LOG_LEVEL="INFO"

ENTRYPOINT ["python3", "/hooks/on_define_domain.py"]
