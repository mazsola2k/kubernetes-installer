#!/bin/bash
# start_portforward.sh
# Usage: ./start_portforward.sh <service-name> <port> <namespace> <log-file> <pid-file>

export HOME=$HOME
export KUBECONFIG=${KUBECONFIG:-$HOME/.kube/config}
KUBECTL=$(which kubectl)
SERVICE_NAME="$1"
PORT="$2"
NAMESPACE="$3"
LOG_FILE="$4"
PID_FILE="$5"

pkill -f "port-forward.*$SERVICE_NAME.*$PORT" || true
nohup setsid "$KUBECTL" -n "$NAMESPACE" port-forward service/"$SERVICE_NAME" "$PORT:$PORT" > "$LOG_FILE" 2>&1 < /dev/null &
echo $! > "$PID_FILE"
