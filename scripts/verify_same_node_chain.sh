#!/usr/bin/env bash
set -euo pipefail

NS_NAMESPACE="${NS_NAMESPACE:-nse-ovs-nat}"
NSM_SYSTEM_NAMESPACE="${NSM_SYSTEM_NAMESPACE:-nsm-system}"
CLIENT_POD_PREFIX="${CLIENT_POD_PREFIX:-nsc-ovs-client-}"
NAT_POD_PREFIX="${NAT_POD_PREFIX:-nse-ovs-nat-}"
SERVER_POD_PREFIX="${SERVER_POD_PREFIX:-nse-ovs-server-}"
CLIENT_IFACE="${CLIENT_IFACE:-nsm-1}"
SERVER_IFACE="${SERVER_IFACE:-nsm-1}"
CLIENT_CONTAINER="${CLIENT_CONTAINER:-client}"
CLIENT_CMD_CONTAINER="${CLIENT_CMD_CONTAINER:-cmd-nsc}"
NAT_CONTAINER="${NAT_CONTAINER:-nse}"
SERVER_CONTAINER="${SERVER_CONTAINER:-server}"
NAT_RULES_PATH="${NAT_RULES_PATH:-/etc/nse-nat/rules.yaml}"
WAIT_TIMEOUT_SECONDS="${WAIT_TIMEOUT_SECONDS:-60}"
PROOF_WINDOW_SECONDS="${PROOF_WINDOW_SECONDS:-3}"
PROOF_CONN_WAIT_SECONDS="${PROOF_CONN_WAIT_SECONDS:-10}"
ARTIFACT_DIR="${ARTIFACT_DIR:-}"
KUBECTL="${KUBECTL:-kubectl}"
DEFAULT_VIRTUAL_IP="${DEFAULT_VIRTUAL_IP:-172.16.5.10}"
DEFAULT_VIRTUAL_PORT="${DEFAULT_VIRTUAL_PORT:-8080}"
DEFAULT_BACKEND_PORT="${DEFAULT_BACKEND_PORT:-5201}"
EXPECT_RESULT="success"
VIRTUAL_IP_INPUT=""
VIRTUAL_PORT_INPUT=""
BACKEND_IP_INPUT=""
BACKEND_PORT_INPUT=""

forward_tcp_pref=110
reverse_tcp_pref=210

usage() {
  cat <<'EOF'
Usage: ./scripts/verify_same_node_chain.sh [--expect-success|--expect-fail] [--virtual-ip <ip>] [--virtual-port <port>] [--backend-ip <ip>] [--backend-port <port>] [--artifact-dir <path>] [--proof-window-seconds <n>]

Verify the same-node NSM OVS NAT chain and prove the current static port-mapping
behavior with direct-backend health, forward/reverse path counters, tc hit counters,
and client/server socket snapshots.

Options:
  --expect-success             Expect virtual tuple access to succeed. Default.
  --expect-fail                Expect virtual tuple access to fail under the current profile.
  --virtual-ip <ip>            Override virtual IP instead of reading it from the NAT pod rules file.
  --virtual-port <port>        Override virtual port instead of reading it from the NAT pod rules file.
  --backend-ip <ip>            Override backend IP instead of reading it from the server interface.
  --backend-port <port>        Override backend port instead of reading it from the NAT pod rules file.
  --artifact-dir <path>        Persist raw proof artifacts into the given directory.
  --proof-window-seconds <n>   Keep the proof iperf3 flow open long enough for snapshots. Default: 3
  -h, --help                   Show this help text.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --expect-success)
      EXPECT_RESULT="success"
      shift
      ;;
    --expect-fail)
      EXPECT_RESULT="fail"
      shift
      ;;
    --virtual-ip)
      VIRTUAL_IP_INPUT="${2:-}"
      shift 2
      ;;
    --virtual-port)
      VIRTUAL_PORT_INPUT="${2:-}"
      shift 2
      ;;
    --backend-ip)
      BACKEND_IP_INPUT="${2:-}"
      shift 2
      ;;
    --backend-port)
      BACKEND_PORT_INPUT="${2:-}"
      shift 2
      ;;
    --artifact-dir)
      ARTIFACT_DIR="${2:-}"
      shift 2
      ;;
    --proof-window-seconds)
      PROOF_WINDOW_SECONDS="${2:-}"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

tmpdir="$(mktemp -d)"
request_pid=""

die() {
  echo "ERROR: $*" >&2
  exit 1
}

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "missing required command: $1"
}

run_kubectl() {
  "$KUBECTL" "$@"
}

sanitize_name() {
  local value="$1"
  [[ "$value" =~ ^[A-Za-z0-9._:-]+$ ]] || die "unexpected name: $value"
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

kv_get() {
  local file="$1"
  local key="$2"
  awk -F'=' -v key="$key" '$1 == key { print $2; exit }' "$file"
}

delta_from_files() {
  local before_file="$1"
  local after_file="$2"
  local key="$3"
  local before_value after_value
  before_value="$(kv_get "$before_file" "$key")"
  after_value="$(kv_get "$after_file" "$key")"
  [[ -n "$before_value" ]] || die "missing before counter $key in $before_file"
  [[ -n "$after_value" ]] || die "missing after counter $key in $after_file"
  echo $((after_value - before_value))
}

persist_artifact() {
  local source_file="$1"
  local target_name="$2"
  if [[ -z "${ARTIFACT_DIR}" ]]; then
    return 0
  fi

  mkdir -p "${ARTIFACT_DIR}"
  cp "${source_file}" "${ARTIFACT_DIR}/${target_name}"
}

get_running_pod_by_prefix() {
  local namespace="$1"
  local prefix="$2"
  run_kubectl get pods -n "$namespace" --no-headers \
    -o custom-columns=NAME:.metadata.name,PHASE:.status.phase \
    | awk -v prefix="$prefix" '$1 ~ ("^" prefix) && $2 == "Running" { print $1; exit }'
}

get_forwarder_pod_on_node() {
  local node_name="$1"
  run_kubectl get pods -n "$NSM_SYSTEM_NAMESPACE" --no-headers \
    -o custom-columns=NAME:.metadata.name,PHASE:.status.phase,NODE:.spec.nodeName \
    | awk -v node_name="$node_name" '$1 ~ /^forwarder-ovs-/ && $2 == "Running" && $3 == node_name { print $1; exit }'
}

require_container() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  if ! run_kubectl get pod -n "$namespace" "$pod_name" \
    -o jsonpath='{range .spec.containers[*]}{.name}{"\n"}{end}' | grep -Fxq "$container_name"; then
    die "container $container_name not found in pod $namespace/$pod_name"
  fi
}

pod_sh() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local command="$4"
  run_kubectl exec -n "$namespace" "$pod_name" -c "$container_name" -- sh -eu -c "$command"
}

list_named_links() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local pattern="$4"
  pod_sh "$namespace" "$pod_name" "$container_name" "
    ip -o link show | awk -F': ' '
      {
        name = \$2
        sub(/ .*/, \"\", name)
        sub(/@.*/, \"\", name)
        if (name ~ /${pattern}/) {
          print \$0
        }
      }'
  "
}

resolve_server_iface() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local preferred_iface="${4:-}"

  if [[ -n "${preferred_iface}" ]] && pod_sh "$namespace" "$pod_name" "$container_name" \
    "ip -o link show dev '${preferred_iface}' >/dev/null 2>&1"; then
    printf '%s\n' "${preferred_iface}"
    return 0
  fi

  local link_line
  link_line="$(trim "$(list_named_links "$namespace" "$pod_name" "$container_name" '^nse-ovs-' | head -n1)")"
  [[ -n "${link_line}" ]] || return 1

  parse_link_name "${link_line}"
}

parse_link_name() {
  local line="$1"
  local token
  token="$(printf '%s\n' "$line" | awk -F': ' '{print $2}' | awk '{print $1}')"
  token="${token%:}"
  printf '%s' "${token%%@*}"
}

parse_link_peer_ifindex() {
  local line="$1"
  local token
  token="$(printf '%s\n' "$line" | awk -F': ' '{print $2}' | awk '{print $1}')"
  token="${token%:}"
  printf '%s\n' "$token" | sed -n 's/.*@if\([0-9][0-9]*\)$/\1/p'
}

capture_netdev_stats() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local iface_name="$4"
  sanitize_name "$iface_name"
  pod_sh "$namespace" "$pod_name" "$container_name" \
    "for key in rx_bytes rx_packets tx_bytes tx_packets; do printf '%s=%s\n' \"\$key\" \"\$(cat /sys/class/net/$iface_name/statistics/\$key)\"; done"
}

capture_ofport_stats() {
  local forwarder_pod="$1"
  local ofport="$2"
  sanitize_name "$ofport"
  run_kubectl exec -n "$NSM_SYSTEM_NAMESPACE" "$forwarder_pod" -- \
    ovs-ofctl dump-ports br-nsm "$ofport" \
    | awk '
        /port [0-9]+: rx pkts=/ {
          gsub(/,/, "")
          match($0, /pkts=([0-9]+)/, rx_pkts)
          match($0, /bytes=([0-9]+)/, rx_b)
          rx_packets = rx_pkts[1]
          rx_bytes = rx_b[1]
        }
        /tx pkts=/ {
          gsub(/,/, "")
          match($0, /pkts=([0-9]+)/, tx_pkts)
          match($0, /bytes=([0-9]+)/, tx_b)
          tx_packets = tx_pkts[1]
          tx_bytes = tx_b[1]
        }
        END {
          printf "rx_bytes=%s\nrx_packets=%s\ntx_bytes=%s\ntx_packets=%s\n", rx_bytes, rx_packets, tx_bytes, tx_packets
        }'
}

save_snapshot() {
  local file_path="$1"
  shift
  "$@" >"$file_path"
}

forwarder_port_name_for_ifindex() {
  local links_file="$1"
  local ifindex="$2"
  awk -F': ' -v ifindex="$ifindex" '
    $1 == ifindex {
      split($2, fields, " ")
      name = fields[1]
      sub(/:$/, "", name)
      sub(/@.*/, "", name)
      print name
      exit
    }' "$links_file"
}

port_conn_id() {
  local port_name="$1"
  printf '%s' "$port_name" | sed -E 's/^tap(src|dst)-//'
}

lookup_ofport() {
  local forwarder_pod="$1"
  local port_name="$2"
  sanitize_name "$port_name"
  trim "$(run_kubectl exec -n "$NSM_SYSTEM_NAMESPACE" "$forwarder_pod" -- ovs-vsctl get Interface "$port_name" ofport)"
}

capture_ss_snapshot() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local output_file="$4"
  pod_sh "$namespace" "$pod_name" "$container_name" "ss -tnH state all 2>/dev/null || true" >"$output_file"
}

wait_for_ss_match() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local pattern="$4"
  local timeout_seconds="$5"
  local output_file="$6"
  local deadline=$((SECONDS + timeout_seconds))

  while ((SECONDS < deadline)); do
    capture_ss_snapshot "$namespace" "$pod_name" "$container_name" "$output_file"
    if grep -Fq "$pattern" "$output_file"; then
      return 0
    fi
    sleep 1
  done

  capture_ss_snapshot "$namespace" "$pod_name" "$container_name" "$output_file"
  return 1
}

capture_tc_filter_stats() {
  local namespace="$1"
  local pod_name="$2"
  local container_name="$3"
  local iface_name="$4"
  local output_file="$5"
  sanitize_name "$iface_name"
  pod_sh "$namespace" "$pod_name" "$container_name" \
    "tc -s filter show dev '${iface_name}' ingress 2>/dev/null || true" >"$output_file"
}

tc_pref_packets_from_file() {
  local file_path="$1"
  local pref="$2"
  awk -v pref="${pref}" '
    $0 ~ ("pref " pref " ") {
      in_filter = 1
      awaiting_stats = 0
      next
    }
    in_filter && /^filter pref / {
      in_filter = 0
      awaiting_stats = 0
    }
    in_filter && /Action statistics:/ {
      awaiting_stats = 1
      next
    }
    in_filter && awaiting_stats && /Sent / {
      for (i = 1; i <= NF; i++) {
        if ($i == "pkt" && i > 1) {
          print $(i - 1)
          found = 1
          exit
        }
      }
      awaiting_stats = 0
    }
    END {
      if (!found) {
        print 0
      }
    }' "$file_path"
}

stop_iperf_server() {
  if [[ -z "${server_pod:-}" ]]; then
    return 0
  fi

  pod_sh "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER" "
    pkill -x iperf3 2>/dev/null || true
  " >/dev/null 2>&1 || true
}

start_iperf_server() {
  stop_iperf_server
  pod_sh "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER" "
    iperf3 -s -B '${backend_ip}' -p '${backend_port}' -D
    sleep 1
    ss -ltn sport = :${backend_port} | grep -F '${backend_ip}:${backend_port}' >/dev/null
  "
}

run_iperf_sync() {
  local target_ip="$1"
  local target_port="$2"
  local output_file="$3"
  if ! run_kubectl exec -n "$NS_NAMESPACE" "$client_pod" -c "$CLIENT_CONTAINER" -- \
    sh -eu -c "timeout 10 iperf3 -c '${target_ip}' -p '${target_port}' -t 1" >"$output_file" 2>&1; then
    cat "$output_file"
    die "direct backend iperf3 request failed"
  fi
}

start_iperf_request_async() {
  local target_ip="$1"
  local target_port="$2"
  local output_file="$3"
  local proof_runtime_seconds=$((PROOF_WINDOW_SECONDS + 2))
  run_kubectl exec -n "$NS_NAMESPACE" "$client_pod" -c "$CLIENT_CONTAINER" -- \
    sh -eu -c "timeout '$((proof_runtime_seconds + PROOF_CONN_WAIT_SECONDS + 5))' iperf3 -c '${target_ip}' -p '${target_port}' -t '${proof_runtime_seconds}'" \
    >"$output_file" 2>&1 &
  request_pid=$!
}

trap 'stop_iperf_server; if [[ -n "${request_pid:-}" ]]; then kill "${request_pid}" 2>/dev/null || true; wait "${request_pid}" 2>/dev/null || true; fi; if [[ -n "${client_pod:-}" && -n "${virtual_ip:-}" ]]; then pod_sh "${NS_NAMESPACE}" "${client_pod}" "${CLIENT_CONTAINER}" "ip neigh del \"${virtual_ip}\" dev \"${CLIENT_IFACE}\" 2>/dev/null || true; ip route del \"${virtual_ip}/32\" dev \"${CLIENT_IFACE}\" 2>/dev/null || true" >/dev/null 2>&1 || true; fi; rm -rf "${tmpdir}"' EXIT

need_cmd awk
need_cmd grep
need_cmd kubectl
need_cmd sed

client_pod="$(get_running_pod_by_prefix "$NS_NAMESPACE" "$CLIENT_POD_PREFIX")"
nat_pod="$(get_running_pod_by_prefix "$NS_NAMESPACE" "$NAT_POD_PREFIX")"
server_pod="$(get_running_pod_by_prefix "$NS_NAMESPACE" "$SERVER_POD_PREFIX")"

[[ -n "$client_pod" ]] || die "running client pod with prefix $CLIENT_POD_PREFIX not found in namespace $NS_NAMESPACE"
[[ -n "$nat_pod" ]] || die "running nat pod with prefix $NAT_POD_PREFIX not found in namespace $NS_NAMESPACE"
[[ -n "$server_pod" ]] || die "running server pod with prefix $SERVER_POD_PREFIX not found in namespace $NS_NAMESPACE"

client_node="$(trim "$(run_kubectl get pod -n "$NS_NAMESPACE" "$client_pod" -o jsonpath='{.spec.nodeName}')")"
[[ -n "$client_node" ]] || die "unable to determine node for pod $client_pod"
forwarder_pod="$(get_forwarder_pod_on_node "$client_node")"
[[ -n "$forwarder_pod" ]] || die "running forwarder-ovs pod not found on node $client_node"

require_container "$NS_NAMESPACE" "$client_pod" "$CLIENT_CONTAINER"
require_container "$NS_NAMESPACE" "$client_pod" "$CLIENT_CMD_CONTAINER"
require_container "$NS_NAMESPACE" "$nat_pod" "$NAT_CONTAINER"
require_container "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER"

client_link_line="$(pod_sh "$NS_NAMESPACE" "$client_pod" "$CLIENT_CONTAINER" "ip -o link show dev ${CLIENT_IFACE}")"
client_iface="$(parse_link_name "$client_link_line")"
client_peer_ifindex="$(parse_link_peer_ifindex "$client_link_line")"
[[ -n "$client_iface" ]] || die "unable to parse client interface from: $client_link_line"
[[ -n "$client_peer_ifindex" ]] || die "unable to parse client peer ifindex from: $client_link_line"

mapfile -t nat_leg_lines < <(list_named_links "$NS_NAMESPACE" "$nat_pod" "$NAT_CONTAINER" '^nse-ovs-')
[[ "${#nat_leg_lines[@]}" -eq 2 ]] || die "expected 2 NAT data interfaces, got ${#nat_leg_lines[@]}"
nat_bridge_line="$(list_named_links "$NS_NAMESPACE" "$nat_pod" "$NAT_CONTAINER" '^nsmbr' | head -n1)"
nat_bridge="$(parse_link_name "$nat_bridge_line")"
if [[ -z "$nat_bridge" ]]; then
  nat_bridge="<none>"
fi

nat_leg_a="$(parse_link_name "${nat_leg_lines[0]}")"
nat_leg_a_peer_ifindex="$(parse_link_peer_ifindex "${nat_leg_lines[0]}")"
nat_leg_b="$(parse_link_name "${nat_leg_lines[1]}")"
nat_leg_b_peer_ifindex="$(parse_link_peer_ifindex "${nat_leg_lines[1]}")"
[[ -n "$nat_leg_a_peer_ifindex" ]] || die "unable to parse NAT leg A peer ifindex"
[[ -n "$nat_leg_b_peer_ifindex" ]] || die "unable to parse NAT leg B peer ifindex"

server_iface_hint="$(resolve_server_iface "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER" "$SERVER_IFACE")" \
  || die "unable to determine server data interface"
server_link_line="$(pod_sh "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER" "ip -o link show dev '${server_iface_hint}'")"
server_iface="$(parse_link_name "$server_link_line")"
server_peer_ifindex="$(parse_link_peer_ifindex "$server_link_line")"
[[ -n "$server_iface" ]] || die "unable to parse server interface from: $server_link_line"
[[ -n "$server_peer_ifindex" ]] || die "unable to parse server peer ifindex from: $server_link_line"

backend_ip="${BACKEND_IP_INPUT:-$(trim "$(pod_sh "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER" "ip -o -4 addr show dev '${server_iface_hint}' | awk '{print \$4}' | cut -d/ -f1 | head -n1")")}"
[[ -n "$backend_ip" ]] || die "unable to determine backend IP"

nat_mode="$(trim "$(pod_sh "$NS_NAMESPACE" "$nat_pod" "$NAT_CONTAINER" "awk -F': *' '/^mode:/{print \$2; exit}' '${NAT_RULES_PATH}'")")"
virtual_ip="${VIRTUAL_IP_INPUT:-$(trim "$(pod_sh "$NS_NAMESPACE" "$nat_pod" "$NAT_CONTAINER" "awk -F': *' '/^virtual_ip:/{print \$2; exit}' '${NAT_RULES_PATH}' 2>/dev/null || true")")}"
virtual_port="${VIRTUAL_PORT_INPUT:-$(trim "$(pod_sh "$NS_NAMESPACE" "$nat_pod" "$NAT_CONTAINER" "awk -F': *' '/^virtual_port:/{print \$2; exit}' '${NAT_RULES_PATH}' 2>/dev/null || true")")}"
backend_port="${BACKEND_PORT_INPUT:-$(trim "$(pod_sh "$NS_NAMESPACE" "$nat_pod" "$NAT_CONTAINER" "awk -F': *' '/^backend_port:/{print \$2; exit}' '${NAT_RULES_PATH}' 2>/dev/null || true")")}"
if [[ -z "$virtual_ip" ]]; then
  virtual_ip="$DEFAULT_VIRTUAL_IP"
fi
if [[ -z "$virtual_port" ]]; then
  virtual_port="$DEFAULT_VIRTUAL_PORT"
fi
if [[ -z "$backend_port" ]]; then
  backend_port="$DEFAULT_BACKEND_PORT"
fi

server_mac="$(trim "$(pod_sh "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER" "cat /sys/class/net/${server_iface_hint}/address")")"
[[ -n "$server_mac" ]] || die "unable to determine server MAC"

forwarder_links_file="${tmpdir}/forwarder-links.txt"
run_kubectl exec -n "$NSM_SYSTEM_NAMESPACE" "$forwarder_pod" -- ip -o link show >"$forwarder_links_file"
persist_artifact "$forwarder_links_file" "forwarder-links.txt"

client_forwarder_port="$(forwarder_port_name_for_ifindex "$forwarder_links_file" "$client_peer_ifindex")"
server_forwarder_port="$(forwarder_port_name_for_ifindex "$forwarder_links_file" "$server_peer_ifindex")"
nat_leg_a_forwarder_port="$(forwarder_port_name_for_ifindex "$forwarder_links_file" "$nat_leg_a_peer_ifindex")"
nat_leg_b_forwarder_port="$(forwarder_port_name_for_ifindex "$forwarder_links_file" "$nat_leg_b_peer_ifindex")"

[[ -n "$client_forwarder_port" ]] || die "unable to map client peer ifindex ${client_peer_ifindex} to forwarder port"
[[ -n "$server_forwarder_port" ]] || die "unable to map server peer ifindex ${server_peer_ifindex} to forwarder port"
[[ -n "$nat_leg_a_forwarder_port" ]] || die "unable to map NAT leg A peer ifindex ${nat_leg_a_peer_ifindex} to forwarder port"
[[ -n "$nat_leg_b_forwarder_port" ]] || die "unable to map NAT leg B peer ifindex ${nat_leg_b_peer_ifindex} to forwarder port"

client_conn_id="$(port_conn_id "$client_forwarder_port")"
server_conn_id="$(port_conn_id "$server_forwarder_port")"
leg_a_conn_id="$(port_conn_id "$nat_leg_a_forwarder_port")"
leg_b_conn_id="$(port_conn_id "$nat_leg_b_forwarder_port")"

if [[ "$leg_a_conn_id" == "$client_conn_id" ]]; then
  nat_ingress_leg="$nat_leg_a"
  nat_ingress_forwarder_port="$nat_leg_a_forwarder_port"
  nat_egress_leg="$nat_leg_b"
  nat_egress_forwarder_port="$nat_leg_b_forwarder_port"
elif [[ "$leg_b_conn_id" == "$client_conn_id" ]]; then
  nat_ingress_leg="$nat_leg_b"
  nat_ingress_forwarder_port="$nat_leg_b_forwarder_port"
  nat_egress_leg="$nat_leg_a"
  nat_egress_forwarder_port="$nat_leg_a_forwarder_port"
else
  die "unable to match NAT ingress leg to client connection id ${client_conn_id}"
fi

if [[ "$(port_conn_id "$nat_egress_forwarder_port")" != "$server_conn_id" ]]; then
  die "NAT egress leg does not map to server connection id ${server_conn_id}"
fi

client_ofport="$(lookup_ofport "$forwarder_pod" "$client_forwarder_port")"
nat_ingress_ofport="$(lookup_ofport "$forwarder_pod" "$nat_ingress_forwarder_port")"
nat_egress_ofport="$(lookup_ofport "$forwarder_pod" "$nat_egress_forwarder_port")"
server_ofport="$(lookup_ofport "$forwarder_pod" "$server_forwarder_port")"

start_iperf_server

backend_output_file="${tmpdir}/backend-direct-iperf.txt"
run_iperf_sync "$backend_ip" "$backend_port" "$backend_output_file"
persist_artifact "$backend_output_file" "backend-direct-iperf.txt"

pod_sh "$NS_NAMESPACE" "$client_pod" "$CLIENT_CONTAINER" "
  ip route replace '${virtual_ip}/32' dev '${CLIENT_IFACE}'
  ip neigh replace '${virtual_ip}' lladdr '${server_mac}' nud permanent dev '${CLIENT_IFACE}'
"

client_before="${tmpdir}/client-before.env"
nat_ingress_before="${tmpdir}/nat-ingress-before.env"
nat_egress_before="${tmpdir}/nat-egress-before.env"
server_before="${tmpdir}/server-before.env"
client_ofport_before="${tmpdir}/client-ofport-before.env"
nat_ingress_ofport_before="${tmpdir}/nat-ingress-ofport-before.env"
nat_egress_ofport_before="${tmpdir}/nat-egress-ofport-before.env"
server_ofport_before="${tmpdir}/server-ofport-before.env"
nat_ingress_tc_before="${tmpdir}/nat-ingress-tc-before.txt"
nat_egress_tc_before="${tmpdir}/nat-egress-tc-before.txt"

save_snapshot "$client_before" capture_netdev_stats "$NS_NAMESPACE" "$client_pod" "$CLIENT_CONTAINER" "$client_iface"
save_snapshot "$nat_ingress_before" capture_netdev_stats "$NS_NAMESPACE" "$nat_pod" "$NAT_CONTAINER" "$nat_ingress_leg"
save_snapshot "$nat_egress_before" capture_netdev_stats "$NS_NAMESPACE" "$nat_pod" "$NAT_CONTAINER" "$nat_egress_leg"
save_snapshot "$server_before" capture_netdev_stats "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER" "$server_iface"
save_snapshot "$client_ofport_before" capture_ofport_stats "$forwarder_pod" "$client_ofport"
save_snapshot "$nat_ingress_ofport_before" capture_ofport_stats "$forwarder_pod" "$nat_ingress_ofport"
save_snapshot "$nat_egress_ofport_before" capture_ofport_stats "$forwarder_pod" "$nat_egress_ofport"
save_snapshot "$server_ofport_before" capture_ofport_stats "$forwarder_pod" "$server_ofport"
capture_tc_filter_stats "$NS_NAMESPACE" "$nat_pod" "$NAT_CONTAINER" "$nat_ingress_leg" "$nat_ingress_tc_before"
capture_tc_filter_stats "$NS_NAMESPACE" "$nat_pod" "$NAT_CONTAINER" "$nat_egress_leg" "$nat_egress_tc_before"

virtual_output_file="${tmpdir}/virtual-iperf.txt"
client_ss_file="${tmpdir}/client-ss.txt"
server_ss_file="${tmpdir}/server-ss.txt"

: >"${client_ss_file}"
: >"${server_ss_file}"

start_iperf_request_async "$virtual_ip" "$virtual_port" "$virtual_output_file"

client_ss_pattern="${virtual_ip}:${virtual_port}"
server_ss_pattern="${backend_ip}:${backend_port}"

if [[ "$EXPECT_RESULT" == "success" ]]; then
  wait_for_ss_match "$NS_NAMESPACE" "$client_pod" "$CLIENT_CONTAINER" "$client_ss_pattern" "$PROOF_CONN_WAIT_SECONDS" "$client_ss_file" \
    || die "client socket snapshot did not show ${client_ss_pattern}"
  wait_for_ss_match "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER" "$server_ss_pattern" "$PROOF_CONN_WAIT_SECONDS" "$server_ss_file" \
    || die "server socket snapshot did not show ${server_ss_pattern}"
fi

wait "$request_pid" || true
request_pid=""

client_after="${tmpdir}/client-after.env"
nat_ingress_after="${tmpdir}/nat-ingress-after.env"
nat_egress_after="${tmpdir}/nat-egress-after.env"
server_after="${tmpdir}/server-after.env"
client_ofport_after="${tmpdir}/client-ofport-after.env"
nat_ingress_ofport_after="${tmpdir}/nat-ingress-ofport-after.env"
nat_egress_ofport_after="${tmpdir}/nat-egress-ofport-after.env"
server_ofport_after="${tmpdir}/server-ofport-after.env"
nat_ingress_tc_after="${tmpdir}/nat-ingress-tc-after.txt"
nat_egress_tc_after="${tmpdir}/nat-egress-tc-after.txt"

save_snapshot "$client_after" capture_netdev_stats "$NS_NAMESPACE" "$client_pod" "$CLIENT_CONTAINER" "$client_iface"
save_snapshot "$nat_ingress_after" capture_netdev_stats "$NS_NAMESPACE" "$nat_pod" "$NAT_CONTAINER" "$nat_ingress_leg"
save_snapshot "$nat_egress_after" capture_netdev_stats "$NS_NAMESPACE" "$nat_pod" "$NAT_CONTAINER" "$nat_egress_leg"
save_snapshot "$server_after" capture_netdev_stats "$NS_NAMESPACE" "$server_pod" "$SERVER_CONTAINER" "$server_iface"
save_snapshot "$client_ofport_after" capture_ofport_stats "$forwarder_pod" "$client_ofport"
save_snapshot "$nat_ingress_ofport_after" capture_ofport_stats "$forwarder_pod" "$nat_ingress_ofport"
save_snapshot "$nat_egress_ofport_after" capture_ofport_stats "$forwarder_pod" "$nat_egress_ofport"
save_snapshot "$server_ofport_after" capture_ofport_stats "$forwarder_pod" "$server_ofport"
capture_tc_filter_stats "$NS_NAMESPACE" "$nat_pod" "$NAT_CONTAINER" "$nat_ingress_leg" "$nat_ingress_tc_after"
capture_tc_filter_stats "$NS_NAMESPACE" "$nat_pod" "$NAT_CONTAINER" "$nat_egress_leg" "$nat_egress_tc_after"

persist_artifact "$client_before" "client-before.env"
persist_artifact "$nat_ingress_before" "nat-ingress-before.env"
persist_artifact "$nat_egress_before" "nat-egress-before.env"
persist_artifact "$server_before" "server-before.env"
persist_artifact "$client_after" "client-after.env"
persist_artifact "$nat_ingress_after" "nat-ingress-after.env"
persist_artifact "$nat_egress_after" "nat-egress-after.env"
persist_artifact "$server_after" "server-after.env"
persist_artifact "$client_ofport_before" "client-ofport-before.env"
persist_artifact "$nat_ingress_ofport_before" "nat-ingress-ofport-before.env"
persist_artifact "$nat_egress_ofport_before" "nat-egress-ofport-before.env"
persist_artifact "$server_ofport_before" "server-ofport-before.env"
persist_artifact "$client_ofport_after" "client-ofport-after.env"
persist_artifact "$nat_ingress_ofport_after" "nat-ingress-ofport-after.env"
persist_artifact "$nat_egress_ofport_after" "nat-egress-ofport-after.env"
persist_artifact "$server_ofport_after" "server-ofport-after.env"
persist_artifact "$nat_ingress_tc_before" "nat-ingress-tc-before.txt"
persist_artifact "$nat_egress_tc_before" "nat-egress-tc-before.txt"
persist_artifact "$nat_ingress_tc_after" "nat-ingress-tc-after.txt"
persist_artifact "$nat_egress_tc_after" "nat-egress-tc-after.txt"
persist_artifact "$client_ss_file" "client-ss.txt"
persist_artifact "$server_ss_file" "server-ss.txt"
persist_artifact "$virtual_output_file" "virtual-iperf.txt"

client_tx_bytes_delta="$(delta_from_files "$client_before" "$client_after" "tx_bytes")"
nat_ingress_rx_bytes_delta="$(delta_from_files "$nat_ingress_before" "$nat_ingress_after" "rx_bytes")"
nat_egress_tx_bytes_delta="$(delta_from_files "$nat_egress_before" "$nat_egress_after" "tx_bytes")"
server_rx_bytes_delta="$(delta_from_files "$server_before" "$server_after" "rx_bytes")"
client_ofport_rx_bytes_delta="$(delta_from_files "$client_ofport_before" "$client_ofport_after" "rx_bytes")"
nat_ingress_ofport_tx_bytes_delta="$(delta_from_files "$nat_ingress_ofport_before" "$nat_ingress_ofport_after" "tx_bytes")"
nat_egress_ofport_rx_bytes_delta="$(delta_from_files "$nat_egress_ofport_before" "$nat_egress_ofport_after" "rx_bytes")"
server_ofport_tx_bytes_delta="$(delta_from_files "$server_ofport_before" "$server_ofport_after" "tx_bytes")"

forward_tcp_hits_before="$(tc_pref_packets_from_file "$nat_ingress_tc_before" "$forward_tcp_pref")"
forward_tcp_hits_after="$(tc_pref_packets_from_file "$nat_ingress_tc_after" "$forward_tcp_pref")"
reverse_tcp_hits_before="$(tc_pref_packets_from_file "$nat_egress_tc_before" "$reverse_tcp_pref")"
reverse_tcp_hits_after="$(tc_pref_packets_from_file "$nat_egress_tc_after" "$reverse_tcp_pref")"
forward_tcp_hits_delta=$((forward_tcp_hits_after - forward_tcp_hits_before))
reverse_tcp_hits_delta=$((reverse_tcp_hits_after - reverse_tcp_hits_before))

if ((client_tx_bytes_delta <= 0)); then
  die "client transmitted no payload during verification"
fi

if [[ "$EXPECT_RESULT" == "success" ]]; then
  [[ "$nat_mode" == "static_port_map" ]] || die "expected nat mode static_port_map, got ${nat_mode:-<empty>}"
  ((nat_ingress_rx_bytes_delta > 0)) || die "NAT ingress counters did not move during success verification"
  ((nat_egress_tx_bytes_delta > 0)) || die "NAT egress counters did not move during success verification"
  ((server_rx_bytes_delta > 0)) || die "server received no traffic during success verification"
  ((client_ofport_rx_bytes_delta > 0)) || die "forwarder client ofport counters did not move"
  ((nat_ingress_ofport_tx_bytes_delta > 0)) || die "forwarder NAT ingress ofport counters did not move"
  ((nat_egress_ofport_rx_bytes_delta > 0)) || die "forwarder NAT egress ofport counters did not move"
  ((server_ofport_tx_bytes_delta > 0)) || die "forwarder server ofport counters did not move"
  ((forward_tcp_hits_delta > 0)) || die "forward TCP NAT rule did not record any packet hits"
  ((reverse_tcp_hits_delta > 0)) || die "reverse TCP NAT rule did not record any packet hits"
  grep -Fq "connected to ${virtual_ip} port ${virtual_port}" "$virtual_output_file" || die "iperf proof output does not mention virtual tuple ${virtual_ip}:${virtual_port}"
else
  if grep -q "pref ${forward_tcp_pref}" "$nat_ingress_tc_after" || grep -q "pref ${reverse_tcp_pref}" "$nat_egress_tc_after"; then
    die "NAT rewrite filters are still present under fail/empty profile"
  fi
  grep -Fq "connected to ${virtual_ip} port ${virtual_port}" "$virtual_output_file" && die "iperf proof output unexpectedly mentions virtual tuple ${virtual_ip}:${virtual_port}"
fi

tc_dump_file="${tmpdir}/tc-summary.txt"
{
  echo "== NAT tc filters with counters =="
  echo "[${nat_ingress_leg}]"
  cat "${nat_ingress_tc_after}"
  echo
  echo "[${nat_egress_leg}]"
  cat "${nat_egress_tc_after}"
} >"${tc_dump_file}"
persist_artifact "${tc_dump_file}" "tc-summary.txt"

if [[ "$EXPECT_RESULT" == "success" ]]; then
  grep -q "${virtual_ip}" "${tc_dump_file}" || die "tc filter evidence does not mention virtual IP ${virtual_ip}"
  grep -q "dst_port ${virtual_port}" "${tc_dump_file}" || die "tc filter evidence does not mention virtual port ${virtual_port}"
  grep -q "${backend_ip}" "${tc_dump_file}" || die "tc filter evidence does not mention backend IP ${backend_ip}"
  grep -q "port ${backend_port}" "${tc_dump_file}" || die "tc filter evidence does not mention backend port ${backend_port}"
fi

echo "== Context =="
echo "Namespace           : ${NS_NAMESPACE}"
echo "Expectation         : ${EXPECT_RESULT}"
echo "Node                : ${client_node}"
echo "Forwarder pod       : ${forwarder_pod}"
echo "Client pod          : ${client_pod}"
echo "NAT pod             : ${nat_pod}"
echo "Server pod          : ${server_pod}"
echo "NAT bridge          : ${nat_bridge}"
echo "Virtual tuple       : ${virtual_ip}:${virtual_port}"
echo "Backend tuple       : ${backend_ip}:${backend_port}"
echo "Artifact dir        : ${ARTIFACT_DIR:-<disabled>}"

echo
echo "== Result =="
echo "direct backend and virtual tuple verification completed"
