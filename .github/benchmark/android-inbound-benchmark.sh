#!/system/bin/sh

set -eu

ROOT=${BENCHMARK_ROOT:-/data/local/tmp/sing-box-inbound-benchmark}
DURATION=${BENCHMARK_DURATION:-5s}
WARMUP=${BENCHMARK_WARMUP:-3s}
CONCURRENCY=${BENCHMARK_CONCURRENCY:-8}
REPETITIONS=${BENCHMARK_REPETITIONS:-5}
TCP_PAYLOAD_SIZE=${BENCHMARK_TCP_PAYLOAD_SIZE:-32768}
UDP_PAYLOAD_SIZE=${BENCHMARK_UDP_PAYLOAD_SIZE:-1200}
SERVER_PORT_BASE=20000
LOCAL_VALIDATION_PORT=31001
LOCAL_VALIDATION_DSCP=1
APP_ADDRESS=10.89.0.2
ROUTER_APP_ADDRESS=10.89.0.1
ROUTER_SERVER_ADDRESS=10.89.1.1
SERVER_ADDRESS=10.89.1.2

usage() {
  echo "usage: $0 setup|suite|run VARIANT REPETITION|validate VARIANT|cleanup" >&2
  exit 2
}

pid_value() {
  local name=$1
  cat "$ROOT/$name.pid"
}

write_configs() {
  cat > "$ROOT/config/redirect.json" <<'EOF'
{"log":{"level":"error","timestamp":true},"inbounds":[{"type":"redirect","tag":"benchmark-in","listen":"0.0.0.0","listen_port":15001}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default_interface":"sbr1","final":"direct"}}
EOF
  cat > "$ROOT/config/tproxy.json" <<'EOF'
{"log":{"level":"error","timestamp":true},"inbounds":[{"type":"tproxy","tag":"benchmark-in","listen":"0.0.0.0","listen_port":15002,"network":["tcp","udp"]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default_interface":"sbr1","final":"direct"}}
EOF
  cat > "$ROOT/config/ebpf-local.json" <<'EOF'
{"log":{"level":"error","timestamp":true},"inbounds":[{"type":"ebpf","tag":"benchmark-in","mode":"local","network":["tcp","udp"],"local":{"dns_mode":"off","include_uid":[2000],"ipv6":false,"bypass_private_address":false}}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default_interface":"sba0","final":"direct"}}
EOF
  cat > "$ROOT/config/ebpf-shared.json" <<'EOF'
{"log":{"level":"error","timestamp":true},"inbounds":[{"type":"ebpf","tag":"benchmark-in","mode":"shared","network":["tcp","udp"],"shared":{"dns_mode":"off","interface":["sbr0"],"ipv6":false,"bypass_private_address":false}}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default_interface":"sbr1","final":"direct"}}
EOF
  cat > "$ROOT/config/tun-mixed.json" <<'EOF'
{"log":{"level":"error","timestamp":true},"inbounds":[{"type":"tun","tag":"benchmark-in","interface_name":"sb-benchmark","address":["172.19.0.1/30"],"mtu":1500,"stack":"mixed","auto_route":true,"auto_redirect":false,"include_uid":[2000],"route_address":["10.89.1.2/32"]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default_interface":"sba0","final":"direct"}}
EOF
  cat > "$ROOT/config/tun-mixed-auto-redirect.json" <<'EOF'
{"log":{"level":"error","timestamp":true},"inbounds":[{"type":"tun","tag":"benchmark-in","interface_name":"sb-benchmark","address":["172.19.0.1/30"],"mtu":1500,"stack":"mixed","auto_route":true,"auto_redirect":true,"include_uid":[2000],"route_address":["10.89.1.2/32"]}],"outbounds":[{"type":"direct","tag":"direct"}],"route":{"default_interface":"sba0","final":"direct"}}
EOF
}

setup_namespace() {
  local namespace=$1
  unshare -n sh -c 'sleep 86400' > /dev/null 2>&1 &
  echo $! > "$ROOT/$namespace.pid"
}

app_net() {
  ip link set lo up
  ip address add "$APP_ADDRESS/24" dev sba0
  ip link set sba0 up
  ip route add default via "$ROUTER_APP_ADDRESS"
  ip rule add priority 10000 fwmark 0x0/0xffff table main
}

router_net() {
  ip link set lo up
  ip address add "$ROUTER_APP_ADDRESS/24" dev sbr0
  ip address add "$ROUTER_SERVER_ADDRESS/24" dev sbr1
  ip link set sbr0 up
  ip link set sbr1 up
  echo 1 > /proc/sys/net/ipv4/ip_forward
  iptables -P FORWARD ACCEPT
}

server_net() {
  ip link set lo up
  ip address add "$SERVER_ADDRESS/24" dev sbs0
  ip link set sbs0 up
  ip route add "$APP_ADDRESS/32" via "$ROUTER_SERVER_ADDRESS"
}

server_run() {
  local server_port=$1
  exec "$ROOT/interception-bench" -mode server -listen "$SERVER_ADDRESS:$server_port"
}

start_server() {
  local server_port=$1
  local repetition=$2
  local server
  local count
  server=$(pid_value server)
  nsenter -t "$server" -n sh "$0" internal-server-run "$server_port" \
    > "$ROOT/logs/server-$repetition.log" 2>&1 &
  echo $! > "$ROOT/server-benchmark.pid"
  count=0
  while [ "$count" -lt 30 ]; do
    if ! kill -0 "$(pid_value server-benchmark)" 2>/dev/null; then
      return 1
    fi
    if nsenter -t "$server" -n sh "$0" internal-server-ready "$server_port"; then
      return 0
    fi
    sleep 0.1
    count=$((count + 1))
  done
  return 1
}

server_ready() {
  local server_port=$1
  ss -H -ltn "sport = :$server_port" | grep -q .
}

stop_server() {
  if [ ! -f "$ROOT/server-benchmark.pid" ]; then
    return
  fi
  local pid
  local count
  pid=$(pid_value server-benchmark)
  kill "$pid" 2>/dev/null || true
  count=0
  while kill -0 "$pid" 2>/dev/null && [ "$count" -lt 20 ]; do
    sleep 0.05
    count=$((count + 1))
  done
  kill -9 "$pid" 2>/dev/null || true
  rm -f "$ROOT/server-benchmark.pid"
}

record_environment() {
  {
    echo "date=$(date -Iseconds 2>/dev/null || date)"
    echo "duration=$DURATION"
    echo "warmup=$WARMUP"
    echo "repetitions=$REPETITIONS"
    echo "concurrency=$CONCURRENCY"
    echo "tcp_payload_size=$TCP_PAYLOAD_SIZE"
    echo "udp_payload_size=$UDP_PAYLOAD_SIZE"
    echo "server_port_base=$SERVER_PORT_BASE"
    echo "variants=direct,ebpf-local,ebpf-shared,redirect,tproxy,tun-mixed,tun-mixed-auto-redirect"
    echo "scenarios=tcp-short,tcp-upload,tcp-download,udp-pps,udp-unconnected-pps,udp-churn"
    echo "topology=android-three-network-namespaces"
    echo "sing_box=$($ROOT/sing-box version 2>&1 | head -n 1)"
    uname -a
  } > "$ROOT/environment/run.txt"
}

setup() {
  local app
  local router
  local server
  [ "$(id -u)" = 0 ] || { echo "root is required" >&2; exit 1; }
  [ -x "$ROOT/sing-box" ] || { echo "missing $ROOT/sing-box" >&2; exit 1; }
  [ -x "$ROOT/interception-bench" ] || { echo "missing $ROOT/interception-bench" >&2; exit 1; }
  case "$REPETITIONS" in
    ''|*[!0-9]*) echo "repetitions must be between 1 and 1000" >&2; exit 2 ;;
  esac
  [ "$REPETITIONS" -ge 1 ] && [ "$REPETITIONS" -le 1000 ] || {
    echo "repetitions must be between 1 and 1000" >&2
    exit 2
  }
  mkdir -p "$ROOT/config" "$ROOT/environment" "$ROOT/logs" "$ROOT/raw" "$ROOT/validation"
  for variant in direct ebpf-local ebpf-shared redirect tproxy tun-mixed tun-mixed-auto-redirect; do
    mkdir -p "$ROOT/raw/$variant"
  done
  write_configs
  setup_namespace app
  setup_namespace router
  setup_namespace server
  sleep 1
  app=$(pid_value app)
  router=$(pid_value router)
  server=$(pid_value server)
  ip link add sba0 type veth peer name sbr0
  ip link set sba0 netns "$app"
  ip link set sbr0 netns "$router"
  ip link add sbr1 type veth peer name sbs0
  ip link set sbr1 netns "$router"
  ip link set sbs0 netns "$server"
  nsenter -t "$app" -n sh "$0" internal-app-net
  nsenter -t "$router" -n sh "$0" internal-router-net
  nsenter -t "$server" -n sh "$0" internal-server-net
  record_environment
  getprop > "$ROOT/environment/getprop.txt"
  echo "benchmark topology ready at $ROOT"
}

router_rules() {
  local action=$1
  local server_port=$2
  iptables -t nat -F
  iptables -t mangle -F
  iptables -F FORWARD
  iptables -P FORWARD ACCEPT
  ip rule del fwmark 1 table 100 2>/dev/null || true
  ip route flush table 100 2>/dev/null || true
  case "$action" in
    redirect)
      iptables -t nat -A PREROUTING -s "$APP_ADDRESS" -d "$SERVER_ADDRESS" \
        -p tcp --dport "$server_port" -j REDIRECT --to-ports 15001
      ;;
    tproxy)
      ip rule add fwmark 1 table 100
      ip route add local 0.0.0.0/0 dev lo table 100
      iptables -t mangle -A PREROUTING -s "$APP_ADDRESS" -d "$SERVER_ADDRESS" \
        -p tcp --dport "$server_port" -j TPROXY --on-ip 0.0.0.0 \
        --on-port 15002 --tproxy-mark 0x1/0x1
      iptables -t mangle -A PREROUTING -s "$APP_ADDRESS" -d "$SERVER_ADDRESS" \
        -p udp --dport "$server_port" -j TPROXY --on-ip 0.0.0.0 \
        --on-port 15002 --tproxy-mark 0x1/0x1
      ;;
  esac
}

router_block() {
  local action=$1
  local server_port=$2
  local network
  for network in tcp udp; do
    if [ "$action" = add ]; then
      iptables -A FORWARD -s "$APP_ADDRESS" -d "$SERVER_ADDRESS" \
        -p "$network" --dport "$server_port" -j REJECT
    else
      iptables -D FORWARD -s "$APP_ADDRESS" -d "$SERVER_ADDRESS" \
        -p "$network" --dport "$server_port" -j REJECT 2>/dev/null || true
    fi
  done
}

app_dscp() {
  local action=$1
  local server_port=$2
  local network
  for network in tcp udp; do
    if [ "$action" = add ]; then
      iptables -t mangle -A OUTPUT -m owner --uid-owner 2000 \
        -d "$SERVER_ADDRESS" -p "$network" --dport "$server_port" \
        -j DSCP --set-dscp "$LOCAL_VALIDATION_DSCP"
    else
      iptables -t mangle -D OUTPUT -m owner --uid-owner 2000 \
        -d "$SERVER_ADDRESS" -p "$network" --dport "$server_port" \
        -j DSCP --set-dscp "$LOCAL_VALIDATION_DSCP" \
        2>/dev/null || true
    fi
  done
}

router_dscp_block() {
  local action=$1
  local server_port=$2
  local network
  for network in tcp udp; do
    if [ "$action" = add ]; then
      iptables -A FORWARD -d "$SERVER_ADDRESS" -p "$network" --dport "$server_port" \
        -m dscp --dscp "$LOCAL_VALIDATION_DSCP" -j REJECT
    else
      iptables -D FORWARD -d "$SERVER_ADDRESS" -p "$network" --dport "$server_port" \
        -m dscp --dscp "$LOCAL_VALIDATION_DSCP" -j REJECT \
        2>/dev/null || true
    fi
  done
}

start_box() {
  local variant=$1
  local repetition=$2
  exec "$ROOT/sing-box" run -c "$ROOT/config/$variant.json" \
    > "$ROOT/logs/$variant-$repetition.log" 2>&1
}

client_run() {
  local variant=$1
  local server_port=$2
  local scenarios=${3:-all}
  [ "$variant" = redirect ] && scenarios=tcp-short,tcp-upload,tcp-download
  exec su 2000 -c "$ROOT/interception-bench -mode client -target $SERVER_ADDRESS:$server_port -scenario $scenarios -duration $DURATION -warmup $WARMUP -concurrency $CONCURRENCY -tcp-payload-size $TCP_PAYLOAD_SIZE -udp-payload-size $UDP_PAYLOAD_SIZE"
}

stop_box() {
  if [ -f "$ROOT/box.pid" ]; then
    local pid
    pid=$(cat "$ROOT/box.pid")
    kill "$pid" 2>/dev/null || true
    sleep 1
    kill -9 "$pid" 2>/dev/null || true
    rm -f "$ROOT/box.pid"
  fi
}

valid_report() {
  local report=$1
  [ -s "$report" ] || return 1
  ! grep -Eq '"errors":[[:space:]]*[1-9]|"rate":[[:space:]]*0([.,}]|$)' "$report"
}

expect_blocked_report() {
  local report=$1
  local scenario=$2
  [ -s "$report" ] || return 1
  grep -q "\"scenario\": \"$scenario\"" "$report" || return 1
  ! valid_report "$report"
}

validate_local_direct_block() {
  local app=$1
  local server_port=$2
  local result=0
  local scenario
  local blocked_report
  for scenario in tcp-short udp-pps; do
    blocked_report="$ROOT/validation/ebpf-local-direct-$scenario.json"
    if BENCHMARK_DURATION=250ms BENCHMARK_WARMUP=0s BENCHMARK_CONCURRENCY=1 \
      nsenter -t "$app" -n sh "$0" internal-client-run ebpf-local "$server_port" "$scenario" \
      > "$blocked_report" 2> "$blocked_report.stderr"; then
      :
    fi
    if ! expect_blocked_report "$blocked_report" "$scenario"; then
      result=1
    fi
  done
  return "$result"
}

validate_variant() {
  local variant=$1
  local app
  local router
  local validation_report="$ROOT/validation/$variant-interception.json"
  local server_port=$LOCAL_VALIDATION_PORT
  local result
  app=$(pid_value app)
  router=$(pid_value router)
  stop_box
  stop_server
  nsenter -t "$router" -n sh "$0" internal-router-rules "$variant" "$server_port"
  if ! start_server "$server_port" "$variant-validation"; then
    stop_server
    nsenter -t "$router" -n sh "$0" internal-router-rules reset "$server_port"
    return 1
  fi
  case "$variant" in
    ebpf-local)
      nsenter -t "$app" -n sh "$0" internal-app-dscp add "$server_port"
      nsenter -t "$router" -n sh "$0" internal-router-dscp-block add "$server_port"
      if ! validate_local_direct_block "$app" "$server_port"; then
        nsenter -t "$app" -n sh "$0" internal-app-dscp del "$server_port"
        nsenter -t "$router" -n sh "$0" internal-router-dscp-block del "$server_port"
        stop_server
        nsenter -t "$router" -n sh "$0" internal-router-rules reset "$server_port"
        return 1
      fi
      nsenter -t "$app" -n sh "$0" internal-start-box ebpf-local validation &
      echo $! > "$ROOT/box.pid"
      ;;
    ebpf-shared|redirect|tproxy)
      nsenter -t "$router" -n sh "$0" internal-start-box "$variant" validation &
      echo $! > "$ROOT/box.pid"
      ;;
    *) return 2 ;;
  esac
  sleep 3
  if ! kill -0 "$(cat "$ROOT/box.pid")" 2>/dev/null; then
    if [ "$variant" = ebpf-local ]; then
      nsenter -t "$app" -n sh "$0" internal-app-dscp del "$server_port"
      nsenter -t "$router" -n sh "$0" internal-router-dscp-block del "$server_port"
    fi
    stop_box
    stop_server
    nsenter -t "$router" -n sh "$0" internal-router-rules reset "$server_port"
    return 1
  fi
  if [ "$variant" != ebpf-local ]; then
    nsenter -t "$router" -n sh "$0" internal-router-block add "$server_port"
  fi
  if BENCHMARK_DURATION=1s BENCHMARK_WARMUP=0s BENCHMARK_CONCURRENCY=2 \
    nsenter -t "$app" -n sh "$0" internal-client-run "$variant" "$server_port" \
      tcp-short,udp-pps,udp-unconnected-pps,udp-churn \
    > "$validation_report" 2> "$validation_report.stderr"; then
    result=0
  else
    result=$?
  fi
  if [ "$variant" != ebpf-local ]; then
    nsenter -t "$router" -n sh "$0" internal-router-block del "$server_port"
  else
    nsenter -t "$app" -n sh "$0" internal-app-dscp del "$server_port"
    nsenter -t "$router" -n sh "$0" internal-router-dscp-block del "$server_port"
  fi
  stop_box
  stop_server
  nsenter -t "$router" -n sh "$0" internal-router-rules reset "$server_port"
  [ "$result" = 0 ] && valid_report "$validation_report" || return 1
}

variant_index() {
  case "$1" in
    direct) echo 1 ;;
    ebpf-local) echo 2 ;;
    ebpf-shared) echo 3 ;;
    redirect) echo 4 ;;
    tproxy) echo 5 ;;
    tun-mixed) echo 6 ;;
    tun-mixed-auto-redirect) echo 7 ;;
    *) return 1 ;;
  esac
}

server_port_for() {
  local variant=$1
  local repetition=$2
  local index
  case "$repetition" in
    ''|*[!0-9]*) return 1 ;;
  esac
  [ "$repetition" -ge 1 ] && [ "$repetition" -le 1000 ] || return 1
  index=$(variant_index "$variant") || return 1
  echo $((SERVER_PORT_BASE + repetition * 10 + index))
}

run_variant() {
  local variant=$1
  local repetition=$2
  local app
  local router
  local server_port
  local result
  local pid
  record_environment
  app=$(pid_value app)
  router=$(pid_value router)
  server_port=$(server_port_for "$variant" "$repetition") || {
    echo "invalid variant or repetition: $variant $repetition" >&2
    return 2
  }
  stop_box
  stop_server
  nsenter -t "$router" -n sh "$0" internal-router-rules "$variant" "$server_port"
  if ! start_server "$server_port" "$variant-$repetition"; then
    stop_server
    nsenter -t "$router" -n sh "$0" internal-router-rules reset "$server_port"
    return 1
  fi
  case "$variant" in
    direct) ;;
    ebpf-shared|redirect|tproxy)
      nsenter -t "$router" -n sh "$0" internal-start-box "$variant" "$repetition" &
      echo $! > "$ROOT/box.pid"
      ;;
    ebpf-local|tun-mixed|tun-mixed-auto-redirect)
      nsenter -t "$app" -n sh "$0" internal-start-box "$variant" "$repetition" &
      echo $! > "$ROOT/box.pid"
      ;;
    *) echo "unknown variant: $variant" >&2; exit 2 ;;
  esac
  if [ "$variant" != direct ]; then
    sleep 3
    if ! kill -0 "$(cat "$ROOT/box.pid")" 2>/dev/null; then
      cat "$ROOT/logs/$variant-$repetition.log" >&2
      stop_box
      stop_server
      nsenter -t "$router" -n sh "$0" internal-router-rules reset "$server_port"
      return 1
    fi
  fi
  if nsenter -t "$app" -n sh "$0" internal-client-run "$variant" "$server_port" \
    > "$ROOT/raw/$variant/$repetition.json" \
    2> "$ROOT/raw/$variant/$repetition.stderr"; then
    result=0
  else
    result=$?
  fi
  if [ "$variant" != direct ]; then
    pid=$(cat "$ROOT/box.pid")
    if [ -r "/proc/$pid/status" ]; then
      grep -E '^(VmPeak|VmHWM|VmRSS|Threads|voluntary_ctxt_switches|nonvoluntary_ctxt_switches):' \
        "/proc/$pid/status" > "$ROOT/raw/$variant/$repetition-process.txt" || true
    fi
  fi
  stop_box
  stop_server
  nsenter -t "$router" -n sh "$0" internal-router-rules reset "$server_port"
  [ "$result" = 0 ] && valid_report "$ROOT/raw/$variant/$repetition.json" || return 1
}

suite() {
  local repetition
  local order
  local variant
  local code
  record_environment
  : > "$ROOT/progress.log"
  : > "$ROOT/failures.tsv"
  repetition=1
  while [ "$repetition" -le "$REPETITIONS" ]; do
    case "$repetition" in
      1) order='direct ebpf-local ebpf-shared redirect tproxy tun-mixed tun-mixed-auto-redirect' ;;
      2) order='tproxy tun-mixed direct ebpf-shared tun-mixed-auto-redirect ebpf-local redirect' ;;
      3) order='tun-mixed-auto-redirect redirect ebpf-local direct tun-mixed ebpf-shared tproxy' ;;
      4) order='ebpf-shared ebpf-local tproxy tun-mixed-auto-redirect redirect direct tun-mixed' ;;
      *) order='tun-mixed direct tproxy ebpf-local redirect ebpf-shared tun-mixed-auto-redirect' ;;
    esac
    for variant in $order; do
      echo "$(date +%s) start $variant $repetition" >> "$ROOT/progress.log"
      if "$0" run "$variant" "$repetition"; then
        echo "$(date +%s) done $variant $repetition" >> "$ROOT/progress.log"
      else
        code=$?
        printf '%s\t%s\t%s\n' "$variant" "$repetition" "$code" >> "$ROOT/failures.tsv"
        echo "$(date +%s) fail $variant $repetition code=$code" >> "$ROOT/progress.log"
      fi
    done
    repetition=$((repetition + 1))
  done
  for variant in ebpf-local ebpf-shared redirect tproxy; do
    echo "$(date +%s) validate $variant" >> "$ROOT/progress.log"
    if validate_variant "$variant"; then
      echo "$(date +%s) validated $variant" >> "$ROOT/progress.log"
    else
      code=$?
      printf '%s\t%s\t%s\n' "$variant-interception-check" validation "$code" >> "$ROOT/failures.tsv"
      echo "$(date +%s) validation-failed $variant code=$code" >> "$ROOT/progress.log"
    fi
  done
  echo "$(date +%s) complete" >> "$ROOT/progress.log"
}

cleanup() {
  local name
  stop_box
  stop_server
  for name in app router server; do
    if [ -f "$ROOT/$name.pid" ]; then
      kill "$(cat "$ROOT/$name.pid")" 2>/dev/null || true
    fi
  done
  echo "benchmark topology removed; results remain in $ROOT"
}

command=${1:-}
case "$command" in
  setup) setup ;;
  suite) suite ;;
  run) [ $# = 3 ] || usage; run_variant "$2" "$3" ;;
  validate) [ $# = 2 ] || usage; validate_variant "$2" ;;
  cleanup) cleanup ;;
  internal-app-net) app_net ;;
  internal-router-net) router_net ;;
  internal-server-net) server_net ;;
  internal-server-run) server_run "$2" ;;
  internal-server-ready) server_ready "$2" ;;
  internal-router-rules) router_rules "$2" "$3" ;;
  internal-router-block) router_block "$2" "$3" ;;
  internal-app-dscp) app_dscp "$2" "$3" ;;
  internal-router-dscp-block) router_dscp_block "$2" "$3" ;;
  internal-start-box) start_box "$2" "$3" ;;
  internal-client-run) client_run "$2" "$3" "${4:-}" ;;
  *) usage ;;
esac
