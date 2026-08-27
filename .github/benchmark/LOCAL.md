# Local transparent inbound benchmarking

This guide covers repeatable local runs outside GitHub Actions. Standard Linux
can use the automated namespace topology. Rooted Android uses the same traffic
generator and an equivalent namespace topology created directly on the device.

## Standard Linux

### Requirements

Use a disposable test host or VM with root access and a kernel that
supports the selected inbound. Install Go, `iproute2`, `iptables`/`ip6tables`,
`nftables`, `jq`, `curl`, `ethtool`, `iputils-ping`, `procps`, and `util-linux`.
The automated script creates only network namespaces and links prefixed with
`sb-bench-`, then removes them on exit.

Build the sing-box binary and traffic generator. CGO and an
Android NDK are not required for this Linux harness:

```sh
mkdir -p build/inbound-benchmark
CGO_ENABLED=0 go build -trimpath -tags with_ebpf,with_gvisor \
  -o build/inbound-benchmark/sing-box ./cmd/sing-box
CGO_ENABLED=0 go build -trimpath \
  -o build/inbound-benchmark/interception-bench \
  ./cmd/internal/interception_bench
```

Run a short functional smoke test first:

```sh
sudo bash .github/benchmark/run-inbound-benchmark.sh \
  --sing-box "$PWD/build/inbound-benchmark/sing-box" \
  --benchmark "$PWD/build/inbound-benchmark/interception-bench" \
  --output "$PWD/build/inbound-benchmark/smoke-ipv4" \
  --family ipv4 \
  --duration 200ms \
  --warmup 50ms \
  --repetitions 1 \
  --concurrency 2 \
  --profile-seconds 0
```

Repeat with a new output directory and `--family ipv6`. A normal comparison
should use longer sampling and at least five randomized repetitions:

```sh
sudo bash .github/benchmark/run-inbound-benchmark.sh \
  --sing-box "$PWD/build/inbound-benchmark/sing-box" \
  --benchmark "$PWD/build/inbound-benchmark/interception-bench" \
  --output "$PWD/build/inbound-benchmark/results-ipv4" \
  --family ipv4 \
  --duration 30s \
  --warmup 5s \
  --repetitions 5 \
  --concurrency 16 \
  --tcp-payload-size 32768 \
  --udp-payload-size 1200 \
  --profile-seconds 15
python3 .github/benchmark/summarize.py \
  build/inbound-benchmark/results-ipv4
```

Limit an A/B run with `--variants` and `--scenarios`, for example:

```sh
--variants direct,ebpf-local,tun-mixed,tun-mixed-auto-redirect \
--scenarios tcp-short,udp-pps,udp-churn
```

Use `--ebpf-policy-prefixes 4096` in a separate run to measure a large
non-matching bypass policy. Never compare that result against an eBPF run with
zero prefixes without labeling the policy difference.

After an interrupted run, verify that no test namespaces remain:

```sh
ip netns list | grep '^sb-bench-' || true
```

### Measurement hygiene

Prefer a bare-metal host with a fixed performance governor and stable cooling.
Stop unrelated workloads, keep offloads unchanged across variants, and retain
the complete output directory. Monitor temperature and frequency separately;
discard a run that throttles. Do not run two benchmark jobs concurrently.

For short-connection pressure, increase `--concurrency` and select `tcp-short`.
For UDP state pressure, select `udp-churn` and test several concurrency levels.
For datagram behavior, run separate 64, 512, 1200, and 1400 byte experiments.
A 10-30 minute soak is useful for lifecycle stability, but should not be merged
with short steady-state throughput samples.

## Rooted Android

Android results must be collected on a physical device. The supplied harness
creates application, router, and server network namespaces on that device:

```text
application (10.89.0.2) -> router (10.89.0.1 / 10.89.1.1) -> server (10.89.1.2)
```

This is the same logical topology as the Linux and GitHub Actions harness. It
does not use Wi-Fi, mobile data, an external server, or `adb reverse`, so ADB
transport throughput and Android's main namespace policy routing do not affect
the data path. Absolute in-memory veth throughput is not a physical-network
claim; use the randomized same-device relative results to compare inbounds.
The Android harness covers the same TCP and UDP workloads as the Linux harness.
Redirect remains TCP-only by design. Shared eBPF is measured at the router-side
veth ingress, which represents a downstream device rather than local traffic.

### Build and deploy

Build a release sing-box binary for the device. `with_gvisor` is mandatory for
the `tun-mixed` variants and `with_ebpf` is mandatory for eBPF:

```sh
TAGS=with_gvisor,with_quic,with_dhcp,with_utls,with_clash_api,with_ebpf,badlinkname,tfogo_checklinkname0 \
CGO_ENABLED=1 \
CC="${ANDROID_NDK_HOME}/toolchains/llvm/prebuilt/linux-x86_64/bin/aarch64-linux-android35-clang" \
GOARCH=arm64 GOOS=android make build
```

The traffic generator is pure Go:

```sh
GOOS=android GOARCH=arm64 CGO_ENABLED=0 go build -trimpath \
  -o build/inbound-benchmark/interception-bench-android-arm64 \
  ./cmd/internal/interception_bench
```

Verify that ADB shell is root and that the required kernel and Android tools are
available. The script uses PID-backed namespaces because Android Toybox does
not provide the same named-netns behavior as util-linux:

```sh
adb shell 'id'
adb shell 'for command in ip iptables nsenter su unshare; do command -v $command; done'
```

Stop the installed sing-box service before the benchmark. The exact service
command is installation-specific; for the KernelSU layout used during
development it is:

```sh
adb shell /data/adb/ksu/bin/box stop
```

Deploy the two binaries and the harness into its dedicated temporary directory:

```sh
BENCHMARK_ROOT=/data/local/tmp/sing-box-inbound-benchmark
adb shell "mkdir -p $BENCHMARK_ROOT"
adb push build/sing-box "$BENCHMARK_ROOT/sing-box"
adb push build/inbound-benchmark/interception-bench-android-arm64 \
  "$BENCHMARK_ROOT/interception-bench"
adb push .github/benchmark/android-inbound-benchmark.sh \
  "$BENCHMARK_ROOT/android-inbound-benchmark.sh"
adb shell "chmod 0755 $BENCHMARK_ROOT/sing-box \
  $BENCHMARK_ROOT/interception-bench \
  $BENCHMARK_ROOT/android-inbound-benchmark.sh"
```

### Run the comparison

Create the topology, then run five interleaved repetitions. Defaults are 5
seconds measurement, 3 seconds warm-up, concurrency 8, 32768-byte TCP frames,
and 1200-byte UDP datagrams. The suite covers direct, local and shared eBPF,
Redirect, TProxy, mixed-stack TUN, and mixed-stack TUN with auto redirect. All
variants except Redirect run TCP short/upload/download plus connected,
unconnected, and churn UDP workloads:

```sh
adb shell "$BENCHMARK_ROOT/android-inbound-benchmark.sh setup"
adb shell "$BENCHMARK_ROOT/android-inbound-benchmark.sh suite"
```

Every performance run uses a distinct server port, preventing TCP `TIME_WAIT`
state from exhausting the repeated short-connection test. After the performance
rounds, the suite performs direct-leak checks. For local eBPF it assigns a
validation-only DSCP value to the benchmark UID's original TCP and UDP traffic,
rejects that value at router
forwarding, and first verifies that both direct paths fail without sing-box.
Intercepted traffic passes because sing-box creates an untagged replacement
connection. Shared eBPF, Redirect, and TProxy reject ordinary app-to-server
forwarding. Failed validation is written to `failures.tsv` and excludes that
variant from the summary.

Override sampling parameters through environment variables when needed:

```sh
adb shell "BENCHMARK_DURATION=15s BENCHMARK_WARMUP=3s \
  BENCHMARK_CONCURRENCY=16 BENCHMARK_REPETITIONS=5 \
  BENCHMARK_UDP_PAYLOAD_SIZE=1200 \
  $BENCHMARK_ROOT/android-inbound-benchmark.sh suite"
```

Follow progress from another terminal. A failure does not stop later variants:

```sh
adb shell "tail -f $BENCHMARK_ROOT/progress.log"
adb shell "cat $BENCHMARK_ROOT/failures.tsv"
```

Run or repeat one variant without rerunning the matrix:

```sh
adb shell "$BENCHMARK_ROOT/android-inbound-benchmark.sh run ebpf-local 6"
```

All application workloads run through Android `su 2000`. Local eBPF selects UID
2000 at TC egress, while sing-box runs as root and its replacement connections
therefore bypass the local UID policy.

Android Toybox `nsenter` also continues parsing command options in cases where
util-linux stops. The harness always enters a namespace through this script and
only then starts binaries, avoiding errors such as `Unknown option 'mode'`.

### Collect and summarize

Pull the complete directory before cleanup and run the same summarizer used by
GitHub Actions:

```sh
RESULT=build/inbound-benchmark/android-$(date +%Y%m%d-%H%M%S)
adb pull "$BENCHMARK_ROOT" "$RESULT"
python3 .github/benchmark/summarize.py "$RESULT" > "$RESULT/summary.md"
sed -n '1,120p' "$RESULT/summary.md"
(cd "$(dirname "$RESULT")" && zip -qr "$(basename "$RESULT").zip" "$(basename "$RESULT")")
```

The summarizer atomically rejects a report when any scenario has errors, a zero
rate, or an abnormal measurement duration. It also rejects a whole variant when
its interception validation fails. Repeat the experiment when the number of
valid reports is below the requested repetition count or thermal throttling
differs materially between variants. The suite interleaves variant order between
repetitions to reduce systematic temperature and background-load bias.

The Android application namespace installs the same masked main-table policy
rule used by Android's default-interface discovery, so the veth default route is
visible to the eBPF interface monitor. The generated `route.default_interface`
still selects the benchmark outbound interface; it does not override interface
discovery. For additional diagnosis, an eBPF run can temporarily use `info` log
level. A direct-like result with failed leak validation is not an eBPF
measurement.

### Cleanup

Remove the namespace processes after pulling results, then restart
the installed service:

```sh
adb shell "$BENCHMARK_ROOT/android-inbound-benchmark.sh cleanup"
adb shell /data/adb/ksu/bin/box start
```

`cleanup` intentionally leaves `$BENCHMARK_ROOT` and its evidence intact. After
confirming the pull, that exact temporary directory may be removed manually.

The namespace shared-eBPF result measures its forwarding data plane and is
comparable with the automated Linux topology. A real hotspot validation still
requires a second downstream device because Android tethering, OEM offloads,
and the physical downstream interface are outside this synthetic topology.

### Android evidence to retain

For every run, keep:

- sing-box commit, build tags, config, complete debug log, and raw JSON;
- `uname -a`, relevant `getprop` output, device model, and Android security patch;
- `id`, namespace addresses, routes, rules, and firewall state;
- `/proc/PID/status`, thermal and battery state before and after the run;
- the eBPF Debug startup summary and pprof captures from
  `experimental.debug.listen` when profiling is enabled.

Keep pprof collection in a separate profiling phase because sampling adds
observation overhead and should not be compared with steady-state throughput.
