# Transparent inbound benchmark

This benchmark compares transparent interception paths with one traffic
generator, one isolated topology, and one direct endpoint. It is intended for
regression testing and engineering measurements. It is not a universal ranking:
kernel version, CPU frequency, offloads, routing rules, and background traffic
can change the result.

See [LOCAL.md](LOCAL.md) for standard Linux and rooted Android procedures. The
rooted Android TCP and UDP matrix uses
[`android-inbound-benchmark.sh`](android-inbound-benchmark.sh) to reproduce the
same three-namespace topology entirely on the device.

## Compared paths

| Variant | Interception setup | Protocols |
|---|---|---|
| `direct` | No sing-box process or interception | TCP and UDP |
| `ebpf-local` | TC egress on the application's default interface | TCP and UDP |
| `ebpf-shared` | TC ingress on the downstream router interface | TCP and UDP |
| `redirect` | Redirect listener and a destination-scoped NAT rule | TCP only |
| `tproxy` | TProxy listener, mark, policy route, and destination-scoped rules | TCP and UDP |
| `tun-mixed` | `stack: mixed`, `auto_route: true`, `auto_redirect: false` | TCP and UDP |
| `tun-mixed-auto-redirect` | `stack: mixed`, `auto_route: true`, `auto_redirect: true` | TCP and UDP |

The two TUN variants deliberately differ only in `auto_redirect`. The benchmark
does not expose separate system or gVisor stack variants. Redirect UDP results
are omitted instead of substituting a different implementation.

## Workloads

| Scenario | Reported rate | Main pressure |
|---|---|---|
| `tcp-short` | Completed request/response connections per second | Setup, interception, dispatch, and cleanup |
| `tcp-upload` | Server-confirmed bit/s | Persistent client-to-server throughput |
| `tcp-download` | Client-received bit/s | Persistent server-to-client throughput |
| `udp-pps` | Echoed datagrams/s from connected sockets | Connected UDP state and round trips |
| `udp-unconnected-pps` | Echoed datagrams/s from unconnected sockets | Per-destination session and reply-socket lookup |
| `udp-churn` | One echoed datagram per newly created socket | Assignment publication, reply-socket lifecycle, and map pressure |

TCP upload and UDP datagram sizes are independent. The defaults are 32 KiB and
1200 bytes respectively. Long uploads use framed data and server confirmation,
so bytes accepted only by a local socket buffer are not counted. UDP rates are
confirmed request/echo round trips, not unchecked send rates.

## Automated topology

The runner creates application, router, and server network namespaces connected
by veth pairs. The application client always runs as UID 65534 and sing-box runs
as root. Every transparent rule is limited to the benchmark server address and
port. The same topology supports IPv4 and IPv6; each run uses one family and
records it in `environment/run.txt`.

Each repetition randomizes variant order. Normal measurements use a release
binary. Correctness checks run separately:

- local eBPF gives the benchmark UID's original traffic a validation-only DSCP
  value and rejects any tagged packet that still reaches router forwarding,
  with negative controls proving
  that both TCP and UDP direct paths are blocked;
- shared eBPF, Redirect, and TProxy reject direct router forwarding after their
  expected interception point;
- both TUN variants must increment the dedicated TUN interface counters.

A failed interception check rejects every report for that variant. Individual
reports are also rejected atomically when any measurement has errors, a zero
rate, or a duration outside the accepted tolerance. This prevents a
misconfigured or partially failed transparent path from looking like a fast
direct connection.

## Run the workflow

Start the `Inbound benchmark` workflow manually. Its main inputs are:

- `family`: `ipv4` or `ipv6`;
- `variants`: a comma-separated subset of the table above;
- `scenarios`: `all` or a comma-separated workload list;
- `duration`, `warmup`, `repetitions`, and `concurrency`;
- `tcp_payload_size` and `udp_payload_size`;
- `ebpf_policy_prefixes`: non-matching CIDRs used to stress eBPF bypass lookup;
- `profile_seconds`: dedicated eBPF profiling duration, or zero to disable it.

The job uploads raw reports, sing-box logs and configurations, topology and
offload records, process snapshots, validation reports, and a median summary.
Do not combine results from different address families, payload sizes, kernels,
or policy-prefix counts.

GitHub-hosted runners are useful for functional coverage and large same-job
regressions. Use a fixed bare-metal runner carrying the `inbound-benchmark`
label for publishable performance comparisons. Run at least five repetitions
and repeat the whole experiment on different days.

## eBPF policy pressure

Set `ebpf_policy_prefixes` to create up to 32,768 non-adjacent host prefixes in
an inline `bypass_rule_set`. The prefixes never contain the benchmark server,
so traffic still traverses the interception path while every eBPF decision
performs a policy miss lookup. A value of zero measures the no-rule-set path.

Run zero and a representative large value as separate experiments. The option
applies only to eBPF inbounds; direct, Redirect, TProxy, and TUN remain reference
paths. The generated policy source is included in the artifact.

## eBPF profiling

When `profile_seconds` is non-zero, the workflow runs local and shared connected
UDP profiling separately for every selected eBPF mode. These runs:

- use `experimental.debug.listen` for CPU, allocation, and heap profiles;
- retain the one-time Debug startup summary and any rate-limited runtime errors.

Profile runs are stored under `profiles/local` and `profiles/shared`; they are
not loaded by the summary tool and must not be compared with steady-state
throughput because pprof sampling changes the workload.

## Interpreting results

The summary reports each valid median and its percentage of the direct median
for the same scenario, followed by every rejected report and its reason. Still
inspect raw reports for packet loss, thermal throttling, link renegotiation, or
unexpected background traffic.
Also compare process CPU ticks and RSS/VmHWM; throughput alone cannot distinguish
user-space cost from BPF data-plane cost.

For controlled A/B work, keep constant:

- sing-box commit, build tags, configuration, and log level;
- kernel, device firmware, CPU governor, affinity, and thermal state;
- NIC, MTU, link speed, and offloads;
- server, route, payload, concurrency, duration, and warmup;
- address family and eBPF policy-prefix count.

Network switching, interface flap, suspend/resume, and long-running map lifecycle
tests are stability tests, not throughput workloads. Run and report them
separately so transient recovery behavior does not distort steady-state medians.
