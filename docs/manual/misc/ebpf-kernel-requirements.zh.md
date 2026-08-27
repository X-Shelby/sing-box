---
icon: material/linux
---

# eBPF 内核要求

eBPF 入站使用 TC 分类器、透明 socket、socket lookup 和 `bpf_sk_assign`。由于
socket 分配是必需能力而不是可选优化，上游 Linux 5.7 是实际最低版本。供应商
内核可能回移或禁用单项 helper，因此运行时探测比版本号更可靠。

## 内核配置

必须启用以下选项或供应商内核中的等价能力：

| 选项 | 用途 |
| --- | --- |
| `CONFIG_BPF` | BPF 核心支持。 |
| `CONFIG_BPF_SYSCALL` | 加载 map 和程序。 |
| `CONFIG_NET_CLS_BPF` | 在 TC hook 运行 BPF 分类器。 |
| `CONFIG_NET_SCH_INGRESS` | 提供 `clsact` ingress/egress hook。 |
| `CONFIG_NET_CLS_ACT` | 支持 direct-action 分类结果。 |
| `CONFIG_VETH` | local 和 hybrid 模式的内部 delivery 链路。 |
| `CONFIG_INET` | IPv4 TCP/UDP 和透明 socket。 |
| `CONFIG_IPV6` | 启用 local 或 shared IPv6 接管时必需。 |

强烈建议启用 `CONFIG_BPF_JIT`，否则报文路径性能可能明显下降。

## 必需的 BPF 能力

目标内核必须支持：

- TC ingress 和 egress 上的 `SCHED_CLS` 程序；
- Linux `SO_COOKIE` socket 选项；
- `ARRAY`、`HASH`、`LRU_HASH`、`LPM_TRIE` 和 `SOCKMAP`；
- `bpf_map_lookup_elem`、`bpf_map_update_elem` 和 `bpf_map_delete_elem`；
- `SCHED_CLS` 中的 `bpf_get_socket_cookie`；
- `SCHED_CLS` 中的 `bpf_get_socket_uid`；
- `SCHED_CLS` 中的 `bpf_redirect`；
- `SCHED_CLS` 中的 `bpf_skb_store_bytes` 和 `bpf_skb_change_head`；
- `SCHED_CLS` 中的 `bpf_skc_lookup_tcp`、`bpf_sk_lookup_udp`、
  `bpf_sk_assign` 和 `bpf_sk_release`。

对象不依赖 BTF 或 CO-RE，同时生成 BPF 大端和小端版本，并避免使用有界循环，
以降低供应商 verifier 差异。

## Linux 6.6 LPM trie 安全性

Linux 6.6.0 至 6.6.46 在更新 LPM trie 时可能因 UBSAN 触发内核崩溃。默认的精确
主机地址策略使用 `HASH` map，不受此问题影响。UID/应用筛选、来源 CIDR 筛选和
目标绕过 CIDR 使用 LPM trie，需要 Linux 6.6.47，或包含上游修复
`896880ff30866f386ebed14ab81ce1ad3710cfc4` 的厂商内核。sing-box 会在已知不安全
的内核上拒绝这些策略。

## 权限

启动时需要足够权限执行以下操作：

- 加载 BPF map 和程序；
- 在 local 或 hybrid 模式创建和删除 veth；
- 添加和删除 `clsact` qdisc 与 BPF filter；
- 添加和删除策略路由规则与 local route；
- 修改内部 delivery 对端的 `rp_filter` 和 `accept_local`；
- 启用 `IP_TRANSPARENT` 或 `IPV6_TRANSPARENT`；

以 root 运行兼容性最好。仅使用 capability 时会受内核版本、发行版策略、LSM
规则和 Android SELinux 策略影响，通常需要 `CAP_NET_ADMIN`、`CAP_BPF`，旧内核
还可能需要 `CAP_SYS_ADMIN`。

运行时不依赖 `bpftool`、`tc` 或 `ip` 命令，sing-box 直接使用 BPF syscall 和
netlink。

## 接口要求

local 模式挂载到网络管理器当前的默认接口；shared 模式挂载到配置的下游接口。
支持 Ethernet/IPoE，以及仅含 L3 的 raw-IP 或 PPP 链路；来源 MAC 策略要求接口使用
以太网帧。不支持 loopback 和无法识别的链路封装。

local attachment 会跟随默认接口变化。配置的 shared 接口存在时会自动挂载，但该接口
作为当前默认上游期间会暂停 shared 接管。链路和路由事件会触发受管 attachment 与网络
状态的检查和修复，不使用周期轮询。

同一时间一个接口只能由一个 sing-box eBPF 入站管理。已有的无关 `clsact` filter
会保留，但 sing-box filter handle 或接口锁冲突会阻止启动。

本机 delivery veth 需要 `/proc/sys/net/ipv4/conf` 下对应接口的 sysctl 可写，清理
时会恢复原值。

## 探测

使用与计划配置相同的模式和协议运行内置内核探测。shared 模式应传入一个当前
存在的下游接口，以检查链路类型。

权限不足导致直接能力探测失败时会报告 `UNKNOWN`，这并不能证明内核支持。请用
实际运行 sing-box 的权限重新探测。非变更型探测不会挂载 TC filter、创建 veth
或修改 sysctl，因此最终仍需一次真实启动验证。

## 报文限制

- 已分片的 IPv4 数据报和非 atomic IPv6 分片直接绕过；IPv6 atomic fragment
  正常处理。
- IPv6 最多解析四个 hop-by-hop、routing、destination-options 或 authentication
  扩展头，然后必须到达 TCP/UDP。
- 使用以太网帧的链路最多解析两层 VLAN 头。
- DHCP 和 DHCPv6 服务流量绕过。
- 转发流量通过 TC ingress interface 元数据绕过 local egress 路径。
- sing-box socket 通过 socket control 记录的 cookie 绕过 local 接管。内核无法提供
  socket cookie 的报文也会绕过。
