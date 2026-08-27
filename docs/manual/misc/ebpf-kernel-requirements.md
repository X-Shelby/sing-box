---
icon: material/linux
---

# eBPF kernel requirements

The eBPF inbound uses TC classifiers, transparent sockets, socket lookup and
`bpf_sk_assign`. Upstream Linux 5.7 is the practical minimum because socket
assignment is required rather than an optional optimization. Vendor kernels may
backport or disable individual helpers, so the runtime probe is more
authoritative than the reported version.

## Kernel configuration

The following options, or their vendor equivalents, are required:

| Option | Purpose |
| --- | --- |
| `CONFIG_BPF` | Core BPF support. |
| `CONFIG_BPF_SYSCALL` | Loads maps and programs. |
| `CONFIG_NET_CLS_BPF` | Runs BPF classifiers at TC hooks. |
| `CONFIG_NET_SCH_INGRESS` | Provides the `clsact` ingress and egress hooks. |
| `CONFIG_NET_CLS_ACT` | Enables direct-action classifier results. |
| `CONFIG_VETH` | Provides the local delivery link in local and hybrid modes. |
| `CONFIG_INET` | IPv4 TCP/UDP and transparent sockets. |
| `CONFIG_IPV6` | Required when local or shared IPv6 interception is enabled. |

`CONFIG_BPF_JIT` is strongly recommended for packet-path performance.

## Required BPF facilities

The selected kernel must support:

- `SCHED_CLS` programs on TC ingress and egress;
- the Linux `SO_COOKIE` socket option;
- `ARRAY`, `HASH`, `LRU_HASH`, `LPM_TRIE`, and `SOCKMAP` maps;
- `bpf_map_lookup_elem`, `bpf_map_update_elem`, and `bpf_map_delete_elem`;
- `bpf_get_socket_cookie` in `SCHED_CLS`;
- `bpf_get_socket_uid` in `SCHED_CLS`;
- `bpf_redirect` in `SCHED_CLS`;
- `bpf_skb_store_bytes` and `bpf_skb_change_head` in `SCHED_CLS`;
- `bpf_skc_lookup_tcp`, `bpf_sk_lookup_udp`, `bpf_sk_assign`, and
  `bpf_sk_release` in `SCHED_CLS`.

The object contains no BTF or CO-RE dependency. It is generated for both BPF
endiannesses and avoids bounded loops so vendor verifier behavior remains
predictable.

## Linux 6.6 LPM trie safety

Linux 6.6.0 through 6.6.46 may panic under UBSAN when an LPM trie is updated.
The default exact host-address policy uses `HASH` maps and is unaffected.
Configured UID/package filters, source CIDR filters, and destination bypass
CIDRs use LPM tries and require Linux 6.6.47 or a vendor kernel containing
upstream fix `896880ff30866f386ebed14ab81ce1ad3710cfc4`. sing-box rejects these
policies on kernels known to be unsafe.

## Privileges

Startup needs enough privilege to:

- load BPF maps and programs;
- create and remove a veth pair in local or hybrid mode;
- add and remove `clsact` qdiscs and BPF filters;
- add and remove policy-routing rules and local routes;
- change `rp_filter` and `accept_local` on the internal delivery peer;
- enable `IP_TRANSPARENT` or `IPV6_TRANSPARENT`;

Running as root is the most portable arrangement. Capability-only deployments
depend on kernel version, distribution policy, LSM rules, and Android SELinux
policy; they commonly require `CAP_NET_ADMIN`, `CAP_BPF`, and on older kernels
`CAP_SYS_ADMIN`.

No `bpftool`, `tc`, or `ip` executable is required at runtime. sing-box uses BPF
syscalls and netlink directly.

## Interface requirements

Local mode attaches to the network manager's current default interface. Shared
mode attaches to each configured downstream interface. Ethernet/IPoE and
L3-only raw-IP or PPP links are supported. Source MAC policy requires Ethernet
framing. Loopback and unrecognized link encapsulations are not supported.

Local attachments follow default-interface changes. Configured shared
interfaces are attached when present, except while an interface is acting as the
current default upstream. Link and route events trigger validation and repair of
managed attachments and network state; no periodic polling is used.

One sing-box eBPF inbound may manage an interface at a time. Existing unrelated
`clsact` filters are preserved, but a conflicting sing-box filter handle or
interface lock prevents startup.

The local delivery veth requires writable per-interface IPv4 sysctls under
`/proc/sys/net/ipv4/conf`. Original values are restored during cleanup.

## Probe

Use the built-in kernel probe with the same mode and protocols as the intended
configuration. For shared mode, pass one active downstream interface so its
link type can be checked.

The probe reports `UNKNOWN` when permission prevents a direct feature test.
This does not prove support; repeat it with the same privileges used to run
sing-box. A real startup remains necessary because the non-mutating probe does
not attach TC filters, create a veth, or change sysctls.

## Packet limitations

- Fragmented IPv4 datagrams and non-atomic IPv6 fragments bypass interception.
  IPv6 atomic fragments are processed normally.
- IPv6 parsing accepts at most four hop-by-hop, routing, destination-options,
  or authentication extension headers before TCP/UDP.
- Up to two VLAN headers are parsed on Ethernet-framed links.
- DHCP and DHCPv6 service traffic bypasses.
- Forwarded traffic bypasses the local egress path through the TC ingress
  interface metadata.
- sing-box sockets bypass local interception through cookies captured by its
  socket controls. Packets for which the kernel provides no socket cookie also
  bypass.
