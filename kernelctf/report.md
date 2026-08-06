# kernelCTF Vulnerability Trend Analysis

Generated: 2026-02-23 17:21 UTC

## Overview

| Metric | Count |
|--------|-------|
| Total submissions analyzed | 81 |
| Unique CVEs | 63 |
| Subsystems affected | 13 |
| Subsystem hotspots (≥3 CVEs) | 5 |
| Exploits requiring separate KASLR leak | 15 |

## ⚠️ Subsystem Hotspots (≥3 CVEs)

The following subsystems have been targeted by three or more distinct CVEs and represent the highest-priority attack surface reduction opportunities. Product security teams should be notified and should evaluate feasibility of restricting these subsystems for untrusted users.

### `netfilter` — 28 CVEs

- CVE-2023-0193
- CVE-2023-32233
- CVE-2023-3390
- CVE-2023-3777
- CVE-2023-4004
- CVE-2023-4015
- CVE-2023-4147
- CVE-2023-4244
- CVE-2023-4569
- CVE-2023-5197
- CVE-2023-52620
- CVE-2023-52924
- CVE-2023-52925
- CVE-2023-52927
- CVE-2023-6111
- CVE-2023-6817
- CVE-2024-0193
- CVE-2024-1085
- CVE-2024-1086
- CVE-2024-26581
- CVE-2024-26642
- CVE-2024-26808
- CVE-2024-26809
- CVE-2024-26925
- CVE-2024-27397
- CVE-2024-39503
- CVE-2024-53141
- CVE-2024-57947

### `net/sched` — 16 CVEs

- CVE-2023-31436
- CVE-2023-3609
- CVE-2023-3611
- CVE-2023-3776
- CVE-2023-4206
- CVE-2023-4207
- CVE-2023-4208
- CVE-2023-4623
- CVE-2023-4921
- CVE-2024-41010
- CVE-2024-53164
- CVE-2025-21700
- CVE-2025-21702
- CVE-2025-37752
- CVE-2025-38001
- CVE-2025-38083

### `tls` — 4 CVEs

- CVE-2023-0461
- CVE-2024-26582
- CVE-2024-26585
- CVE-2024-58240

### `bpf` — 4 CVEs

- CVE-2023-52447
- CVE-2024-41009
- CVE-2024-49861
- CVE-2024-53125

### `io_uring` — 4 CVEs

- CVE-2023-6560
- CVE-2024-0582
- CVE-2024-40364
- CVE-2025-21836

## Subsystem Breakdown

| Subsystem | Unique CVEs | Hotspot |
|-----------|-------------|---------|
| `netfilter` | 28 | ⚠️ Yes |
| `net/sched` | 16 | ⚠️ Yes |
| `tls` | 4 | ⚠️ Yes |
| `bpf` | 4 | ⚠️ Yes |
| `io_uring` | 4 | ⚠️ Yes |
| `af_unix` | 2 | No |
| `crypto` | 2 | No |
| `xfrm` | 1 | No |
| `smb` | 1 | No |
| `perf_events` | 1 | No |
| `ip_multicast` | 1 | No |
| `ethtool` | 1 | No |
| `vsock` | 1 | No |

## Bug-Cause Distribution

From `vulnerability.bug_classes` in `metadata.json` (falling back to heuristic doc parsing for older submissions). A single submission may exhibit multiple causes.

| Bug Cause | Submissions |
|-----------|-------------|
| `uaf` | 63 |
| `race` | 12 |
| `double-free` | 9 |
| `oob` | 8 |
| `missing-check` | 5 |
| `integer-overflow` | 2 |
| `buffer-overlap` | 1 |

## Exploit Technique Trends

From `techniques` in each `exploits.<target>` entry of `metadata.json` (falling back to heuristic doc parsing for older submissions). Recurring techniques across many CVEs are prime targets for generic mitigations (e.g., hardening heap object layouts, restricting cross-cache reuse).

| Technique | Submissions |
|-----------|-------------|
| `kaslr-bypass` | 71 |
| `heap-spray` | 66 |
| `rop` | 64 |
| `fake-ops` | 49 |
| `cross-cache` | 21 |
| `msg_msg-spray` | 21 |
| `page-allocator` | 13 |
| `race-exploit` | 13 |
| `user_key_payload-spray` | 12 |
| `pipe_buffer-spray` | 12 |
| `setxattr-spray` | 10 |
| `entrybleed` | 4 |

## Heap Caches Targeted

Heap allocator caches (`kmalloc-*`) mentioned in exploit documentation, showing which kernel object sizes are most often used as spray targets. Hardening high-frequency caches (e.g., `CONFIG_SLAB_VIRTUAL`, `CONFIG_RANDOM_KMALLOC_CACHES`) directly impacts exploit reliability.

| Cache | Mentions |
|-------|----------|
| `kmalloc-128` | 18 |
| `kmalloc-256` | 11 |
| `kmalloc-cg-192` | 11 |
| `kmalloc-cg-96` | 8 |
| `kmalloc-512` | 7 |
| `kmalloc-cg-16` | 7 |
| `kmalloc-cg-64` | 6 |
| `kmalloc-192` | 6 |
| `kmalloc-cg-256` | 5 |
| `kmalloc-1024` | 5 |
| `kmalloc-8192` | 4 |
| `kmalloc-cg-128` | 4 |
| `kmalloc-cg-512` | 3 |
| `kmalloc-96` | 3 |
| `kmalloc-64` | 2 |
| `kmalloc-2048` | 1 |
| `kmalloc-196` | 1 |
| `kmalloc-cg-32` | 1 |
| `kmalloc-8` | 1 |
| `kmalloc-cg-2048` | 1 |

## Syscalls Used in Exploit Code

From `syscalls_used` in each `exploits.<target>` entry of `metadata.json` (falling back to heuristic C source scanning for older submissions). These are the building blocks of the exploits and potential seccomp / LSM restriction points.

| Syscall | Exploit variants |
|---------|-----------------|
| `unshare` | 63 |
| `socket` | 56 |
| `setsockopt` | 50 |
| `sendmsg` | 32 |
| `sendto` | 26 |
| `socketpair` | 19 |
| `pipe` | 17 |
| `msgget` | 15 |
| `msgsnd` | 14 |
| `msgrcv` | 10 |
| `add_key` | 9 |
| `recvmsg` | 9 |
| `clone` | 8 |
| `timerfd_settime` | 7 |
| `timerfd_create` | 7 |
| `ioctl` | 7 |
| `setxattr` | 5 |
| `mount` | 5 |
| `epoll_create` | 5 |
| `epoll_ctl` | 5 |
| `keyctl` | 4 |
| `fcntl` | 4 |
| `bpf` | 4 |
| `splice` | 2 |
| `prctl` | 2 |
| `getxattr` | 2 |
| `perf_event_open` | 2 |
| `getsockopt` | 1 |
| `vmsplice` | 1 |
| `io_uring_setup` | 1 |
| `io_uring_enter` | 1 |
| `io_uring_register` | 1 |

## Recommended Syscall Restrictions (from docs)

Taken from `Syscall to disable` fields in `vulnerability.md`. These are the authors' own suggestions for limiting each vulnerability's reach.

| Recommended restriction | Frequency |
|-------------------------|-----------|
| `disallow unprivileged username space` | 22 |
| `unshare` | 6 |
| `splice` | 2 |
| `bpf` | 2 |
| `setsockopt tcp_ulp` | 1 |
| `socket` | 1 |
| `setsockopt` | 1 |

## Attack Surface Usage (Syscall Entry Points)

The `attack_surface` field records which unprivileged syscall entry points (`userns`, `io_uring`) are used to reach the vulnerability.

| Entry Point | Submissions |
|-------------|-------------|
| `userns` | 34 |
| `io_uring` | 3 |

## Required Capabilities

| Capability | Submissions |
|------------|-------------|
| `CAP_NET_ADMIN` | 61 |
| `CAP_SYS_ADMIN` | 1 |
| `CAP_NET_RAW` | 1 |

## Exploit Reliability Distribution

Parsed from `stability_notes` in `metadata.json`. Low-reliability exploits may indicate timing or race-based vulnerabilities; very-high-reliability exploits are the most dangerous and suggest straightforward memory corruption paths.

| Reliability band | Exploit variants |
|------------------|------------------|
| 0-29% (low) | 10 |
| 30-69% (medium) | 7 |
| 70-89% (high) | 19 |
| 90-100% (very high) | 45 |

## Attack Surface Reduction Opportunities

Suggested measures to limit exposure of hotspot subsystems to untrusted users. Feasibility and customer impact should be discussed with the relevant product security teams before deployment.

- **`bpf`**: Set `kernel.unprivileged_bpf_disabled=1` to block unprivileged BPF. Alternatively, enforce `CAP_BPF` or `CAP_SYS_ADMIN` for BPF syscall use.
- **`io_uring`**: Set `kernel.io_uring_disabled=1` (Linux 6.4+) or `kernel.io_uring_group` to restrict io_uring to specific groups. Consider disabling io_uring in container environments where it is not needed.
- **`net/sched`**: Limit `tc` (traffic control) access via user namespace restrictions. The `CAP_NET_ADMIN` capability required by this subsystem is reachable inside user namespaces; restricting `CLONE_NEWUSER` mitigates exposure.
- **`netfilter`**: Restrict nftables access for unprivileged user namespaces. Options include `sysctl -w user.max_user_namespaces=0` to fully disable unprivileged user namespaces, AppArmor/seccomp rules to restrict `unshare` or `clone(CLONE_NEWUSER)`, or distro-level restrictions (e.g., Debian/Ubuntu `kernel.unprivileged_userns_clone=0`). The `CONFIG_NF_TABLES` subsystem has the highest CVE count in kernelCTF history.
- **`tls`**: Disable `CONFIG_TLS` in deployments where kernel TLS offload is not required. Review whether `CONFIG_XFRM_ESPINTCP` is needed.

