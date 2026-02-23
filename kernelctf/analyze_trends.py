#!/usr/bin/env -S python3 -u
"""Analyze kernelCTF submission trends and identify subsystem hotspots.

Reads all metadata.json files from pocs/linux/kernelctf/, groups submissions
by subsystem (derived from kernel_config requirements), and reports:
  - Subsystems targeted by three or more unique CVEs (hotspots)
  - Attack surface usage (syscall entry points: userns, io_uring, etc.)
  - Required capability trends
  - Overall vulnerability statistics

Writes a Markdown report to stdout and to $GITHUB_STEP_SUMMARY when set.
Exits with code 1 if any subsystem hotspot is found, so CI can detect it.
"""

import glob
import json
import os
import re
import sys
from collections import defaultdict
from datetime import datetime, timezone

POC_FOLDER = "pocs/linux/kernelctf/"
HOTSPOT_THRESHOLD = 3

# Ordered list of (compiled regex, canonical subsystem name).
# The first matching prefix wins for each kernel config option.
SUBSYSTEM_CONFIG_MAP = [
    (re.compile(r"^CONFIG_NF_"), "netfilter"),
    (re.compile(r"^CONFIG_NETFILTER"), "netfilter"),
    (re.compile(r"^CONFIG_IP_SET"), "netfilter"),
    (re.compile(r"^CONFIG_NET_SCH_"), "net/sched"),
    (re.compile(r"^CONFIG_NET_CLS_"), "net/sched"),
    (re.compile(r"^CONFIG_NET_SCHED"), "net/sched"),
    (re.compile(r"^CONFIG_BPF"), "bpf"),
    (re.compile(r"^CONFIG_TLS"), "tls"),
    (re.compile(r"^CONFIG_IO_URING"), "io_uring"),
    (re.compile(r"^CONFIG_PERF_EVENTS"), "perf_events"),
    (re.compile(r"^CONFIG_AF_UNIX"), "af_unix"),
    (re.compile(r"^CONFIG_UNIX"), "af_unix"),
    (re.compile(r"^CONFIG_SMBFS"), "smb"),
    (re.compile(r"^CONFIG_VSOCKETS"), "vsock"),
    (re.compile(r"^CONFIG_ETHTOOL"), "ethtool"),
    (re.compile(r"^CONFIG_IP_MULTICAST"), "ip_multicast"),
    (re.compile(r"^CONFIG_XFRM"), "xfrm"),
    (re.compile(r"^CONFIG_CRYPTO_"), "crypto"),
]

# Suggested attack surface reduction measures per subsystem.
REDUCTION_HINTS = {
    "netfilter": (
        "Restrict nftables access for unprivileged user namespaces. "
        "Options include `sysctl -w user.max_user_namespaces=0` to fully disable "
        "unprivileged user namespaces, AppArmor/seccomp rules to restrict `unshare` "
        "or `clone(CLONE_NEWUSER)`, or distro-level restrictions (e.g., "
        "Debian/Ubuntu `kernel.unprivileged_userns_clone=0`). "
        "The `CONFIG_NF_TABLES` subsystem has the highest CVE count in kernelCTF history."
    ),
    "net/sched": (
        "Limit `tc` (traffic control) access via user namespace restrictions. "
        "The `CAP_NET_ADMIN` capability required by this subsystem is reachable "
        "inside user namespaces; restricting `CLONE_NEWUSER` mitigates exposure."
    ),
    "bpf": (
        "Set `kernel.unprivileged_bpf_disabled=1` to block unprivileged BPF. "
        "Alternatively, enforce `CAP_BPF` or `CAP_SYS_ADMIN` for BPF syscall use."
    ),
    "io_uring": (
        "Set `kernel.io_uring_disabled=1` (Linux 6.4+) or "
        "`kernel.io_uring_group` to restrict io_uring to specific groups. "
        "Consider disabling io_uring in container environments where it is not needed."
    ),
    "tls": (
        "Disable `CONFIG_TLS` in deployments where kernel TLS offload is not "
        "required. Review whether `CONFIG_XFRM_ESPINTCP` is needed."
    ),
    "af_unix": (
        "Restrict Unix domain socket creation in sandboxed environments via "
        "seccomp or network namespace isolation."
    ),
    "perf_events": (
        "Set `kernel.perf_event_paranoid=3` to restrict perf event access to "
        "privileged users, or disable `CONFIG_PERF_EVENTS` in hardened builds."
    ),
    "vsock": (
        "Limit `CONFIG_VSOCKETS` to environments that require VM-to-host "
        "communication (e.g., restrict via seccomp in containers)."
    ),
    "xfrm": (
        "Restrict `CONFIG_XFRM_ESPINTCP` and related IPsec options to "
        "deployments that actively use kernel IPsec."
    ),
}


def classify_subsystems(kernel_configs):
    """Return the set of subsystem names for a list of kernel config options."""
    subsystems = set()
    for config in kernel_configs:
        for pattern, subsystem in SUBSYSTEM_CONFIG_MAP:
            if pattern.match(config):
                subsystems.add(subsystem)
                break
    return subsystems if subsystems else {"unknown"}


def load_submissions(poc_folder):
    """Load all metadata.json files and return a list of submission dicts."""
    submissions = []
    pattern = os.path.join(poc_folder, "*/metadata.json")
    for metadata_file in sorted(glob.glob(pattern)):
        submission_dir = os.path.basename(os.path.dirname(metadata_file))
        try:
            with open(metadata_file) as f:
                metadata = json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            print(f"[!] Skipping {metadata_file}: {e}", file=sys.stderr)
            continue

        vuln = metadata.get("vulnerability", {})
        reqs = vuln.get("requirements", {})

        cve = vuln.get("cve", "")
        submission_ids = metadata.get("submission_ids", [])
        if isinstance(submission_ids, str):
            submission_ids = [submission_ids]

        kernel_configs = reqs.get("kernel_config", [])
        attack_surface = reqs.get("attack_surface", [])
        capabilities = reqs.get("capabilities", [])
        subsystems = classify_subsystems(kernel_configs)

        submissions.append({
            "dir": submission_dir,
            "cve": cve,
            "submission_ids": submission_ids,
            "kernel_configs": kernel_configs,
            "attack_surface": attack_surface,
            "capabilities": capabilities,
            "subsystems": subsystems,
        })
    return submissions


def analyze(submissions):
    """Analyze submissions and return an aggregated statistics dict."""
    subsystem_cves = defaultdict(set)
    attack_surface_counts = defaultdict(int)
    capability_counts = defaultdict(int)
    total_unique_cves = set()

    for sub in submissions:
        cve_key = sub["cve"] or sub["dir"]
        total_unique_cves.add(cve_key)

        for subsystem in sub["subsystems"]:
            subsystem_cves[subsystem].add(cve_key)

        for entry in sub["attack_surface"]:
            attack_surface_counts[entry] += 1

        for cap in sub["capabilities"]:
            capability_counts[cap] += 1

    hotspots = {
        subsystem: cves
        for subsystem, cves in subsystem_cves.items()
        if len(cves) >= HOTSPOT_THRESHOLD
    }

    return {
        "total_submissions": len(submissions),
        "total_unique_cves": len(total_unique_cves),
        "subsystem_cves": dict(subsystem_cves),
        "hotspots": hotspots,
        "attack_surface_counts": dict(attack_surface_counts),
        "capability_counts": dict(capability_counts),
    }


def generate_report(stats):
    """Generate and return a Markdown trend report string."""
    lines = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    lines += [
        "# kernelCTF Vulnerability Trend Analysis",
        "",
        f"Generated: {now}",
        "",
        "## Overview",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Total submissions analyzed | {stats['total_submissions']} |",
        f"| Unique CVEs | {stats['total_unique_cves']} |",
        f"| Subsystems affected | {len(stats['subsystem_cves'])} |",
        f"| Subsystem hotspots (≥{HOTSPOT_THRESHOLD} CVEs) | {len(stats['hotspots'])} |",
        "",
    ]

    # Hotspot section
    if stats["hotspots"]:
        lines += [
            f"## ⚠️ Subsystem Hotspots (≥{HOTSPOT_THRESHOLD} CVEs)",
            "",
            "The following subsystems have been targeted by three or more distinct CVEs "
            "and represent the highest-priority attack surface reduction opportunities. "
            "Product security teams should be notified and should evaluate feasibility "
            "of restricting these subsystems for untrusted users.",
            "",
        ]
        sorted_hotspots = sorted(
            stats["hotspots"].items(), key=lambda x: -len(x[1])
        )
        for subsystem, cves in sorted_hotspots:
            lines.append(f"### `{subsystem}` — {len(cves)} CVEs")
            lines.append("")
            for cve in sorted(cves):
                lines.append(f"- {cve}")
            lines.append("")

    # Full subsystem breakdown table
    lines += [
        "## Subsystem Breakdown",
        "",
        "| Subsystem | Unique CVEs | Hotspot |",
        "|-----------|-------------|---------|",
    ]
    sorted_subsystems = sorted(
        stats["subsystem_cves"].items(), key=lambda x: -len(x[1])
    )
    for subsystem, cves in sorted_subsystems:
        flag = "⚠️ Yes" if subsystem in stats["hotspots"] else "No"
        lines.append(f"| `{subsystem}` | {len(cves)} | {flag} |")
    lines.append("")

    # Attack surface / syscall entry points
    lines += [
        "## Attack Surface Usage (Syscall Entry Points)",
        "",
        "The `attack_surface` field records which unprivileged syscall entry points "
        "(`userns`, `io_uring`) are used to reach the vulnerability.",
        "",
        "| Entry Point | Submissions |",
        "|-------------|-------------|",
    ]
    sorted_atk = sorted(
        stats["attack_surface_counts"].items(), key=lambda x: -x[1]
    )
    for entry, count in sorted_atk:
        lines.append(f"| `{entry}` | {count} |")
    if not stats["attack_surface_counts"]:
        lines.append("| *(none recorded)* | — |")
    lines.append("")

    # Capability requirements
    lines += [
        "## Required Capabilities",
        "",
        "| Capability | Submissions |",
        "|------------|-------------|",
    ]
    sorted_caps = sorted(
        stats["capability_counts"].items(), key=lambda x: -x[1]
    )
    for cap, count in sorted_caps:
        lines.append(f"| `{cap}` | {count} |")
    if not stats["capability_counts"]:
        lines.append("| *(none required)* | — |")
    lines.append("")

    # Attack surface reduction recommendations
    if stats["hotspots"]:
        lines += [
            "## Attack Surface Reduction Opportunities",
            "",
            "Suggested measures to limit exposure of hotspot subsystems to "
            "untrusted users. Feasibility and customer impact should be discussed "
            "with the relevant product security teams before deployment.",
            "",
        ]
        for subsystem in sorted(stats["hotspots"].keys()):
            hint = REDUCTION_HINTS.get(
                subsystem,
                "Review subsystem access controls and consider user namespace "
                "or seccomp restrictions to limit exposure to unprivileged users.",
            )
            lines.append(f"- **`{subsystem}`**: {hint}")
        lines.append("")

    return "\n".join(lines)


def main():
    base_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(base_dir)
    poc_folder = os.path.join(repo_root, POC_FOLDER)

    print(f"[-] Scanning: {poc_folder}", file=sys.stderr)

    submissions = load_submissions(poc_folder)
    print(f"[-] Loaded {len(submissions)} submission(s)", file=sys.stderr)

    stats = analyze(submissions)
    report = generate_report(stats)

    print(report)

    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if step_summary:
        with open(step_summary, "a") as f:
            f.write(report + "\n")

    if stats["hotspots"]:
        hotspot_names = ", ".join(sorted(stats["hotspots"].keys()))
        print(
            f"[!] {len(stats['hotspots'])} hotspot(s) found "
            f"(≥{HOTSPOT_THRESHOLD} CVEs): {hotspot_names}",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
