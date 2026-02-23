#!/usr/bin/env -S python3 -u
"""Analyze kernelCTF submission trends and identify subsystem hotspots.

Reads all metadata.json files from pocs/linux/kernelctf/.  Structured fields
added to metadata.json (bug_classes, techniques, syscalls_used) are read
directly; for older files without those fields the tool falls back to
heuristic extraction from docs/vulnerability.md, docs/exploit.md and exploit
C source files.

Report sections:
  - Subsystems targeted by three or more unique CVEs (hotspots)
  - Bug-cause taxonomy (UAF, OOB, race condition, …)
  - Exploit techniques (cross-cache, heap spray, ROP, KASLR bypass, …)
  - Heap caches targeted by spraying
  - Syscalls used in exploit code
  - Syscall-to-disable recommendations from the docs
  - Attack surface / capability trends
  - Exploit stability distribution

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
# Max rows shown in the syscall-restrictions and heap-cache tables.
MAX_TABLE_ROWS = 20

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

# --- Bug-cause classification -------------------------------------------------

# (regex applied to vulnerability.md text, canonical label)
BUG_CAUSE_PATTERNS = [
    (re.compile(r"\bdouble.?free\b", re.I), "double-free"),
    (re.compile(r"\buse.after.free\b|\buaf\b", re.I), "uaf"),
    (re.compile(r"\bout.of.bounds\b|\boob\b|\bslab.out.of.bounds\b", re.I), "oob"),
    (re.compile(r"\binteger overflow\b|\bint overflow\b", re.I), "integer-overflow"),
    (re.compile(r"\bbuffer overl(?:ap|apping)\b", re.I), "buffer-overlap"),
    (re.compile(r"\brace condition\b|\brace window\b|\bTOCTOU\b", re.I), "race"),
    (re.compile(r"\brefcount overflow\b|\brefcount\b.*overflow", re.I), "refcount-overflow"),
    (re.compile(r"\bmissing.*check\b|\binput saniti", re.I), "missing-check"),
]

# --- Exploit-technique classification -----------------------------------------

# (regex, canonical technique label)
TECHNIQUE_PATTERNS = [
    (re.compile(r"\bcross.cache\b", re.I), "cross-cache"),
    (re.compile(r"\bentrybleed\b", re.I), "entrybleed"),
    (re.compile(r"\buserfaultfd\b", re.I), "userfaultfd"),
    (re.compile(r"\bpage allocator\b|\bbuddy allocator\b|\border-0 page\b", re.I), "page-allocator"),
    (re.compile(r"\bpipe.buffer\b|\bstruct pipe_buffer\b", re.I), "pipe_buffer-spray"),
    (re.compile(r"\bmsg_msg\b|\bstruct msg_msg\b", re.I), "msg_msg-spray"),
    (re.compile(r"\buser_key_payload\b", re.I), "user_key_payload-spray"),
    (re.compile(r"\bsetxattr\b.*spray|\bspray\b.*setxattr", re.I), "setxattr-spray"),
    (re.compile(r"\bheap spray\b|\bspray\b.*heap|\bheap.*spray\b|\bspray.+object\b", re.I), "heap-spray"),
    (re.compile(r"\bKASLR bypass\b|\bleaking.*kaslr\b|\bbypass.*kaslr\b|\bkaslr.*leak\b", re.I), "kaslr-bypass"),
    (re.compile(r"\bROP chain\b|\bROP gadget\b|\bret2\b|\bRIP control\b", re.I), "rop"),
    (re.compile(r"\brace condition\b.*exploit|\bexploit.*race condition\b|\brace window\b", re.I), "race-exploit"),
    (re.compile(r"\bfake ops\b|\bfake.*ops\b|\bhijack.*ops\b", re.I), "fake-ops"),
]

# Syscalls we care about detecting in exploit source code.
SOURCE_SYSCALL_PATTERNS = re.compile(
    r"\b(io_uring_setup|io_uring_enter|unshare|clone3?|socket|"
    r"sendmsg|sendto|recvmsg|setsockopt|getsockopt|ioctl|"
    r"perf_event_open|keyctl|msgsnd|msgrcv|timerfd_create|"
    r"userfaultfd|epoll_create|prctl|bpf|mount|umount|pipe|"
    r"setxattr|getxattr|splice)\s*\("
)

# Pattern to find heap cache names referenced in docs.
HEAP_CACHE_PATTERN = re.compile(r"\bkmalloc-(?:cg-|dyn-)?\d+\b")

# Patterns to parse stability_notes into a 0-100 percentage.
_STABILITY_PATTERNS = [
    # "10 times success per 10 times run" → 100 %
    (re.compile(r"(\d+(?:\.\d+)?)\s*(?:~|-)\s*(\d+(?:\.\d+)?)\s*times?\s+success\s+per\s+10\s+times?\s+run", re.I),
     lambda m: (float(m.group(1)) + float(m.group(2))) / 2 * 10),
    (re.compile(r"(\d+(?:\.\d+)?)\s*times?\s+success\s+per\s+10\s+times?\s+run", re.I),
     lambda m: float(m.group(1)) * 10),
    (re.compile(r"succeeded\s+on\s+10/10", re.I),
     lambda m: 100.0),
    # "80% success rate" / "~99%" / "Near 100%"
    (re.compile(r"(?:near\s+)?~?\s*(\d+(?:\.\d+)?)\s*%", re.I),
     lambda m: float(m.group(1))),
]


def _parse_stability(notes):
    """Return success rate 0-100 from a stability_notes string, or None."""
    if not notes:
        return None
    for pattern, extractor in _STABILITY_PATTERNS:
        m = pattern.search(notes)
        if m:
            try:
                val = extractor(m)
                return max(0.0, min(100.0, val))
            except (ValueError, IndexError):
                pass
    return None


# --- Documentation helpers ----------------------------------------------------

def _read_file(path):
    """Read a file silently, returning empty string on error."""
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def _extract_bug_causes(text):
    """Return set of canonical bug-cause labels found in *text*."""
    found = set()
    for pattern, label in BUG_CAUSE_PATTERNS:
        if pattern.search(text):
            found.add(label)
    # Also accept inline "Cause: X" field (try to normalise raw values)
    m = re.search(r"[-*]\s*Cause\s*:\s*(.+)", text, re.I)
    if m:
        raw = m.group(1).strip().lower()
        mapping = {
            "use-after-free": "uaf", "uaf": "uaf",
            "double free": "double-free", "double-free": "double-free",
            "out-of-bounds": "oob", "out-of-bounds access": "oob",
            "buffer overlapping": "buffer-overlap",
            "race condition": "race",
            "integer overflow": "integer-overflow",
            "missing range check": "missing-check",
            "missing range check, out-of-bounds write": "oob",
            "refcount overflow": "refcount-overflow",
        }
        normalized = mapping.get(raw)
        if normalized:
            found.add(normalized)
    return found


def _extract_syscall_to_disable(text):
    """Return list of syscall-to-disable strings from vulnerability.md."""
    results = []
    for m in re.finditer(r"[-*\s]+[Ss]yscall\s+to\s+disable\s*[:*]*\s*(.+)", text):
        val = m.group(1).strip().rstrip(".").strip("`")
        # Drop boilerplate / partial captures
        if not val or val in ("-", "N/A", "n/a", "none"):
            continue
        # Truncate at parentheses or backtick to avoid partial captures
        val = re.split(r"\s*[\(]", val)[0].strip()
        if val:
            results.append(val)
    return results


def _extract_techniques(text):
    """Return set of technique labels found in *text*."""
    found = set()
    for pattern, label in TECHNIQUE_PATTERNS:
        if pattern.search(text):
            found.add(label)
    return found


def _extract_heap_caches(text):
    """Return set of heap cache names (kmalloc-*) found in *text*."""
    return set(HEAP_CACHE_PATTERN.findall(text))


def _extract_source_syscalls(source_text):
    """Return set of syscall names found as calls in C source code."""
    return set(m.group(1) for m in SOURCE_SYSCALL_PATTERNS.finditer(source_text))


def _read_docs_and_source(submission_path):
    """Read vulnerability.md, exploit.md and all exploit.c / poc.c files."""
    vuln_text = _read_file(os.path.join(submission_path, "docs", "vulnerability.md"))
    exploit_text = _read_file(os.path.join(submission_path, "docs", "exploit.md"))

    source_text = ""
    exploit_dir = os.path.join(submission_path, "exploit")
    for src_pattern in ("**/exploit.c", "**/poc.c", "**/exploit.cpp"):
        for src_file in glob.glob(os.path.join(exploit_dir, src_pattern), recursive=True):
            source_text += _read_file(src_file)

    return vuln_text, exploit_text, source_text


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
        submission_path = os.path.dirname(metadata_file)
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

        # --- Structured fields from metadata.json (preferred) ---------------
        bug_causes = set(vuln.get("bug_classes") or [])
        exploits_raw = metadata.get("exploits", {})
        exploit_entries = (
            exploits_raw if isinstance(exploits_raw, list) else list(exploits_raw.values())
        )
        # Aggregate per-exploit techniques / syscalls across all variants.
        techniques_from_meta: set = set()
        source_syscalls_from_meta: set = set()
        for entry in exploit_entries:
            techniques_from_meta.update(entry.get("techniques") or [])
            source_syscalls_from_meta.update(entry.get("syscalls_used") or [])

        # --- Fallback: parse docs / source when structured fields absent ----
        needs_docs = (
            not bug_causes
            or not techniques_from_meta
            or not source_syscalls_from_meta
        )
        vuln_text = exploit_text = source_text = ""
        if needs_docs:
            vuln_text, exploit_text, source_text = _read_docs_and_source(submission_path)
        combined_docs = vuln_text + "\n" + exploit_text

        if not bug_causes:
            bug_causes = _extract_bug_causes(vuln_text or combined_docs)
        if not techniques_from_meta:
            techniques_from_meta = _extract_techniques(combined_docs)
        if not source_syscalls_from_meta:
            source_syscalls_from_meta = _extract_source_syscalls(source_text)

        # syscalls_to_disable and heap_caches are always read from docs
        # (they have no structured field in metadata.json yet).
        if not vuln_text and not exploit_text:
            vuln_text, exploit_text, _ = _read_docs_and_source(submission_path)
        combined_docs = vuln_text + "\n" + exploit_text
        syscalls_to_disable = _extract_syscall_to_disable(vuln_text)
        heap_caches = _extract_heap_caches(combined_docs)

        # --- Parse stability and KASLR flag from all exploit entries --------
        stabilities = []
        kaslr_separate = False
        for entry in exploit_entries:
            notes = entry.get("stability_notes", "")
            s = _parse_stability(notes)
            if s is not None:
                stabilities.append(s)
            # handle both spellings present in the wild
            kaslr_key = entry.get(
                "requires_separate_kaslr_leak",
                entry.get("requires_seperate_kaslr_leak"),
            )
            if kaslr_key is True:
                kaslr_separate = True

        avg_stability = (
            round(sum(stabilities) / len(stabilities), 1) if stabilities else None
        )

        submissions.append({
            "dir": submission_dir,
            "cve": cve,
            "submission_ids": submission_ids,
            "kernel_configs": kernel_configs,
            "attack_surface": attack_surface,
            "capabilities": capabilities,
            "subsystems": subsystems,
            "bug_causes": bug_causes,
            "syscalls_to_disable": syscalls_to_disable,
            "techniques": techniques_from_meta,
            "heap_caches": heap_caches,
            "source_syscalls": source_syscalls_from_meta,
            "avg_stability": avg_stability,
            "kaslr_separate": kaslr_separate,
        })
    return submissions


def analyze(submissions):
    """Analyze submissions and return an aggregated statistics dict."""
    subsystem_cves = defaultdict(set)
    attack_surface_counts = defaultdict(int)
    capability_counts = defaultdict(int)
    bug_cause_counts = defaultdict(int)
    technique_counts = defaultdict(int)
    heap_cache_counts = defaultdict(int)
    source_syscall_counts = defaultdict(int)
    syscall_to_disable_counts = defaultdict(int)
    total_unique_cves = set()
    kaslr_separate_count = 0
    stabilities = []

    for sub in submissions:
        cve_key = sub["cve"] or sub["dir"]
        total_unique_cves.add(cve_key)

        for subsystem in sub["subsystems"]:
            subsystem_cves[subsystem].add(cve_key)

        for entry in sub["attack_surface"]:
            attack_surface_counts[entry] += 1

        for cap in sub["capabilities"]:
            capability_counts[cap] += 1

        for cause in sub["bug_causes"]:
            bug_cause_counts[cause] += 1

        for tech in sub["techniques"]:
            technique_counts[tech] += 1

        for cache in sub["heap_caches"]:
            heap_cache_counts[cache] += 1

        for sc in sub["source_syscalls"]:
            source_syscall_counts[sc] += 1

        for s2d in sub["syscalls_to_disable"]:
            # Normalise common values
            key = s2d.lower().strip()
            key = re.sub(r"\s+", " ", key)
            syscall_to_disable_counts[key] += 1

        if sub["kaslr_separate"]:
            kaslr_separate_count += 1

        if sub["avg_stability"] is not None:
            stabilities.append(sub["avg_stability"])

    hotspots = {
        subsystem: cves
        for subsystem, cves in subsystem_cves.items()
        if len(cves) >= HOTSPOT_THRESHOLD
    }

    stability_dist = _stability_distribution(stabilities)

    return {
        "total_submissions": len(submissions),
        "total_unique_cves": len(total_unique_cves),
        "subsystem_cves": dict(subsystem_cves),
        "hotspots": hotspots,
        "attack_surface_counts": dict(attack_surface_counts),
        "capability_counts": dict(capability_counts),
        "bug_cause_counts": dict(bug_cause_counts),
        "technique_counts": dict(technique_counts),
        "heap_cache_counts": dict(heap_cache_counts),
        "source_syscall_counts": dict(source_syscall_counts),
        "syscall_to_disable_counts": dict(syscall_to_disable_counts),
        "kaslr_separate_count": kaslr_separate_count,
        "stability_dist": stability_dist,
    }


def _stability_distribution(values):
    """Bucket stability values into Low/Medium/High/Very-High bands."""
    if not values:
        return {}
    buckets = {"0-29% (low)": 0, "30-69% (medium)": 0,
               "70-89% (high)": 0, "90-100% (very high)": 0}
    for v in values:
        if v < 30:
            buckets["0-29% (low)"] += 1
        elif v < 70:
            buckets["30-69% (medium)"] += 1
        elif v < 90:
            buckets["70-89% (high)"] += 1
        else:
            buckets["90-100% (very high)"] += 1
    return buckets


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
        f"| Exploits requiring separate KASLR leak | {stats['kaslr_separate_count']} |",
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

    # Bug cause / vulnerability type distribution
    if stats["bug_cause_counts"]:
        lines += [
            "## Bug-Cause Distribution",
            "",
            "From `vulnerability.bug_classes` in `metadata.json` "
            "(falling back to heuristic doc parsing for older submissions). "
            "A single submission may exhibit multiple causes.",
            "",
            "| Bug Cause | Submissions |",
            "|-----------|-------------|",
        ]
        for cause, count in sorted(stats["bug_cause_counts"].items(), key=lambda x: -x[1]):
            lines.append(f"| `{cause}` | {count} |")
        lines.append("")

    # Exploit technique trends
    if stats["technique_counts"]:
        lines += [
            "## Exploit Technique Trends",
            "",
            "From `techniques` in each `exploits.<target>` entry of `metadata.json` "
            "(falling back to heuristic doc parsing for older submissions). "
            "Recurring techniques across many CVEs are prime targets for "
            "generic mitigations (e.g., hardening heap object layouts, "
            "restricting cross-cache reuse).",
            "",
            "| Technique | Submissions |",
            "|-----------|-------------|",
        ]
        for tech, count in sorted(stats["technique_counts"].items(), key=lambda x: -x[1]):
            lines.append(f"| `{tech}` | {count} |")
        lines.append("")

    # Heap caches targeted in exploits
    if stats["heap_cache_counts"]:
        # Show top MAX_TABLE_ROWS caches to keep the report concise
        top_caches = sorted(stats["heap_cache_counts"].items(), key=lambda x: -x[1])[:MAX_TABLE_ROWS]
        lines += [
            "## Heap Caches Targeted",
            "",
            "Heap allocator caches (`kmalloc-*`) mentioned in exploit documentation, "
            "showing which kernel object sizes are most often used as spray targets. "
            "Hardening high-frequency caches (e.g., `CONFIG_SLAB_VIRTUAL`, "
            "`CONFIG_RANDOM_KMALLOC_CACHES`) directly impacts exploit reliability.",
            "",
            "| Cache | Mentions |",
            "|-------|----------|",
        ]
        for cache, count in top_caches:
            lines.append(f"| `{cache}` | {count} |")
        lines.append("")

    # Syscalls used in exploit source code
    if stats["source_syscall_counts"]:
        lines += [
            "## Syscalls Used in Exploit Code",
            "",
            "From `syscalls_used` in each `exploits.<target>` entry of `metadata.json` "
            "(falling back to heuristic C source scanning for older submissions). "
            "These are the building blocks of the exploits and potential "
            "seccomp / LSM restriction points.",
            "",
            "| Syscall | Exploit variants |",
            "|---------|-----------------|",
        ]
        for sc, count in sorted(stats["source_syscall_counts"].items(), key=lambda x: -x[1]):
            lines.append(f"| `{sc}` | {count} |")
        lines.append("")

    # Syscall-to-disable recommendations from docs
    if stats["syscall_to_disable_counts"]:
        lines += [
            "## Recommended Syscall Restrictions (from docs)",
            "",
            "Taken from `Syscall to disable` fields in `vulnerability.md`. "
            "These are the authors' own suggestions for limiting each vulnerability's reach.",
            "",
            "| Recommended restriction | Frequency |",
            "|-------------------------|-----------|",
        ]
        for s2d, count in sorted(
            stats["syscall_to_disable_counts"].items(), key=lambda x: -x[1]
        )[:MAX_TABLE_ROWS]:
            lines.append(f"| `{s2d}` | {count} |")
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

    # Exploit stability distribution
    if stats["stability_dist"]:
        lines += [
            "## Exploit Reliability Distribution",
            "",
            "Parsed from `stability_notes` in `metadata.json`. "
            "Low-reliability exploits may indicate timing or race-based "
            "vulnerabilities; very-high-reliability exploits are the most "
            "dangerous and suggest straightforward memory corruption paths.",
            "",
            "| Reliability band | Exploit variants |",
            "|------------------|------------------|",
        ]
        for band, count in stats["stability_dist"].items():
            lines.append(f"| {band} | {count} |")
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
