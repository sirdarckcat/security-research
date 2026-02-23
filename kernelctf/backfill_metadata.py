#!/usr/bin/env -S python3 -u
"""Populate (or refresh) structured analysis fields in each metadata.json.

Reads the following files for each submission and derives the field values
from their documented content — NOT from broad regex heuristics:

  docs/vulnerability.md   → vulnerability.bug_classes
                            (parses the explicit "Cause:" key-value field or
                             "## Cause" section body; falls back to reading the
                             vulnerability description when neither is present)

  docs/exploit.md         → exploits.<target>.techniques
                            (extracts section headers and maps them to canonical
                             technique labels; also detects specific technique
                             phrases that authors document in body text rather
                             than section headings)

  exploit/<target>/**/*.{c,cpp}  → exploits.<target>.syscalls_used
                            (scans every C/C++ source file in the per-target
                             exploit directory for direct syscall invocations)

Run from the repo root:
    python3 kernelctf/backfill_metadata.py [--dry-run]

The script always re-derives all three fields, overwriting any previously
computed values so that the output reflects the current document content.
"""

import glob
import json
import os
import re
import sys

_here = os.path.dirname(os.path.abspath(__file__))
DRY_RUN = "--dry-run" in sys.argv
POC_FOLDER = os.path.join(os.path.dirname(_here), "pocs", "linux", "kernelctf")

# ---------------------------------------------------------------------------
# bug_classes — parsed from vulnerability.md
# ---------------------------------------------------------------------------

# Maps the normalised text of a "Cause:" field (or equivalent section body)
# to one or more canonical bug-class enum values.
_CAUSE_MAP: dict[str, list[str]] = {
    "use-after-free":                           ["uaf"],
    "use after free":                           ["uaf"],
    "uaf":                                      ["uaf"],
    "double-free":                              ["double-free"],
    "double free":                              ["double-free"],
    "locking issue leads to double free":       ["double-free"],
    "race condition":                           ["race"],
    "race condition / use-after-free":          ["race", "uaf"],
    "out-of-bounds access":                     ["oob"],
    "out-of-bounds memory access":             ["oob"],
    "out-of-bounds reads and writes":           ["oob"],
    "out-of-bounds write":                      ["oob"],
    "out-of-bounds read/write":                 ["oob"],
    "slab-out-of-bounds read/write":            ["oob"],
    "out-of-bounds":                            ["oob"],
    "oob":                                      ["oob"],
    "missing range check":                      ["missing-check"],
    "missing range check, out-of-bounds write": ["missing-check", "oob"],
    "buffer overlapping":                       ["buffer-overlap"],
    "buffer overlap":                           ["buffer-overlap"],
    "integer overflow":                         ["integer-overflow"],
    "refcount overflow":                        ["refcount-overflow"],
}

# Fallback phrase → bug class used when no structured "Cause:" field exists.
# Ordered from most specific to least specific to avoid wrong matches.
_DESCRIPTION_PHRASES: list[tuple[str, str]] = [
    ("double-free",      "double-free"),
    ("double free",      "double-free"),
    ("refcount overflow","refcount-overflow"),
    ("integer overflow", "integer-overflow"),
    ("buffer overlapping","buffer-overlap"),
    ("race condition",   "race"),
    ("use-after-free",   "uaf"),
    ("use after free",   "uaf"),
    ("out-of-bounds",    "oob"),
]


def _parse_bug_classes(vuln_text: str) -> list[str]:
    """Return sorted canonical bug-class labels from vulnerability.md content.

    Reads the document in this priority order:
      1. Explicit 'Cause:' key-value field (e.g. '- Cause: Use-After-Free')
      2. Body of a '## Cause' section (first non-blank line/bullet)
      3. Vulnerability description text (targeted phrase lookup, last resort)
    """
    classes: set[str] = set()

    # 1. Structured key-value field: "- Cause: X" / "- **Cause**: X"
    for m in re.finditer(
        r"^\s*[-*]\s*\*{0,2}Cause\*{0,2}\s*:\s*(.+)",
        vuln_text,
        re.MULTILINE | re.IGNORECASE,
    ):
        raw = m.group(1).strip().rstrip(".").strip("`")
        mapped = _CAUSE_MAP.get(raw.lower())
        if mapped:
            classes.update(mapped)

    if classes:
        return sorted(classes)

    # 2. "## Cause" section body — read first meaningful line or bullet
    m = re.search(
        r"^##\s+Cause[^\n]*\n((?:(?!^##)[\s\S])*)",
        vuln_text,
        re.MULTILINE,
    )
    if m:
        for line in m.group(1).splitlines():
            text = line.strip().lstrip("-* ").rstrip(".").strip("`")
            if not text:
                continue
            mapped = _CAUSE_MAP.get(text.lower())
            if mapped:
                classes.update(mapped)
                break

    if classes:
        return sorted(classes)

    # 3. Fall back to reading the vulnerability description text.
    #    Use targeted, unambiguous phrase lookups rather than broad patterns.
    lower = vuln_text.lower()
    for phrase, label in _DESCRIPTION_PHRASES:
        if phrase in lower:
            classes.add(label)
            break  # only pick the first (most specific) match

    return sorted(classes)


# ---------------------------------------------------------------------------
# techniques — derived from exploit.md section headers and documented phrases
# ---------------------------------------------------------------------------

# Maps a keyword (matched case-insensitively in a section header) to a
# technique label.  Each entry is (keywords, label); the first keyword that
# appears anywhere in the header text wins.
_HEADER_TECHNIQUES: list[tuple[list[str], str]] = [
    # KASLR bypass — must check before generic "bypass" to avoid false match
    (["entrybleed"],                                            "entrybleed"),
    (["kaslr", "infoleak with prefetch"],                      "kaslr-bypass"),
    # Cross-cache
    (["cross-cache attack", "cross-cache", "cross cache",
      "heap grooming and cross"],                              "cross-cache"),
    # Heap spray objects
    (["heap spray", "spray heap", "spray objects",
      "spray as many", "spray large amount",
      "spray ebpf", "spray bpf"],                             "heap-spray"),
    # msg_msg
    (["msg_msg", "struct msg_msg",
      "reclaim skb with msg_msg"],                            "msg_msg-spray"),
    # pipe_buffer
    (["pipe_buffer", "pipe page buffer", "pipe buffer",
      "reclaim skb with pipe",
      "exploiting pipe inode"],                               "pipe_buffer-spray"),
    # user_key_payload
    (["user_key_payload"],                                     "user_key_payload-spray"),
    # setxattr spray
    (["setxattr"],                                             "setxattr-spray"),
    # Page allocator bypass
    (["page uaf", "dirty pagedirectory",
      "__alloc_pages", "allocate_slab"],                      "page-allocator"),
    # userfaultfd
    (["userfaultfd"],                                          "userfaultfd"),
    # ROP / RIP control
    (["rop chain", "rop detail", "rop chain construction",
      "rip control", "rip target", "control rip",
      "pc control", "getting rip control",
      "uaf to rip control", "use-after-free to control rip",
      "heap spray and rip"],                                  "rop"),
    # Race exploit
    (["race between", "race condition", "race to double free",
      "repeating the race", "extending the race",
      "race window"],                                         "race-exploit"),
    # Fake ops — section heading variant
    (["fake ops", "fake_ops", "fake qdisc_ops", "fake qdisc"],
                                                              "fake-ops"),
]

# Explicit phrases that document a technique in body text rather than as a
# section heading.  These are unambiguous, stable technique names that
# authors consistently use when describing these primitives.
_BODY_PHRASES: list[tuple[str, str]] = [
    ("fake ops",        "fake-ops"),     # "sprayed fake ops address"
    ("fake_ops",        "fake-ops"),     # code snippets
    ("cross-cache",     "cross-cache"),  # "-" separated variant in body
    ("cross cache",     "cross-cache"),  # space-separated variant in body
    # "use page allocator" / "to use page allocator" → mitigation bypass
    ("use page allocator",      "page-allocator"),
    ("buddy allocator",         "page-allocator"),
    # user_key_payload mentioned in body without its own header
    ("user_key_payload",        "user_key_payload-spray"),
]


def _parse_techniques(exploit_text: str) -> list[str]:
    """Return sorted canonical technique labels from exploit.md content.

    Primary source: section headers (h1–h4).
    Secondary source: specific named technique phrases in body text.
    """
    techniques: set[str] = set()

    # 1. Extract all markdown section headers (# H1 … #### H4)
    headers = re.findall(r"^#{1,4}\s+(.+)", exploit_text, re.MULTILINE)

    for header in headers:
        header_lower = header.lower()
        for keywords, label in _HEADER_TECHNIQUES:
            if any(kw in header_lower for kw in keywords):
                techniques.add(label)

    # 2. Scan body text for well-defined technique phrases that authors use
    #    consistently but do not always give their own section heading.
    exploit_lower = exploit_text.lower()
    for phrase, label in _BODY_PHRASES:
        if phrase in exploit_lower:
            techniques.add(label)

    # 3. ROP is ubiquitous — also infer it when the text mentions "rop"
    #    as a standalone word (e.g. "stored the rop payload").
    if re.search(r"\brop\b", exploit_lower):
        techniques.add("rop")

    return sorted(techniques)


# ---------------------------------------------------------------------------
# syscalls_used — scanned from all exploit C/C++ sources
# ---------------------------------------------------------------------------

# Syscalls we want to track.  The pattern matches a function call whose name
# is exactly one of these identifiers (whole-word match).
_SYSCALL_NAMES = (
    "bpf", "clone", "epoll_create", "getxattr", "getsockopt", "ioctl",
    "io_uring_enter", "io_uring_setup", "keyctl", "mount", "msgrcv", "msgsnd",
    "perf_event_open", "pipe", "prctl", "recvmsg", "sendmsg", "sendto",
    "setsockopt", "setxattr", "socket", "splice", "timerfd_create",
    "umount", "unshare", "userfaultfd",
)
_SYSCALL_PATTERN = re.compile(
    r"\b(" + "|".join(re.escape(s) for s in _SYSCALL_NAMES) + r")\s*\("
)


def _scan_syscalls(exploit_dir: str, target_name: str) -> list[str]:
    """Return sorted syscall names called in exploit sources for *target_name*.

    Scans every .c and .cpp file under exploit/<target_name>/.
    """
    target_dir = os.path.join(exploit_dir, target_name)
    syscalls: set[str] = set()
    for pattern in ("**/*.c", "**/*.cpp"):
        for src in glob.glob(os.path.join(target_dir, pattern), recursive=True):
            try:
                with open(src) as f:
                    text = f.read()
            except OSError:
                continue
            for m in _SYSCALL_PATTERN.finditer(text):
                syscalls.add(m.group(1))
    return sorted(syscalls)


# ---------------------------------------------------------------------------
# Main backfill logic
# ---------------------------------------------------------------------------

def _read(path: str) -> str:
    try:
        with open(path) as f:
            return f.read()
    except OSError:
        return ""


def backfill(metadata_file: str) -> bool:
    """Re-derive analysis fields for one metadata.json.  Return True if changed."""
    submission_path = os.path.dirname(metadata_file)
    docs_dir = os.path.join(submission_path, "docs")
    exploit_dir = os.path.join(submission_path, "exploit")

    with open(metadata_file) as f:
        metadata = json.load(f)

    vuln_text = _read(os.path.join(docs_dir, "vulnerability.md"))
    exploit_text = _read(os.path.join(docs_dir, "exploit.md"))

    # --- vulnerability.bug_classes -------------------------------------------
    vuln = metadata.setdefault("vulnerability", {})
    bug_classes = _parse_bug_classes(vuln_text)
    changed = False

    if vuln.get("bug_classes") != bug_classes:
        if bug_classes:
            vuln["bug_classes"] = bug_classes
        elif "bug_classes" in vuln:
            del vuln["bug_classes"]
        changed = True

    # --- per-exploit techniques + syscalls_used ------------------------------
    techniques = _parse_techniques(exploit_text)

    exploits_raw = metadata.get("exploits", {})
    is_list = isinstance(exploits_raw, list)
    entries = exploits_raw if is_list else list(exploits_raw.items())

    for item in entries:
        if is_list:
            entry = item
            target = entry.get("environment", "")
        else:
            target, entry = item

        syscalls = _scan_syscalls(exploit_dir, target)

        if entry.get("techniques") != techniques:
            entry["techniques"] = techniques
            changed = True
        if entry.get("syscalls_used") != syscalls:
            entry["syscalls_used"] = syscalls
            changed = True

    if changed and not DRY_RUN:
        with open(metadata_file, "w") as f:
            json.dump(metadata, f, indent=4)
            f.write("\n")

    return changed


def main() -> None:
    pattern = os.path.join(POC_FOLDER, "*/metadata.json")
    files = sorted(glob.glob(pattern))
    updated = 0
    for mf in files:
        name = os.path.basename(os.path.dirname(mf))
        try:
            changed = backfill(mf)
        except Exception as e:
            print(f"[!] ERROR {name}: {e}", file=sys.stderr)
            continue
        if changed:
            updated += 1
            action = "(dry-run)" if DRY_RUN else "updated"
            print(f"[+] {action}: {name}")

    total = len(files)
    print(
        f"\n{'[dry-run] Would update' if DRY_RUN else 'Updated'} "
        f"{updated}/{total} metadata.json files.",
        file=sys.stderr,
    )


if __name__ == "__main__":
    main()
