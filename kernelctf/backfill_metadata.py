#!/usr/bin/env -S python3 -u
"""Backfill new structured fields into existing metadata.json files.

Adds the following fields (if not already present) to every metadata.json
found under pocs/linux/kernelctf/:

  vulnerability.bug_classes      – e.g. ["uaf", "race"]
  exploits.<target>.techniques   – e.g. ["heap-spray", "rop", "kaslr-bypass"]
  exploits.<target>.syscalls_used – e.g. ["unshare", "socket", "sendmsg"]

Values are derived by running the same heuristics as analyze_trends.py
against the submission's docs/vulnerability.md, docs/exploit.md and
per-target exploit C source files.

Run from the repo root:
    python3 kernelctf/backfill_metadata.py

Dry-run mode (no files written):
    python3 kernelctf/backfill_metadata.py --dry-run
"""

import glob
import json
import os
import re
import sys

# ---------------------------------------------------------------------------
# Import helpers from analyze_trends (same directory)
# ---------------------------------------------------------------------------
_here = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _here)
from analyze_trends import (  # noqa: E402
    _extract_bug_causes,
    _extract_source_syscalls,
    _extract_techniques,
    _read_file,
)

DRY_RUN = "--dry-run" in sys.argv

POC_FOLDER = os.path.join(
    os.path.dirname(_here), "pocs", "linux", "kernelctf"
)


def _source_for_target(submission_path, target_name):
    """Return concatenated C source for one exploit target directory."""
    exploit_dir = os.path.join(submission_path, "exploit", target_name)
    source = ""
    for pat in ("**/*.c", "**/*.cpp"):
        for src in glob.glob(os.path.join(exploit_dir, pat), recursive=True):
            source += _read_file(src)
    return source


def backfill(metadata_file):
    """Backfill new fields into one metadata.json.  Return True if changed."""
    submission_path = os.path.dirname(metadata_file)

    with open(metadata_file) as f:
        metadata = json.load(f)

    # --- collect doc text ---------------------------------------------------
    vuln_text = _read_file(
        os.path.join(submission_path, "docs", "vulnerability.md")
    )
    exploit_text = _read_file(
        os.path.join(submission_path, "docs", "exploit.md")
    )
    combined_docs = vuln_text + "\n" + exploit_text

    # --- vulnerability.bug_classes ------------------------------------------
    vuln = metadata.setdefault("vulnerability", {})
    changed = False

    if "bug_classes" not in vuln:
        causes = sorted(_extract_bug_causes(vuln_text or combined_docs))
        if causes:
            vuln["bug_classes"] = causes
            changed = True

    # --- per-exploit techniques + syscalls_used -----------------------------
    exploits_raw = metadata.get("exploits", {})
    is_list = isinstance(exploits_raw, list)

    def _get_target_name(entry):
        """Return the target environment name for a v2 list entry."""
        return entry.get("environment", "")

    techniques_shared = sorted(_extract_techniques(combined_docs))

    if is_list:
        for entry in exploits_raw:
            target = _get_target_name(entry)
            if "techniques" not in entry and techniques_shared:
                entry["techniques"] = techniques_shared
                changed = True
            if "syscalls_used" not in entry:
                sc = sorted(_extract_source_syscalls(
                    _source_for_target(submission_path, target)
                ))
                if sc:
                    entry["syscalls_used"] = sc
                    changed = True
    else:
        for target, entry in exploits_raw.items():
            if "techniques" not in entry and techniques_shared:
                entry["techniques"] = techniques_shared
                changed = True
            if "syscalls_used" not in entry:
                sc = sorted(_extract_source_syscalls(
                    _source_for_target(submission_path, target)
                ))
                if sc:
                    entry["syscalls_used"] = sc
                    changed = True

    if changed and not DRY_RUN:
        with open(metadata_file, "w") as f:
            json.dump(metadata, f, indent=4)
            f.write("\n")

    return changed


def main():
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
