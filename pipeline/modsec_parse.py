#!/usr/bin/env python3
"""parse_modsecurity_logs.py (named‑sections version)
Usage
-----
```bash
python parse_modsecurity_logs.py /var/log/nginx/audit.log --pretty > audit.json
```
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Dict, List, TextIO

#  Section mapping
SECTION_NAMES: dict[str, str] = {
    "A": "A-audit_header",        # connection info / timestamp
    "B": "B-request_headers",     # inbound request headers
    "C": "C-request_body",        # request body (if present)
    "D": "D-intermediate_body",   # (rarely used)
    "E": "E-response_body",       # outbound response body
    "F": "F-response_headers",    # outbound response headers
    "G": "G-reserved",            # (unused, kept for spec completeness)
    "H": "H-audit_messages",      # rule hits, warnings, anomalies
    "I": "I-additional_data",     # extra debug / data
    "J": "J-trailer",             # summary trailer
    "K": "K-origin_request",      # origin request headers (if proxy)
    "Z": "Z-postlude",            # final boundary / closing marker
}

# Example boundary line:  "---s8lLQJCk---B--"
BOUNDARY_RX = re.compile(r"^---(?P<id>[A-Za-z0-9]+)---(?P<section>[A-Z])--$")


#  Core parser helpers

def parse_audit_stream(stream: TextIO):
    """Yield *(id, section_letter, content)* for each block in *stream*."""
    current_lines: List[str] = []
    current_id: str | None = None
    current_section: str | None = None

    for raw in stream:
        line = raw.rstrip("\n")
        m = BOUNDARY_RX.match(line)
        if m:
            # Emit the previous section before starting the next one
            if current_id is not None and current_section is not None:
                yield current_id, current_section, "\n".join(current_lines).rstrip()
            # Reset state for the new boundary
            current_id = m.group("id")
            current_section = m.group("section")
            current_lines = []
        else:
            current_lines.append(line)

    # Emit the tail section if the file ended without a closing boundary
    if current_id is not None and current_section is not None and current_lines:
        yield current_id, current_section, "\n".join(current_lines).rstrip()


def build_transactions(stream: TextIO):
    """Return a list of transaction dictionaries with *named* sections."""
    txns: Dict[str, Dict[str, str]] = {}

    for _id, letter, content in parse_audit_stream(stream):
        # Use a friendly name when available, else the raw letter
        name = SECTION_NAMES.get(letter, letter)
        txn = txns.setdefault(_id, {"id": _id, "sections": {}})

        # Concatenate duplicate sections (e.g. multiple H blocks)
        sections = txn["sections"]
        if name in sections and content:
            sections[name] += "\n\n" + content
        else:
            sections[name] = content

    # Preserve the order of first appearance in the log
    return list(txns.values())


#  CLI

def main(argv: List[str] | None = None):
    parser = argparse.ArgumentParser(description="Parse ModSecurity audit logs → JSON with named sections")
    parser.add_argument("logfile", nargs="?", type=Path, help="Path to audit log (default: STDIN)")
    parser.add_argument("--pretty", action="store_true", help="Pretty‑print JSON with indentation")
    args = parser.parse_args(argv)

    with (args.logfile.open("r", encoding="utf-8", errors="replace") if args.logfile else sys.stdin) as fh:
        result = build_transactions(fh)

    json.dump(result, sys.stdout, indent=2 if args.pretty else None)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()

