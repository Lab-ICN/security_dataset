#!/usr/bin/env python3
"""modsec_json_to_columns.py

Transform the *intermediate* JSON you showed (one object per transaction with
`sections` strings) into a fully‑flattened **CSV/TSV/JSON** table.  Besides the
standard request/response headers it also:

• parses the *URL* → separate `uri_path` and **one column per query parameter**
  (`param_page`, `param_size`, …).
• explodes **Cookie** and **Set‑Cookie** headers → individual `req_cookie_*` and
  `resp_cookie_*` columns.
• extracts rule IDs, severities and messages from the audit‑messages block.
• preserves every remaining header under a predictable prefix (`req_` or
  `resp_`).

The script is streaming and pure‑stdlib.  Usage examples:

```bash
# Convert JSON array → CSV
python modsec_json_to_columns.py audit.json --csv > audit.csv

# Same but TSV
python modsec_json_to_columns.py audit.json --tsv > audit.tsv

# Read from stdin and pretty‑print expanded JSON
cat audit.json | python modsec_json_to_columns.py --json | jq '.[0]'
```
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import urllib.parse as ul
from datetime import datetime
from pathlib import Path
from typing import Dict, Iterable, List

# ---------------------------------------------------------------------------
#  Regex helpers
# ---------------------------------------------------------------------------
REQUEST_LINE_RX = re.compile(r"^(?P<method>[A-Z]+) (?P<uri>\S+) HTTP/(?P<http_version>[0-9.]+)$")
STATUS_LINE_RX = re.compile(r"^HTTP/(?P<http_ver>[0-9.]+) (?P<status>[0-9]{3})")
RULE_RX = re.compile(r"\[id \"(?P<id>[0-9]+)\"].*?\[msg \"(?P<msg>[^\"]+)\"]", re.DOTALL)
HDR_A_RX = re.compile(r"\[(?P<ts>[^\]]+)\] (?P<unique>[\S]+) (?P<remote_ip>[\S]+) (?P<remote_port>[\S]+) (?P<local_ip>[\S]+) (?P<local_port>[\S]+)")
COOKIE_PAIR_RX = re.compile(r"\s*([^=\s]+)=([^;]+)")

# ---------------------------------------------------------------------------
#  Parsing helpers
# ---------------------------------------------------------------------------

def parse_header_block(block: str, prefix: str):
    """Return (start_line, headers_dict)."""
    lines = block.split("\n") if block else []
    if not lines:
        return "", {}
    start = lines[0]
    hdrs: Dict[str, str] = {}
    for l in lines[1:]:
        if ":" not in l:
            continue
        k, v = l.split(":", 1)
        hdrs[f"{prefix}{k.strip().lower().replace('-', '_')}"] = v.strip()
    return start, hdrs


def parse_cookies(cookie_header: str, col_prefix: str):
    """Return a dict of cookie_name → value with `col_prefix`."""
    out = {}
    if not cookie_header:
        return out
    for match in COOKIE_PAIR_RX.finditer(cookie_header):
        name, val = match.group(1, 2)
        out[f"{col_prefix}{name}"] = val
    return out


def extract_params(uri: str):
    out = {}
    parsed = ul.urlparse(uri)
    for k, vlist in ul.parse_qs(parsed.query).items():
        # Only keep first value if repeated
        out[f"param_{k}"] = vlist[0]
    out["uri_path"] = parsed.path
    return out


def parse_rule_block(hblock: str):
    ids, msgs = [], []
    for m in RULE_RX.finditer(hblock):
        ids.append(m.group("id"))
        msgs.append(m.group("msg"))
    return {
        "rule_ids": ",".join(sorted(set(ids))),
        "rule_msgs": " | ".join(msgs[:5])  # truncate long lists
    }

# ---------------------------------------------------------------------------
#  Main row‑expander
# ---------------------------------------------------------------------------

def expand_tx(tx: Dict) -> Dict[str, str]:
    row: Dict[str, str] = {"id": tx["id"]}
    sec = tx["sections"]

    # Section A — audit header
    if hdr := sec.get("A-audit_header"):
        m = HDR_A_RX.match(hdr)
        if m:
            row.update(
                timestamp=m.group("ts"),
                unique_txn=m.group("unique"),
                remote_ip=m.group("remote_ip"),
                remote_port=m.group("remote_port"),
                local_ip=m.group("local_ip"),
                local_port=m.group("local_port"),
            )
    # Section B — request
    req_line, req_hdrs = parse_header_block(sec.get("B-request_headers", ""), "req_")
    row.update(req_hdrs)
    if req_line:
        m = REQUEST_LINE_RX.match(req_line)
        if m:
            row.update(method=m.group("method"), http_version=m.group("http_version"))
            uri = m.group("uri")
            row["uri"] = uri
            row.update(extract_params(uri))
    # Request cookies
    row.update(parse_cookies(row.get("req_cookie", ""), "req_cookie_"))

    # Section F — response
    resp_line, resp_hdrs = parse_header_block(sec.get("F-response_headers", ""), "resp_")
    row.update(resp_hdrs)
    if resp_line:
        m = STATUS_LINE_RX.match(resp_line)
        if m:
            row.update(status_code=m.group("status"), resp_http_version=m.group("http_ver"))
    # Response cookies (may be multiple Set-Cookie lines); combine
    set_cookie_join = row.get("resp_set_cookie", "")
    row.update(parse_cookies(set_cookie_join, "resp_cookie_"))

    # Section H — audit messages
    if hblock := sec.get("H-audit_messages"):
        row.update(parse_rule_block(hblock))

    return row

# ---------------------------------------------------------------------------
#  Output helpers
# ---------------------------------------------------------------------------

def emit(rows: Iterable[Dict[str, str]], fmt: str):
    rows = list(rows)
    if fmt == "json":
        json.dump(rows, sys.stdout, indent=2)
        sys.stdout.write("\n")
    else:
        fieldnames = sorted({k for r in rows for k in r.keys()})
        dialect = {"csv": "excel", "tsv": "excel-tab"}[fmt]
        writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames, dialect=dialect)
        writer.writeheader()
        for r in rows:
            writer.writerow(r)

# ---------------------------------------------------------------------------
#  CLI
# ---------------------------------------------------------------------------

def main(argv: List[str] | None = None):
    p = argparse.ArgumentParser(description="Flatten ModSecurity JSON array → columns")
    p.add_argument("infile", nargs="?", type=Path, help="audit.json (default STDIN)")
    g = p.add_mutually_exclusive_group()
    g.add_argument("--csv", action="store_true")
    g.add_argument("--tsv", action="store_true")
    g.add_argument("--json", action="store_true")
    args = p.parse_args(argv)

    fmt = "json" if args.json else ("tsv" if args.tsv else "csv")

    with (args.infile.open("r", encoding="utf-8") if args.infile else sys.stdin) as fh:
        data = json.load(fh)
        rows = (expand_tx(tx) for tx in data)
        emit(rows, fmt)


if __name__ == "__main__":
    main()

