#!/usr/bin/env python3
"""modsec_to_columns.py  – *fixed field order*

This revision corrects the mapping of *remote/local IP/port* fields that appear
in section **A** of a ModSecurity audit entry.  The previous version was off by
one token because the timestamp contains a space before the timezone
("+0000]").  We now use a dedicated regex to grab the five elements that follow
that timestamp reliably:

    [timestamp +tz]  TXN_ID  REMOTE_IP  REMOTE_PORT  LOCAL_IP  LOCAL_PORT

All other behaviour (dynamic header columns, CSV/TSV/JSON output) is unchanged.
"""
from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from pathlib import Path
from typing import Dict, Iterable, List, TextIO

# ---------------------------------------------------------------------------
#  Regex helpers (updated)
# ---------------------------------------------------------------------------
BOUNDARY_RX = re.compile(r"^---(?P<id>[A-Za-z0-9]+)---(?P<section>[A-Z])--$")

# Map section letters to friendly names (subset used here)
SECTION_RX = {
    "A": "audit_header",
    "B": "request_headers",
    "F": "response_headers",
    "H": "audit_messages",
}

TIMESTAMP_RX = re.compile(r"\[(?P<ts>[^\]]+)\]")
# Capture the five tokens *after* the timestamp+timezone
HDR_A_RX = re.compile(r"\[[^\]]+\]\s+(?P<txn>\S+)\s+(?P<remote_ip>\S+)\s+(?P<remote_port>\S+)\s+(?P<local_ip>\S+)\s+(?P<local_port>\S+)")
REQUEST_LINE_RX = re.compile(r"^(?P<meth>[A-Z]+) (?P<uri>\S+) HTTP/(?P<ver>[0-9.]+)$")
STATUS_LINE_RX = re.compile(r"^HTTP/[0-9.]+ (?P<code>[0-9]{3})")
RULE_ID_RX = re.compile(r"\[id \"(?P<id>[0-9]+)\"\]")

# ---------------------------------------------------------------------------
#  Section splitter
# ---------------------------------------------------------------------------

def iter_sections(stream: TextIO):
    cur_id: str | None = None
    cur_sec: str | None = None
    buf: List[str] = []
    for raw in stream:
        line = raw.rstrip("\n")
        m = BOUNDARY_RX.match(line)
        if m:
            if cur_id and cur_sec is not None:
                yield cur_id, cur_sec, "\n".join(buf).rstrip()
            cur_id, cur_sec, buf = m.group("id"), m.group("section"), []
        else:
            buf.append(line)
    if cur_id and cur_sec is not None and buf:
        yield cur_id, cur_sec, "\n".join(buf).rstrip()

# ---------------------------------------------------------------------------
#  Transaction assembler
# ---------------------------------------------------------------------------

def build_transactions(stream: TextIO):
    tx: Dict[str, Dict[str, str]] = {}
    for _id, sec, body in iter_sections(stream):
        entry = tx.setdefault(_id, {"id": _id})
        entry[SECTION_RX.get(sec, sec)] = body
    return tx.values()

# ---------------------------------------------------------------------------
#  Field extractors (fixed audit header)
# ---------------------------------------------------------------------------

def parse_audit_header(text: str):
    out: Dict[str, str] = {}
    ts_match = TIMESTAMP_RX.search(text)
    if ts_match:
        out["timestamp"] = ts_match.group("ts")
    hdr_match = HDR_A_RX.match(text)
    if hdr_match:
        out.update(
            remote_ip=hdr_match.group("remote_ip"),
            remote_port=hdr_match.group("remote_port"),
            local_ip=hdr_match.group("local_ip"),
            local_port=hdr_match.group("local_port"),
            txn_id=hdr_match.group("txn"),
        )
    return out


def parse_headers_block(text: str, prefix: str):
    lines = text.split("\n")
    first = lines[0]

def extract_rule_ids(text: str):
    return ",".join(sorted({m.group("id") for m in RULE_ID_RX.finditer(text)})) if text else ""


def explode_transaction(tx: Dict[str, str]):
    row = {"id": tx["id"]}
    # A — header
    if hdr := tx.get("audit_header"):
        row.update(parse_audit_header(hdr))
    # B — request
    first_req = ""
    if req := tx.get("request_headers"):
        first_req, req_hdrs = parse_headers_block(req, "req_")
        row.update(req_hdrs)
        if m := REQUEST_LINE_RX.match(first_req):
            row.update(method=m.group("meth"), uri=m.group("uri"), http_version=m.group("ver"))
    # F — response
    first_resp = ""
    if resp := tx.get("response_headers"):
        first_resp, resp_hdrs = parse_headers_block(resp, "resp_")
        row.update(resp_hdrs)
        if m := STATUS_LINE_RX.match(first_resp):
            row["status_code"] = m.group("code")
    # H — rule hits
    if msgs := tx.get("audit_messages"):
        row["rule_ids"] = extract_rule_ids(msgs)
    return row

# ---------------------------------------------------------------------------
#  Output helpers
# ---------------------------------------------------------------------------

def emit_csv(rows: Iterable[Dict[str, str]], tsv: bool = False):
    rows = list(rows)
    fieldnames = sorted({k for r in rows for k in r.keys()})
    writer = csv.DictWriter(sys.stdout, fieldnames=fieldnames, dialect=("excel-tab" if tsv else "excel"))
    writer.writeheader()
    for r in rows:
        writer.writerow(r)


def emit_json(rows: Iterable[Dict[str, str]]):
    json.dump(list(rows), sys.stdout, indent=2)
    sys.stdout.write("\n")

# ---------------------------------------------------------------------------
#  CLI
# ---------------------------------------------------------------------------

def main(argv: List[str] | None = None):
    p = argparse.ArgumentParser(description="ModSecurity audit → CSV/TSV/JSON (fixed field order)")
    p.add_argument("logfile", nargs="?", type=Path)
    g = p.add_mutually_exclusive_group()
    g.add_argument("--csv", action="store_true", help="CSV output (default)")
    g.add_argument("--tsv", action="store_true", help="TSV output")
    g.add_argument("--json", action="store_true", help="JSON output")
    args = p.parse_args(argv)

    with (args.logfile.open("r", encoding="utf-8", errors="replace") if args.logfile else sys.stdin) as fh:
        rows = (explode_transaction(tx) for tx in build_transactions(fh))
        if args.json:
            emit_json(rows)
        else:
            emit_csv(rows, tsv=args.tsv)


if __name__ == "__main__":
    main()

