"""MemTrainer Kommandozeile – Claude-Schnittstelle (fuer ToolHub/MCP). Alle Ausgaben sind JSON.

Beispiele:
  python cli.py processes --windows
  python cli.py scan --process game.exe --type "4 Bytes" --mode "Exakter Wert" --value 1500 --new
  python cli.py scan --process game.exe --mode "Erhöht um" --value 50
  python cli.py read --process game.exe --expr "game.exe+1A2B" --type "4 Bytes"
  python cli.py write --process game.exe --expr 7FF6A1B2C3D0 --type "4 Bytes" --value 99999 --dry-run
  python cli.py speed --process game.exe --factor 2
"""
import argparse
import json
import os
import struct
import sys
import tempfile

import numpy as np

import aob
from scanner_core import (FIRST_MODES, NEEDS_V1, NEXT_MODES, TYPES, Process, Scanner, fmt_value,
                          list_processes, parse_value, window_titles)
from trainer_core import resolve_expr

STATE_DIR = os.path.join(tempfile.gettempdir(), "memtrainer")


class CliError(Exception):
    pass


def out(obj):
    sys.stdout.write(json.dumps(obj, ensure_ascii=False, indent=1) + "\n")


def open_process(spec):
    procs = list_processes()
    if spec.isdigit():
        match = [p for p in procs if p[0] == int(spec)]
    else:
        match = [p for p in procs if p[1].lower() == spec.lower()]
    if not match:
        raise CliError(f"Prozess '{spec}' läuft nicht.")
    pid, name = match[0]
    try:
        return Process(pid, name)
    except OSError as e:
        raise CliError(str(e)) from e


def need_type(t):
    if t not in TYPES:
        raise CliError(f"Unbekannter Typ '{t}'. Erlaubt: {', '.join(TYPES)}")
    return TYPES[t]


def addr_of(proc, expr):
    a = resolve_expr(proc, expr)
    if a is None:
        raise CliError(f"Adresse '{expr}' ist ungültig oder ein Zeiger ist nicht lesbar.")
    return a


# ---------------------------------------------------------------- Befehle
def cmd_processes(a):
    titles = window_titles()
    rows = [{"pid": pid, "name": n, "window": titles.get(pid, "")} for pid, n in list_processes()]
    if a.windows:
        rows = [r for r in rows if r["window"]]
    if a.filter:
        f = a.filter.lower()
        rows = [r for r in rows if f in r["name"].lower() or f in r["window"].lower()]
    out({"count": len(rows), "processes": rows})


def cmd_read(a):
    p = open_process(a.process)
    addr = addr_of(p, a.expr)
    v = p.read_value(addr, need_type(a.type))
    if v is None:
        raise CliError("Adresse nicht lesbar.")
    out({"process": p.name, "expr": a.expr, "address": p.fmt_addr(addr), "type": a.type, "value": fmt_value(v)})


def cmd_write(a):
    p = open_process(a.process)
    dt = need_type(a.type)
    addr = addr_of(p, a.expr)
    try:
        v = parse_value(a.value, dt)[0]
    except ValueError as e:
        raise CliError(str(e)) from e
    old = p.read_value(addr, dt)
    res = {"process": p.name, "address": p.fmt_addr(addr), "type": a.type,
           "old": None if old is None else fmt_value(old), "new": fmt_value(v)}
    if a.dry_run:
        out(res | {"dry_run": True})
        return
    if not p.write_value(addr, dt, v):
        raise CliError("Schreiben fehlgeschlagen.")
    out(res | {"written": True, "now": fmt_value(p.read_value(addr, dt))})


def _state_path(p):
    return os.path.join(STATE_DIR, f"scan_{p.pid}.npz")


def _save_scan(p, sc):
    os.makedirs(STATE_DIR, exist_ok=True)
    arrays = {"_meta": np.array([json.dumps({"type": sc.type_name, "scans": sc.scans, "pid": p.pid})])}
    for i, (base, (idx, prev)) in enumerate(sorted(sc.blocks.items())):
        arrays[f"b{i}_base"] = np.array([base], np.uint64)
        arrays[f"b{i}_idx"] = idx
        arrays[f"b{i}_prev"] = prev
    np.savez(_state_path(p), **arrays)


def _load_scan(p):
    path = _state_path(p)
    if not os.path.exists(path):
        return None
    d = np.load(path)
    meta = json.loads(str(d["_meta"][0]))
    sc = Scanner(p, meta["type"])
    sc.scans = meta["scans"]
    i = 0
    while f"b{i}_base" in d:
        sc.blocks[int(d[f"b{i}_base"][0])] = (d[f"b{i}_idx"], d[f"b{i}_prev"])
        i += 1
    return sc


def cmd_scan(a):
    p = open_process(a.process)
    sc = None if a.new else _load_scan(p)
    first = sc is None
    if first and not a.type:
        raise CliError("Für einen neuen Scan --type angeben.")
    if not first and a.type and a.type != sc.type_name:
        raise CliError(f"Laufender Scan hat Typ '{sc.type_name}'. Für einen anderen Typ --new verwenden.")
    modes = FIRST_MODES if first else NEXT_MODES
    if a.mode not in modes or a.mode == "Unbekannter Startwert":
        allowed = [m for m in modes if m != "Unbekannter Startwert"]
        raise CliError(f"Scan-Art '{a.mode}' hier nicht möglich. Erlaubt: {', '.join(allowed)}")
    if first:
        sc = Scanner(p, a.type)
    v1 = v2 = None
    tol = 0
    try:
        if a.mode in NEEDS_V1:
            if a.value is None:
                raise CliError("--value fehlt.")
            v1, tol = parse_value(a.value, sc.dtype)
        if a.mode == "Zwischen":
            if a.value2 is None:
                raise CliError("--value2 fehlt.")
            v2, t2 = parse_value(a.value2, sc.dtype)
            tol = max(tol, t2)
    except ValueError as e:
        raise CliError(str(e)) from e
    (sc.first_scan if first else sc.next_scan)(a.mode, v1, v2, tol)
    _save_scan(p, sc)
    rows = sc.results(a.limit)
    cur = [p.read_value(addr, sc.dtype) for addr, _ in rows]
    out({"process": p.name, "scan": sc.scans, "type": sc.type_name, "count": sc.count(),
         "results": [{"address": p.fmt_addr(addr), "value": "??" if c is None else fmt_value(c)}
                     for (addr, _), c in zip(rows, cur)],
         "hint": "Wert im Spiel ändern und erneut 'scan' (ohne --new) aufrufen, bis wenige Treffer übrig sind."})


def cmd_aob(a):
    p = open_process(a.process)
    try:
        hits = aob.scan_aob(p, a.pattern, a.module or None, limit=a.limit)
    except ValueError as e:
        raise CliError(str(e)) from e
    out({"process": p.name, "pattern": a.pattern, "count": len(hits), "addresses": [p.fmt_addr(h) for h in hits]})


def cmd_text(a):
    p = open_process(a.process)
    hits = aob.scan_text(p, a.text, utf16=a.utf16, limit=a.limit)
    out({"process": p.name, "text": a.text, "count": len(hits), "addresses": [p.fmt_addr(h) for h in hits]})


def cmd_speed(a):
    from speedhack import SPEED, SpeedHack
    p = open_process(a.process)
    path = os.path.join(STATE_DIR, f"speed_{p.pid}.json")
    if a.dry_run:
        out({"process": p.name, "factor": a.factor, "dry_run": True})
        return
    data = None
    if os.path.exists(path):  # Speedhack ist schon im Spiel -> nur Faktor aendern
        with open(path, encoding="utf-8") as f:
            data = json.load(f)["data"]
        if p.read_bytes(data + SPEED, 8) is None:
            data = None
    if data is None:
        try:
            data = SpeedHack(p).data
        except RuntimeError as e:
            raise CliError(str(e)) from e
        os.makedirs(STATE_DIR, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"data": data}, f)
    p.write_bytes(data + SPEED, struct.pack("<d", float(a.factor)))
    out({"process": p.name, "factor": a.factor, "active": True,
         "note": "Später geladene Spiel-Module werden nur mit offener GUI/Trainer nachträglich erfasst."})


def cmd_table(a):
    from trainer_core import CheatRunner, table_from_json
    with open(a.file, encoding="utf-8") as f:
        t = table_from_json(json.load(f))
    proc_name = a.process or t["process"]
    p = open_process(proc_name) if proc_name else None
    r = CheatRunner(p) if p else None
    out({"title": t["title"], "process": t["process"],
         "entries": [{"desc": e["desc"], "expr": e["expr"], "type": e["type"], "group": e["group"],
                      "hotkey": e["hotkey"], "value": r.display(e) if r else None} for e in t["entries"]]})


def main(argv=None):
    ap = argparse.ArgumentParser(prog="memtrainer", description="MemTrainer CLI (JSON-Ausgabe)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("processes")
    s.add_argument("--filter")
    s.add_argument("--windows", action="store_true")
    s.set_defaults(fn=cmd_processes)

    for name, fn in (("read", cmd_read), ("write", cmd_write)):
        s = sub.add_parser(name)
        s.add_argument("--process", required=True)
        s.add_argument("--expr", required=True)
        s.add_argument("--type", default="4 Bytes")
        if name == "write":
            s.add_argument("--value", required=True)
            s.add_argument("--dry-run", action="store_true")
        s.set_defaults(fn=fn)

    s = sub.add_parser("scan")
    s.add_argument("--process", required=True)
    s.add_argument("--type")
    s.add_argument("--mode", default="Exakter Wert")
    s.add_argument("--value")
    s.add_argument("--value2")
    s.add_argument("--new", action="store_true")
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(fn=cmd_scan)

    s = sub.add_parser("aob")
    s.add_argument("--process", required=True)
    s.add_argument("--pattern", required=True)
    s.add_argument("--module")
    s.add_argument("--limit", type=int, default=100)
    s.set_defaults(fn=cmd_aob)

    s = sub.add_parser("text")
    s.add_argument("--process", required=True)
    s.add_argument("--text", required=True)
    s.add_argument("--utf16", action="store_true")
    s.add_argument("--limit", type=int, default=100)
    s.set_defaults(fn=cmd_text)

    s = sub.add_parser("speed")
    s.add_argument("--process", required=True)
    s.add_argument("--factor", type=float, required=True)
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_speed)

    s = sub.add_parser("table")
    s.add_argument("--file", required=True)
    s.add_argument("--process")
    s.set_defaults(fn=cmd_table)

    a = ap.parse_args(argv)
    try:
        a.fn(a)
    except CliError as e:
        sys.stderr.write(json.dumps({"error": str(e)}, ensure_ascii=False) + "\n")
        return 1
    return 0


if __name__ == "__main__":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    sys.exit(main())
