"""MemTrainer Kommandozeile – Claude-Schnittstelle (fuer ToolHub/MCP). Alle Ausgaben sind JSON.

Beispiele:
  python cli.py processes --windows
  python cli.py scan --process game.exe --type "4 Bytes" --mode "Exakter Wert" --value 1500 --new
  python cli.py scan --process game.exe --mode "Erhöht um" --value 50
  python cli.py read --process game.exe --expr "game.exe+1A2B" --type "4 Bytes"
  python cli.py write --process game.exe --expr 7FF6A1B2C3D0 --type "4 Bytes" --value 99999 --dry-run
  python cli.py speed --process game.exe --factor 2
  python cli.py scan --process game.exe --type "Alle Zahlentypen" --value 336,7 --new
  python cli.py monitor --process game.exe --expr 7FF6A1B2C3D0 --type Float --seconds 5
  python cli.py unity-search --process game.exe --query coins
  python cli.py unity-objects --process game.exe --class PlayerOptionsData --field Coins
  python cli.py read --process game.exe --expr "unity:GameManager::_mainCharacters[0]._currentHp" --type Float
  python cli.py unity-path --process game.exe --class PlayerOptionsData --field Coins
  python cli.py unity-methods --process game.exe --class GameManager --query rosary
  python cli.py unity-call --process game.exe --call "GameManager::RosaryDamage(true, 1.8)" --dry-run
"""
import argparse
import json
import os
import struct
import sys
import tempfile

import numpy as np

import aob
from scanner_core import (FIRST_MODES, MULTI, NEEDS_V1, NEXT_MODES, TYPES, MultiScanner, Process, Scanner,
                          fmt_value, list_processes, parse_value, window_titles)
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


_UNITY = {}


def addr_of(proc, expr):
    if str(expr).startswith("unity:"):
        u = _UNITY.get(proc.pid) or _unity(proc)
        _UNITY[proc.pid] = u
        try:
            a = u.resolve_path(expr[6:])[0]
        except Exception as e:  # noqa: BLE001
            raise CliError(f"Unity-Pfad: {e}") from e
        finally:
            u.close_hook()
    else:
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


def _subs(sc):
    return sc.subs if isinstance(sc, MultiScanner) else [sc]


def _save_scan(p, sc):
    os.makedirs(STATE_DIR, exist_ok=True)
    meta = {"type": sc.type_name, "scans": sc.scans, "pid": p.pid,
            "subs": [{"type": s.type_name, "scale": s.scale} for s in _subs(sc)]}
    arrays = {"_meta": np.array([json.dumps(meta)])}
    for j, s in enumerate(_subs(sc)):
        for i, (base, (idx, prev)) in enumerate(sorted(s.blocks.items())):
            arrays[f"s{j}_b{i}_base"] = np.array([base], np.uint64)
            arrays[f"s{j}_b{i}_idx"] = idx
            arrays[f"s{j}_b{i}_prev"] = prev
    np.savez(_state_path(p), **arrays)


def _load_scan(p):
    path = _state_path(p)
    if not os.path.exists(path):
        return None
    d = np.load(path)
    meta = json.loads(str(d["_meta"][0]))
    subs = meta.get("subs") or [{"type": meta["type"], "scale": 1}]
    if meta["type"] == MULTI:
        sc = MultiScanner(p, combos=[(x["type"], x["scale"]) for x in subs])
    else:
        sc = Scanner(p, meta["type"])
    sc.scans = meta["scans"]
    for j, s in enumerate(_subs(sc)):
        s.scans = meta["scans"]
        i = 0
        while f"s{j}_b{i}_base" in d:
            s.blocks[int(d[f"s{j}_b{i}_base"][0])] = (d[f"s{j}_b{i}_idx"], d[f"s{j}_b{i}_prev"])
            i += 1
        if j == 0 and not i and "b0_base" in d:  # alte Zustandsdatei
            while f"b{i}_base" in d:
                s.blocks[int(d[f"b{i}_base"][0])] = (d[f"b{i}_idx"], d[f"b{i}_prev"])
                i += 1
    return sc


def _scan_out(p, sc, limit, hint):
    rows = sc.rows(limit)
    res = []
    for addr, s, _ in rows:
        c = p.read_value(addr, s.dtype)
        res.append({"address": p.fmt_addr(addr), "type": s.type_name,
                    **({"scale": s.scale} if s.scale != 1 else {}),
                    "value": "??" if c is None else fmt_value(s.display(c))})
    by_type = sc.by_type() if isinstance(sc, MultiScanner) else None
    out({"process": p.name, "scan": sc.scans, "type": sc.type_name, "count": sc.count(),
         **({"by_type": by_type} if by_type else {}), "results": res, "hint": hint})


def cmd_scan(a):
    p = open_process(a.process)
    sc = None if a.new else _load_scan(p)
    first = sc is None
    if first and not a.type:
        a.type = MULTI
    if first and a.type != MULTI and a.type not in TYPES:
        raise CliError(f"Unbekannter Typ '{a.type}'. Erlaubt: {MULTI}, {', '.join(TYPES)}")
    if not first and a.type and a.type != sc.type_name:
        raise CliError(f"Laufender Scan hat Typ '{sc.type_name}'. Für einen anderen Typ --new verwenden.")
    modes = FIRST_MODES if first else NEXT_MODES
    if a.mode not in modes or a.mode == "Unbekannter Startwert":
        allowed = [m for m in modes if m != "Unbekannter Startwert"]
        raise CliError(f"Scan-Art '{a.mode}' hier nicht möglich. Erlaubt: {', '.join(allowed)}")
    if a.mode in NEEDS_V1 and a.value is None:
        raise CliError("--value fehlt.")
    if a.mode == "Zwischen" and a.value2 is None:
        raise CliError("--value2 fehlt.")
    if first:
        sc = MultiScanner(p) if a.type == MULTI else Scanner(p, a.type)
    try:
        sc.scan(first, a.mode, a.value or "", a.value2 or "")
    except ValueError as e:
        raise CliError(str(e)) from e
    _save_scan(p, sc)
    _scan_out(p, sc, a.limit, "Wert im Spiel ändern und erneut 'scan' (ohne new) aufrufen, bis wenige Treffer übrig "
                              "sind. Viele Treffer, die sich von selbst ändern? 'noise' aufrufen, während der Spieler "
                              "nichts tut.")


def cmd_noise(a):
    p = open_process(a.process)
    sc = _load_scan(p)
    if sc is None:
        raise CliError("Kein laufender Scan – zuerst 'scan' mit new.")
    sc.filter_noise(a.seconds)
    _save_scan(p, sc)
    _scan_out(p, sc, a.limit, "Entfernt: alles, was sich ohne Zutun geändert hat. Jetzt Wert im Spiel ändern und "
                              "'scan' mit 'Erhöht'/'Verringert' aufrufen.")


def cmd_monitor(a):
    """Adressen einige Sekunden beobachten und Änderungen melden (live)."""
    import time
    p = open_process(a.process)
    dt = need_type(a.type)
    addrs = [(e, addr_of(p, e)) for e in a.expr]
    hist = {e: [] for e, _ in addrs}
    end = time.time() + a.seconds
    t0 = time.time()
    while time.time() < end:
        for e, ad in addrs:
            v = p.read_value(ad, dt)
            h = hist[e]
            if not h or h[-1][1] != v:
                h.append((round(time.time() - t0, 2), v))
        time.sleep(a.interval)
    out({"process": p.name, "type": a.type, "seconds": a.seconds,
         "values": {e: {"changes": max(0, len(h) - 1), "now": fmt_value(h[-1][1]) if h and h[-1][1] is not None else "??",
                        "history": [{"t": t, "v": "??" if v is None else fmt_value(v)} for t, v in h[-30:]]}
                    for e, h in hist.items()}})


def cmd_struct(a):
    """Speicher um eine Adresse als Felder; bei Unity mit Feldnamen."""
    p = open_process(a.process)
    base = addr_of(p, a.expr)
    data = p.read_bytes(base, a.size)
    if data is None:
        raise CliError("Adresse nicht lesbar.")
    names = {}
    if a.unity:
        import unity
        u = unity.UnityRuntime(p).load()
        head = p.read_ptr(base)
        cls = u.by_ptr.get(head)
        c, depth = cls, 0
        while c is not None and depth < 16:
            for f in c.fields:
                if not f.static:
                    names.setdefault(f.offset, f"{f.name.replace('k__BackingField', '').strip('<>')} ({f.short_type()})")
            c = u.by_ptr.get(c.parent)
            depth += 1
    rows = []
    for off in range(0, len(data) - 3, 4):
        i32, f32 = struct.unpack_from("<i", data, off)[0], struct.unpack_from("<f", data, off)[0]
        r = {"offset": f"+{off:X}", "int": i32, "float": fmt_value(f32) if 1e-6 < abs(f32) < 1e9 or f32 == 0 else None}
        if off % 8 == 0 and off + 8 <= len(data):
            q = struct.unpack_from("<Q", data, off)[0]
            if 0x10000 <= q < 0x7FFFFFFFFFFF and p.read_bytes(q, 1) is not None:
                r["pointer"] = p.fmt_addr(q)
        if off in names:
            r["field"] = names[off]
        rows.append(r)
    out({"process": p.name, "base": p.fmt_addr(base), "fields": rows})


def cmd_refs(a):
    import pointer_scan
    p = open_process(a.process)
    target = addr_of(p, a.expr)
    refs = pointer_scan.find_refs(p, target, int(a.max_offset, 16), limit=a.limit)
    out({"process": p.name, "target": p.fmt_addr(target),
         "refs": [{"at": p.fmt_addr(at), "offset": f"+{off:X}", "static": st,
                   "expr": f"[{p.fmt_addr(at)}]+{off:X}"} for at, off, st in refs],
         "hint": "static=true heißt: Zeiger liegt in einem Modul und bleibt nach Neustart gültig."})


def _debug_session(w, seconds):
    import time
    w.start()
    end = time.time() + seconds
    while time.time() < end and w.running:
        time.sleep(0.1)
    w.stop()
    w.join(5)


def cmd_writes(a):
    """Was schreibt/greift auf eine Adresse zu? (Hardware-Breakpoint für einige Sekunden)"""
    import debugger
    p = open_process(a.process)
    addr = addr_of(p, a.expr)
    if a.dry_run:
        out({"preview": f"Würde sich {a.seconds:g} s als Debugger an {p.name} anhängen und Zugriffe auf "
                        f"{p.fmt_addr(addr)} protokollieren. Währenddessen den Wert im Spiel ändern.",
             "risk": "Spiele mit Anti-Debug-Schutz können abstürzen."})
        return
    w = debugger.AccessWatcher(p, addr, a.size, "rw" if a.access else "w")
    _debug_session(w, a.seconds)
    if w.error:
        raise CliError(w.error)
    res = []
    for ip, n in w.hits.most_common(50):
        ins = debugger.find_instruction(p, ip)
        res.append({"instruction": p.fmt_addr(ins[0]) if ins else p.fmt_addr(ip), "count": n,
                    "code": ins[3] if ins else "?", "bytes": ins[2].hex(" ") if ins else ""})
    out({"process": p.name, "address": p.fmt_addr(addr), "instructions": res,
         "hint": "Leer? Wert im Spiel während der Messung ändern. Danach 'trace' mit der Befehlsadresse zeigt, welche "
                 "anderen Adressen derselbe Code benutzt."})


def cmd_trace(a):
    """Welche Adressen nutzt dieser Befehl? (Ausführungs-Breakpoint für einige Sekunden)"""
    import debugger
    p = open_process(a.process)
    addr = addr_of(p, a.expr)
    t = debugger.InstructionTracer(p, addr)
    if t.error:
        raise CliError(t.error)
    if a.dry_run:
        out({"preview": f"Würde sich {a.seconds:g} s als Debugger anhängen und bei jedem Ausführen von "
                        f"'{t.text}' ({p.fmt_addr(addr)}) die benutzte Adresse notieren.",
             "risk": "Spiele mit Anti-Debug-Schutz können abstürzen."})
        return
    _debug_session(t, a.seconds)
    if t.error:
        raise CliError(t.error)
    dt = np.int64 if t.op_size == 8 else np.int32
    out({"process": p.name, "instruction": f"{p.fmt_addr(addr)}  {t.text}",
         "addresses": [{"address": p.fmt_addr(x), "count": n, "int": p.read_value(x, dt),
                        "float": fmt_value(v) if (v := p.read_value(x, np.float32)) is not None else None}
                       for x, n in t.addresses.most_common(100)]})


def _unity(p):
    import unity
    try:
        return unity.UnityRuntime(p).load()
    except (unity.UnityError, unity.RemoteError) as e:
        raise CliError(str(e)) from e


def cmd_unity_search(a):
    p = open_process(a.process)
    u = _unity(p)
    res = u.search(a.query or "", numeric_only=not a.all_types, include_ui=a.ui, limit=a.limit)
    u.describe_types([f for f in res if f.tenum == 0x11])
    out({"process": p.name, "runtime": u.kind, "classes": len(u.classes),
         "fields": [{"class": f.cls.full, "field": f.name.replace("k__BackingField", "").strip("<>"),
                     "type": f.short_type(), "offset": f"+{f.offset:X}", "static": f.static} for f in res],
         "hint": "Mit 'unity-objects' (class + field) die Objekte samt aktuellem Wert und Adresse holen."})


def cmd_unity_objects(a):
    p = open_process(a.process)
    u = _unity(p)
    cls = u.find_class(a.cls)
    if not cls:
        raise CliError(f"Klasse '{a.cls}' nicht gefunden (Name mit oder ohne Namespace).")
    cls = cls[0]
    fname = a.field.lower()
    c, f, depth = cls, None, 0
    while c is not None and f is None and depth < 16:
        f = next((x for x in c.fields if x.name.replace("k__BackingField", "").strip("<>").lower() == fname), None)
        c = u.by_ptr.get(c.parent)
        depth += 1
    if f is None:
        raise CliError(f"Feld '{a.field}' gibt es in {cls.full} nicht.")
    sub = u.struct_fields(f) if f.tenum == 0x11 else None
    if sub:
        u.describe_types([f])
    if f.static:
        base = u.static_base(cls)
        objs = [("statisch", u.field_addr(f, None, base))] if base else []
    else:
        objs = [(p.fmt_addr(o), o + f.offset) for o in u.instances(cls, limit=a.limit)]
    out({"process": p.name, "class": cls.full, "field": f.name, "type": f.short_type(), "mem_type": f.mem_type,
         "objects": [{"object": o, "address": p.fmt_addr(ad), "value": u.read_field(ad, f, sub)} for o, ad in objs],
         "hint": "Mehrere Objekte = oft Kopien (alter Spielstand). Das echte ändert sich mit dem Spiel; mit 'monitor' "
                 "beobachten, mit 'write' (type=mem_type) ändern."})


def cmd_unity_methods(a):
    p = open_process(a.process)
    u = _unity(p)
    cls = u.find_class(a.cls)
    if not cls:
        raise CliError(f"Klasse '{a.cls}' nicht gefunden.")
    q = (a.query or "").lower()
    rows = []
    try:
        k, depth = cls[0], 0
        while k is not None and depth < (8 if a.inherited else 1):
            rows += [{"class": k.name, "signature": m.signature, "callable": m.callable}
                     for m in u.methods(k) if q in m.name.lower()]
            k, depth = u.by_ptr.get(k.parent), depth + 1
    except Exception as e:  # noqa: BLE001 - UnityError (z. B. Mono)
        raise CliError(str(e)) from e
    out({"process": p.name, "class": cls[0].full, "methods": rows[:a.limit],
         "hint": "Aufruf mit unity-call --call \"Klasse::Methode(arg1, arg2)\". Enum-Argument '*' = alle Werte, "
                 "'keys:feld.dict' = Schlüssel eines Dictionary (z. B. vorhandene Inhalte)."})


def cmd_unity_path(a):
    """Stabilen unity:-Pfad (ab statischem Feld) zu einem Feld finden; ohne --object: alle Objekte der Klasse."""
    p = open_process(a.process)
    u = _unity(p)
    cls = u.find_class(a.cls)
    if not cls:
        raise CliError(f"Klasse '{a.cls}' nicht gefunden.")
    cls = cls[0]
    f = u._field_of(cls.ptr, a.field)
    if f is None:
        raise CliError(f"Feld '{a.field}' gibt es in {cls.full} nicht.")
    objs = [int(a.object, 16)] if a.object else ([None] if f.static else u.instances(cls, limit=a.limit))
    rows = []
    for o in objs:
        paths = u.path_for_field(o, f)
        addr = u.field_addr(f, o, u.static_base(cls) if f.static else 0)
        rows.append({"object": p.fmt_addr(o) if o else "statisch", "value": u.read_field(addr, f) if addr else None,
                     "paths": paths})
    out({"process": p.name, "class": cls.full, "field": f.name, "mem_type": f.mem_type, "objects": rows,
         "hint": "Pfad als --expr für read/write/monitor nutzen oder in eine Tabelle eintragen; übersteht Neustarts. "
                 "Objekte ohne Pfad sind oft alte Kopien."})


def cmd_unity_call(a):
    import unity
    p = open_process(a.process)
    u = _unity(p)
    if a.dry_run:
        out({"process": p.name, "call": a.call, "dry_run": True,
             "hint": "Ruft eine Spiel-Methode im Hauptthread auf. Kann den Spielstand verändern."})
        return
    try:
        res = u.run_call(a.call, timeout=a.timeout)
    except (unity.UnityError, unity.RemoteError) as e:
        raise CliError(str(e)) from e
    finally:
        u.close_hook()
    out({"process": p.name, "call": a.call, "calls": len(res), "returns": [f"{r:X}" for r in res[:50]],
         "alive": p.alive()})


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

    s = sub.add_parser("noise")
    s.add_argument("--process", required=True)
    s.add_argument("--seconds", type=float, default=5.0)
    s.add_argument("--limit", type=int, default=50)
    s.set_defaults(fn=cmd_noise)

    s = sub.add_parser("monitor")
    s.add_argument("--process", required=True)
    s.add_argument("--expr", required=True, action="append")
    s.add_argument("--type", default="4 Bytes")
    s.add_argument("--seconds", type=float, default=5.0)
    s.add_argument("--interval", type=float, default=0.1)
    s.set_defaults(fn=cmd_monitor)

    s = sub.add_parser("struct")
    s.add_argument("--process", required=True)
    s.add_argument("--expr", required=True)
    s.add_argument("--size", type=lambda x: int(x, 0), default=0x100)
    s.add_argument("--unity", action="store_true")
    s.set_defaults(fn=cmd_struct)

    s = sub.add_parser("refs")
    s.add_argument("--process", required=True)
    s.add_argument("--expr", required=True)
    s.add_argument("--max-offset", default="400")
    s.add_argument("--limit", type=int, default=100)
    s.set_defaults(fn=cmd_refs)

    s = sub.add_parser("writes")
    s.add_argument("--process", required=True)
    s.add_argument("--expr", required=True)
    s.add_argument("--size", type=int, default=4)
    s.add_argument("--access", action="store_true")
    s.add_argument("--seconds", type=float, default=10.0)
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_writes)

    s = sub.add_parser("trace")
    s.add_argument("--process", required=True)
    s.add_argument("--expr", required=True)
    s.add_argument("--seconds", type=float, default=5.0)
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_trace)

    s = sub.add_parser("unity-search")
    s.add_argument("--process", required=True)
    s.add_argument("--query", default="")
    s.add_argument("--all-types", action="store_true")
    s.add_argument("--ui", action="store_true")
    s.add_argument("--limit", type=int, default=60)
    s.set_defaults(fn=cmd_unity_search)

    s = sub.add_parser("unity-objects")
    s.add_argument("--process", required=True)
    s.add_argument("--class", dest="cls", required=True)
    s.add_argument("--field", required=True)
    s.add_argument("--limit", type=int, default=20)
    s.set_defaults(fn=cmd_unity_objects)

    s = sub.add_parser("unity-methods")
    s.add_argument("--process", required=True)
    s.add_argument("--class", dest="cls", required=True)
    s.add_argument("--query", default="")
    s.add_argument("--inherited", action="store_true")
    s.add_argument("--limit", type=int, default=200)
    s.set_defaults(fn=cmd_unity_methods)

    s = sub.add_parser("unity-path")
    s.add_argument("--process", required=True)
    s.add_argument("--class", dest="cls", required=True)
    s.add_argument("--field", required=True)
    s.add_argument("--object")
    s.add_argument("--limit", type=int, default=6)
    s.set_defaults(fn=cmd_unity_path)

    s = sub.add_parser("unity-call")
    s.add_argument("--process", required=True)
    s.add_argument("--call", required=True)
    s.add_argument("--timeout", type=float, default=5.0)
    s.add_argument("--dry-run", action="store_true")
    s.set_defaults(fn=cmd_unity_call)

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
