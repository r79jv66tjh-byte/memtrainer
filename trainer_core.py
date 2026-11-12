"""Cheat-Eintraege: Adress-Ausdruecke, Einfrieren, Hotkey-Aktionen, Code-Patches.

Wird vom Scanner UND von exportierten Trainern benutzt.
Adress-Ausdruck-Syntax (wie Cheat Engine):
    7FF6A1B2C3D0                  absolute Adresse (hex)
    spiel.exe+1A2B                Modul + Offset
    [[spiel.exe+1A2B]+10]+48      Pointer-Kette ([x] = Zeiger an Adresse x lesen)
    "Mein Spiel.exe"+10           Modulnamen mit Leer-/Sonderzeichen in Anfuehrungszeichen
    unity:GameManager::_mainCharacters[0]._currentHp
                                  Unity-Pfad (lebendes Objekt -> Felder), uebersteht Neustarts
"""
import re

import numpy as np

import aob
from scanner_core import TYPES, fmt_value, parse_value

PATCH = "Code-Patch"
ALL_TYPES = list(TYPES) + [PATCH]
FREEZE_MODES = {"=": "Wert halten", ">=": "Nicht weniger werden", "<=": "Nicht mehr werden"}
HK_ACTIONS = {"toggle": "Ein/Aus", "set": "Wert setzen", "add": "Wert addieren"}

_TOKEN = re.compile(r'"[^"]*"|\[|\]|\+|-|[^\[\]+\-\s"]+')


def resolve_expr(proc, expr):
    """Ausdruck -> absolute Adresse oder None (z. B. wenn ein Zeiger ungueltig ist)."""
    toks = _TOKEN.findall(str(expr))
    pos = 0

    def peek():
        return toks[pos] if pos < len(toks) else None

    def take():
        nonlocal pos
        pos += 1
        return toks[pos - 1]

    def term():
        tok = take()
        if tok == "[":
            v = expression()
            if take() != "]":
                raise ValueError("']' fehlt")
            p = proc.read_ptr(v)
            if not p:
                raise LookupError("Zeiger ungültig")
            return p
        name = tok.strip('"')
        base = proc.module_base(name)
        if base is not None:
            return base
        return int(name, 16)

    def expression():
        v = term()
        while peek() in ("+", "-"):
            op = take()
            t = term()
            v = v + t if op == "+" else v - t
        return v

    try:
        v = expression()
        return v if pos == len(toks) else None
    except (ValueError, LookupError, IndexError, TypeError):
        return None


def new_entry(**kw):
    e = {"desc": "Neuer Eintrag", "expr": "", "type": "4 Bytes", "group": "",
         "active": False, "value": None, "mode": "=",
         "hotkey": "", "hk_action": "toggle", "hk_value": None,
         "orig": "", "new": "", "aob": "", "aob_module": "", "aob_offset": 0}
    e.update(kw)
    return e


class CheatRunner:
    """Wendet Eintraege auf einen Prozess an. Haelt nichts an GUI-Zustand."""

    def __init__(self, proc):
        self.proc = proc
        self._patch_addr = {}
        self.unity = None  # UnityRuntime für 'unity:'-Pfade (optional)

    def address(self, e):
        if e["type"] == PATCH:
            return self._patch_address(e)
        expr = str(e["expr"])
        if expr.startswith("unity:"):
            if self.unity is None:
                return None
            try:
                return self.unity.resolve_path(expr[6:], wait=False)[0]
            except Exception:  # noqa: BLE001 - ungültiger Pfad / Spiel im Ladebildschirm
                return None
        return resolve_expr(self.proc, expr)

    def _patch_address(self, e):
        key = id(e)
        addr = self._patch_addr.get(key)
        orig, new = bytes.fromhex(e["orig"]), bytes.fromhex(e["new"])
        if addr is not None:
            return addr
        cand = resolve_expr(self.proc, e["expr"])
        if cand is not None:
            cur = self.proc.read_bytes(cand, len(orig))
            if cur in (orig, new):
                self._patch_addr[key] = cand
                return cand
        if e.get("aob"):  # Spiel-Update? per Signatur neu suchen
            hits = aob.scan_aob(self.proc, e["aob"], e.get("aob_module") or None, limit=2)
            if len(hits) == 1:
                self._patch_addr[key] = hits[0] + int(e.get("aob_offset", 0))
                return self._patch_addr[key]
        return None

    def read(self, e):
        addr = self.address(e)
        if addr is None:
            return None
        if e["type"] == PATCH:
            cur = self.proc.read_bytes(addr, len(bytes.fromhex(e["new"])))
            return None if cur is None else (cur == bytes.fromhex(e["new"]))
        return self.proc.read_value(addr, TYPES[e["type"]])

    def display(self, e):
        v = self.read(e)
        if v is None:
            return "??"
        if e["type"] == PATCH:
            return "aktiv" if v else "aus"
        return fmt_value(v)

    def write(self, e, value):
        addr = self.address(e)
        return addr is not None and self.proc.write_value(addr, TYPES[e["type"]], value)

    def set_active(self, e, on, capture=True):
        """Einfrieren bzw. Patch an/aus. capture: aktuellen Wert als Einfrier-Wert merken."""
        if e["type"] == PATCH:
            addr = self.address(e)
            if addr is None:
                return False
            data = bytes.fromhex(e["new"] if on else e["orig"])
            if not self.proc.write_bytes(addr, data, code=True):
                return False
        elif on and (capture or e["value"] is None):
            v = self.read(e)
            if v is None:
                return False
            e["value"] = v
        e["active"] = on
        return True

    def hotkey(self, e):
        act = e.get("hk_action", "toggle")
        if act == "toggle" or e["type"] == PATCH:
            return self.set_active(e, not e["active"], capture=False)
        if e.get("hk_value") is None:
            return False
        if act == "set":
            val = e["hk_value"]
        else:
            cur = self.read(e)
            if cur is None:
                return False
            val = cur + e["hk_value"]
            info = np.iinfo(TYPES[e["type"]]) if np.dtype(TYPES[e["type"]]).kind in "iu" else None
            if info:
                val = max(info.min, min(info.max, int(val)))
        if e["active"]:
            e["value"] = val
        return self.write(e, val)

    def tick(self, entries):
        """Eingefrorene Werte schreiben (regelmaessig aufrufen)."""
        for e in entries:
            if not e["active"] or e["type"] == PATCH or e["value"] is None:
                continue
            mode = e.get("mode", "=")
            if mode != "=":
                cur = self.read(e)
                if cur is None or (mode == ">=" and cur >= e["value"]) or (mode == "<=" and cur <= e["value"]):
                    continue
            self.write(e, e["value"])

    def deactivate_all(self, entries):
        for e in entries:
            if e["active"]:
                self.set_active(e, False)


def parse_for_entry(e, text):
    return parse_value(text, TYPES[e["type"]])[0]


# ---------------------------------------------------------------- Tabellen-Dateien
SAVE_KEYS = ("desc", "expr", "type", "group", "active", "value", "mode", "hotkey", "hk_action", "hk_value",
             "orig", "new", "aob", "aob_module", "aob_offset")


ACTION_KEYS = ("desc", "call", "hotkey", "interval")


def new_action(**kw):
    """Aktion = Spiel-Methode aufrufen (Unity), per Hotkey und/oder alle 'interval' Sekunden (Timer)."""
    a = {"desc": "Neue Aktion", "call": "", "hotkey": "", "interval": 0.0, "timer": False}
    a.update(kw)
    return a


def table_to_json(entries, process="", title="", speed=None, actions=()):
    return {"version": 3, "title": title, "process": process, "speed": speed or {},
            "entries": [{k: e.get(k) for k in SAVE_KEYS} for e in entries],
            "actions": [{k: a.get(k) for k in ACTION_KEYS} for a in actions]}


def table_from_json(data):
    """Akzeptiert auch das alte Format (Liste mit addr/module/offset)."""
    if isinstance(data, list):
        data = {"entries": data}
    entries = []
    for d in data.get("entries", []):
        if "expr" not in d:
            if d.get("module"):
                mod = d["module"]
                mod = f'"{mod}"' if any(c in mod for c in ' []+-"') else mod
                d["expr"] = f"{mod}+{int(d.get('offset') or 0):X}"
            else:
                d["expr"] = f"{int(d.get('addr') or 0):X}"
            if d.get("fval") is not None:
                d["active"], d["value"] = True, d["fval"]
        entries.append(new_entry(**{k: d[k] for k in SAVE_KEYS if k in d and d[k] is not None}))
    actions = [new_action(**{k: a[k] for k in ACTION_KEYS if a.get(k) is not None})
               for a in data.get("actions", []) if isinstance(a, dict)]
    return {"title": data.get("title", ""), "process": data.get("process", ""),
            "speed": data.get("speed") or {}, "entries": entries, "actions": actions}
