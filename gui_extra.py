"""Zusätzliche Werkzeug-Fenster: Struktur-Ansicht, 'Wer zeigt hierhin?', Werteverlauf,
'Welche Adressen nutzt dieser Befehl?', Unity-Explorer und Such-Assistent."""
import struct
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

import numpy as np

import debugger
import pointer_scan
from gui_tools import Tool, _hex_or_expr
from scanner_core import TYPES, fmt_value
from trainer_core import new_entry

COLORS = ("#d62728", "#1f77b4", "#2ca02c", "#9467bd", "#ff7f0e", "#17becf")


def _type_size(type_name):
    return np.dtype(TYPES.get(type_name, np.int32)).itemsize


def _valid_ptr(proc, v):
    return bool(v) and 0x10000 <= v < (0xFFFFFFFF if proc.is32 else 0x7FFFFFFFFFFF) and proc.read_bytes(v, 1) is not None


# ---------------------------------------------------------------- Struktur-Ansicht
class StructWindow(Tool):
    """Speicher rund um eine Adresse als Felder (int/float/Zeiger), live mit Änderungs-Markierung.
    Bei Unity-Spielen werden die echten Feldnamen angezeigt, wenn die Adresse ein Objekt ist."""

    def __init__(self, app, addr=None):
        super().__init__(app, "Struktur-Ansicht", "980x600")
        self.base = addr if addr is not None else 0
        self.prev = None
        self.changed_at = {}
        self.names = {}
        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")
        ttk.Label(bar, text="Adresse:").pack(side="left")
        self.ent = ttk.Entry(bar, width=36)
        self.ent.pack(side="left", padx=4)
        self.ent.insert(0, app.proc.fmt_addr(self.base) if addr is not None else "")
        self.ent.bind("<Return>", lambda _: self.goto())
        ttk.Button(bar, text="Gehe zu", command=self.goto).pack(side="left")
        ttk.Button(bar, text="−0x40", command=lambda: self.shift(-0x40)).pack(side="left", padx=(8, 0))
        ttk.Button(bar, text="+0x40", command=lambda: self.shift(0x40)).pack(side="left")
        ttk.Label(bar, text="Größe:").pack(side="left", padx=(12, 2))
        self.size = ttk.Combobox(bar, values=["0x100", "0x200", "0x400", "0x800"], width=7, state="readonly")
        self.size.set("0x200")
        self.size.pack(side="left")
        self.size.bind("<<ComboboxSelected>>", lambda _: self.rebuild())
        self.step8 = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="8-Byte-Schritte", variable=self.step8, command=self.rebuild).pack(side="left", padx=8)
        self.info = ttk.Label(bar, text="", foreground="#06c")
        self.info.pack(side="right")
        ttk.Label(self, text="Gelb = hat sich gerade geändert · Doppelklick: Zeiger folgen bzw. zur Adressliste · "
                             "Rechtsklick: mehr", foreground="#555", padding=(6, 0)).pack(anchor="w")
        cols = (("off", "Offset", 70), ("hex", "Hex", 150), ("i32", "Int32", 100), ("f32", "Float", 110),
                ("q", "Int64 / Double / Zeiger", 240), ("name", "Feld / Hinweis", 260))
        self.tv = ttk.Treeview(self, columns=[c[0] for c in cols], show="headings")
        for c, t, w in cols:
            self.tv.heading(c, text=t)
            self.tv.column(c, width=w, anchor="w")
        self.tv.tag_configure("chg", background="#fff3a0")
        sb = ttk.Scrollbar(self, command=self.tv.yview)
        self.tv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tv.pack(fill="both", expand=True, padx=(6, 0), pady=(0, 6))
        self.tv.bind("<Double-1>", self.dbl)
        self.tv.bind("<Button-3>", self.menu)
        self.rebuild()
        self.every(300, self.refresh)

    def goto(self):
        a = _hex_or_expr(self.app, self.ent.get())
        if a is not None:
            self.base = a
            self.rebuild()

    def shift(self, d):
        self.base = max(0, self.base + d)
        self.ent.delete(0, "end")
        self.ent.insert(0, self.app.proc.fmt_addr(self.base))
        self.rebuild()

    def rebuild(self):
        self.prev = None
        self.changed_at.clear()
        self.tv.delete(*self.tv.get_children())
        step = 8 if self.step8.get() else 4
        for off in range(0, int(self.size.get(), 16), step):
            self.tv.insert("", "end", iid=str(off), values=(f"+{off:X}",) + ("",) * 5)
        self.names = self._unity_names()
        self.refresh()

    def _unity_names(self):
        """Offset -> 'Feldname (Typ)', falls die Adresse ein Unity-Objekt ist."""
        u = getattr(self.app, "unity", None)
        if not u:
            self.info.config(text="")
            return {}
        head = self.app.proc.read_ptr(self.base)
        cls = u.by_ptr.get(head) or next((c for c in u.classes if c.header and c.header == head), None)
        if not cls:
            self.info.config(text="")
            return {}
        names, c, depth = {}, cls, 0
        while c is not None and depth < 16:
            for f in c.fields:
                if not f.static:
                    names.setdefault(f.offset, f"{f.name.replace('k__BackingField', '').strip('<>')} ({f.short_type()})")
            c = u.by_ptr.get(c.parent)
            depth += 1
        self.info.config(text=f"Unity-Objekt: {cls.full}")
        return names

    def refresh(self):
        p = self.app.proc
        if not p:
            return
        n = int(self.size.get(), 16)
        data = p.read_bytes(self.base, n)
        if data is None:
            self.info.config(text="Adresse nicht lesbar", foreground="#b00")
            return
        now = time.time()
        step = 8 if self.step8.get() else 4
        for off in range(0, n, step):
            chunk = data[off:off + step]
            if self.prev is not None and self.prev[off:off + step] != chunk:
                self.changed_at[off] = now
            i32 = struct.unpack_from("<i", data, off)[0]
            f32 = struct.unpack_from("<f", data, off)[0]
            q = ""
            hint = self.names.get(off, "")
            if off % 8 == 0 and off + 8 <= n:
                v64 = struct.unpack_from("<Q", data, off)[0]
                d = struct.unpack_from("<d", data, off)[0]
                if _valid_ptr(p, v64):
                    q = f"→ {p.fmt_addr(v64)}"
                    if not hint:
                        hint = "Zeiger"
                else:
                    q = f"{struct.unpack_from('<q', data, off)[0]}"
                    if 1e-6 < abs(d) < 1e12:
                        q += f" / {fmt_value(d)}"
            fs = fmt_value(f32) if 1e-6 < abs(f32) < 1e9 or f32 == 0 else "–"
            tags = ("chg",) if now - self.changed_at.get(off, 0) < 1.5 else ()
            self.tv.item(str(off), values=(f"+{off:X}", chunk.hex(" "), i32, fs, q, hint), tags=tags)
        self.prev = data

    def _sel(self):
        s = self.tv.selection()
        return int(s[0]) if s else None

    def add(self, off, type_name):
        name = self.names.get(off, f"+{off:X}")
        self.app.add_entry(new_entry(desc=name.split(" (")[0], expr=self.app.proc.fmt_addr(self.base + off),
                                     type=type_name))

    def follow(self, off):
        v = self.app.proc.read_ptr(self.base + off)
        if _valid_ptr(self.app.proc, v):
            StructWindow(self.app, v)
            return True
        return False

    def dbl(self, ev):
        off = self._sel()
        if off is None:
            return
        if off % 8 == 0 and self.follow(off):
            return
        data = self.app.proc.read_bytes(self.base + off, 4) or b"\0" * 4
        f = struct.unpack("<f", data)[0]
        self.add(off, "Float" if 1e-4 < abs(f) < 1e7 and not data[3] in (0, 0xFF) else "4 Bytes")

    def menu(self, ev):
        iid = self.tv.identify_row(ev.y)
        if not iid:
            return
        self.tv.selection_set(iid)
        off = int(iid)
        a = self.base + off
        m = tk.Menu(self, tearoff=0)
        for t in ("4 Bytes", "Float", "8 Bytes", "Double", "Byte", "2 Bytes"):
            m.add_command(label=f"→ Adressliste als {t}", command=lambda t=t: self.add(off, t))
        m.add_separator()
        m.add_command(label="Zeiger folgen", command=lambda: self.follow(off) or messagebox.showinfo(
            "Hinweis", "Hier steht kein gültiger Zeiger.", parent=self))
        m.add_command(label="Werteverlauf (Float + Int32)", command=lambda: HistoryWindow(
            self.app, [(f"+{off:X} Float", a, "Float", 1), (f"+{off:X} Int32", a, "4 Bytes", 1)]))
        m.add_command(label="Was schreibt hierhin?", command=lambda: self.app.watch(a, 4, "w"))
        m.add_command(label="Wer zeigt auf diese Struktur?", command=lambda: RefsWindow(self.app, self.base))
        m.tk_popup(ev.x_root, ev.y_root)


# ---------------------------------------------------------------- Wer zeigt hierhin?
class RefsWindow(Tool):
    def __init__(self, app, target):
        super().__init__(app, f"Wer zeigt auf {app.proc.fmt_addr(target)}?", "820x460")
        self.target = target
        self.cancel = threading.Event()
        self.prog = {"v": 0.0}
        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")
        ttk.Label(bar, text="Max. Offset (hex):").pack(side="left")
        self.maxoff = ttk.Entry(bar, width=8)
        self.maxoff.insert(0, "400")
        self.maxoff.pack(side="left", padx=4)
        self.btn = ttk.Button(bar, text="Suchen", command=self.search)
        self.btn.pack(side="left")
        self.pb = ttk.Progressbar(bar, maximum=1.0, length=180)
        self.pb.pack(side="left", padx=8)
        self.status = ttk.Label(bar, text="", foreground="#555")
        self.status.pack(side="left")
        ttk.Label(self, text="Zeiger, die auf diese Adresse oder kurz davor (Objektanfang) zeigen. ✓ statisch = liegt "
                             "in einem Modul → stabil auch nach Neustart.\nDoppelklick: Zeigerkette zur Adressliste · "
                             "Rechtsklick: Struktur des Fundorts", foreground="#555", padding=(6, 0)).pack(anchor="w")
        self.tv = ttk.Treeview(self, columns=("at", "off", "st", "expr"), show="headings")
        for c, t, w in (("at", "Fundort", 230), ("off", "Offset", 80), ("st", "Statisch", 70), ("expr", "Ausdruck", 380)):
            self.tv.heading(c, text=t)
            self.tv.column(c, width=w, anchor="w")
        self.tv.pack(fill="both", expand=True, padx=6, pady=6)
        self.tv.bind("<Double-1>", lambda _: self.add())
        self.tv.bind("<Button-3>", self.menu)
        self.every(150, lambda: self.pb.configure(value=self.prog["v"]))
        self.search()

    def search(self):
        try:
            mo = int(self.maxoff.get(), 16)
        except ValueError:
            mo = 0x400
        self.btn.config(state="disabled")
        self.status.config(text="Suche…")
        self.tv.delete(*self.tv.get_children())
        prog = self.prog

        def work():
            return pointer_scan.find_refs(self.app.proc, self.target, mo,
                                          progress=lambda f: prog.__setitem__("v", f), cancel=self.cancel)

        def done(res, err):
            self.btn.config(state="normal")
            if err:
                self.status.config(text=f"Fehler: {err}")
                return
            p = self.app.proc
            for at, off, st in res:
                expr = f"[{p.fmt_addr(at)}]+{off:X}"
                self.tv.insert("", "end", iid=str(at), values=(p.fmt_addr(at), f"+{off:X}", "✓" if st else "", expr))
            self.status.config(text=f"{len(res)} Fundstellen" + (" – keine: Pointer-Scan mit mehr Ebenen versuchen"
                                                                  if not res else ""))
        self.run_bg(work, done)

    def close(self):
        self.cancel.set()
        super().close()

    def add(self):
        for iid in self.tv.selection():
            expr = self.tv.set(iid, "expr")
            self.app.add_entry(new_entry(desc="Über Zeiger", expr=expr, type="4 Bytes"))

    def menu(self, ev):
        iid = self.tv.identify_row(ev.y)
        if not iid:
            return
        self.tv.selection_set(iid)
        at = int(iid)
        m = tk.Menu(self, tearoff=0)
        m.add_command(label="Zeigerkette → Adressliste", command=self.add)
        m.add_command(label="Fundort in Struktur-Ansicht (Eltern-Objekt)", command=lambda: StructWindow(self.app, at & ~0xF))
        m.add_command(label="Wer zeigt auf den Fundort?", command=lambda: RefsWindow(self.app, at))
        m.tk_popup(ev.x_root, ev.y_root)


# ---------------------------------------------------------------- Werteverlauf
class HistoryWindow(Tool):
    """Live-Graph von bis zu 6 Adressen (je eine Zeile, 30 s Verlauf)."""
    SAMPLES = 300

    def __init__(self, app, items):
        super().__init__(app, "Werteverlauf (live)", "760x" + str(90 + 110 * min(len(items), 6)))
        self.items = items[:6]
        self.data = [[] for _ in self.items]
        self.changes = [0] * len(self.items)
        self.paused = tk.BooleanVar(value=False)
        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")
        ttk.Checkbutton(bar, text="Pause", variable=self.paused).pack(side="left")
        ttk.Button(bar, text="Leeren", command=self.clear).pack(side="left", padx=6)
        ttk.Label(bar, text="Ändere den Wert im Spiel – die richtige Adresse springt genau dann.",
                  foreground="#555").pack(side="left", padx=8)
        self.cv = tk.Canvas(self, background="white", highlightthickness=0)
        self.cv.pack(fill="both", expand=True, padx=6, pady=(0, 6))
        self.every(100, self.sample)

    def clear(self):
        self.data = [[] for _ in self.items]
        self.changes = [0] * len(self.items)

    def sample(self):
        if self.paused.get() or not self.app.proc:
            return
        for i, (_, addr, tname, scale) in enumerate(self.items):
            v = self.app.proc.read_value(addr, TYPES[tname])
            if v is not None and scale != 1:
                v = v / scale
            d = self.data[i]
            if d and v is not None and d[-1] is not None and v != d[-1]:
                self.changes[i] += 1
            d.append(v)
            del d[:-self.SAMPLES]
        self.draw()

    def draw(self):
        cv = self.cv
        cv.delete("all")
        w, h = max(cv.winfo_width(), 200), max(cv.winfo_height(), 100)
        rows = len(self.items) or 1
        rh = h / rows
        for i, (label, addr, _, _) in enumerate(self.items):
            y0 = i * rh
            vals = [v for v in self.data[i] if v is not None and v == v]
            cv.create_line(0, y0 + rh - 1, w, y0 + rh - 1, fill="#ddd")
            cur = self.data[i][-1] if self.data[i] else None
            text = f"{label}  {self.app.proc.fmt_addr(addr)}   jetzt: {fmt_value(cur) if cur is not None else '??'}"
            if vals:
                text += f"   min {fmt_value(min(vals))}  max {fmt_value(max(vals))}  Änderungen: {self.changes[i]}"
            cv.create_text(6, y0 + 4, anchor="nw", text=text, font=("Segoe UI", 9), fill=COLORS[i % len(COLORS)])
            if len(vals) < 2:
                continue
            lo, hi = min(vals), max(vals)
            span = (hi - lo) or 1
            pts = []
            n = len(self.data[i])
            for j, v in enumerate(self.data[i]):
                if v is None or v != v:
                    continue
                x = w * (self.SAMPLES - n + j) / self.SAMPLES
                y = y0 + 22 + (rh - 30) * (1 - (v - lo) / span)
                pts += [x, y]
            if len(pts) >= 4:
                cv.create_line(*pts, fill=COLORS[i % len(COLORS)], width=2)


# ---------------------------------------------------------------- Welche Adressen nutzt dieser Befehl?
class TracerWindow(Tool):
    def __init__(self, app, ins_addr):
        super().__init__(app, "Welche Adressen nutzt dieser Befehl?", "820x440")
        self.tr = debugger.InstructionTracer(app.proc, ins_addr)
        ttk.Label(self, text=f"Befehl: {app.proc.fmt_addr(ins_addr)}   {self.tr.text}\n"
                             "Zeigt alle Adressen, auf die dieser Code zugreift – z. B. Leben von Spieler UND Gegnern. "
                             "So erkennst du, ob ein Befehl nur deinen Wert betrifft.",
                  foreground="#555", padding=6, wraplength=780, justify="left").pack(anchor="w")
        self.tv = ttk.Treeview(self, columns=("addr", "n", "i32", "f32"), show="headings")
        for c, t, w in (("addr", "Adresse", 260), ("n", "Zugriffe", 90), ("i32", "Wert (Int)", 140),
                        ("f32", "Wert (Float)", 140)):
            self.tv.heading(c, text=t)
            self.tv.column(c, width=w, anchor="w")
        self.tv.pack(fill="both", expand=True, padx=6)
        self.tv.bind("<Double-1>", lambda _: self.add())
        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")
        self.btn = ttk.Button(bar, text="Stopp", command=self.stop)
        self.btn.pack(side="left")
        ttk.Button(bar, text="→ Adressliste", command=self.add).pack(side="left", padx=6)
        ttk.Button(bar, text="Struktur ansehen", command=self.struct).pack(side="left")
        self.status = ttk.Label(bar, text="", foreground="#070")
        self.status.pack(side="right")
        if self.tr.error:
            self.status.config(text=self.tr.error, foreground="#b00")
        else:
            self.tr.start()
            self.status.config(text="Debugger läuft…")
        self.every(300, self.refresh)

    def refresh(self):
        if self.tr.error:
            self.status.config(text=self.tr.error, foreground="#b00")
        elif not self.tr.running:
            self.status.config(text="Gestoppt", foreground="#555")
        p = self.app.proc
        for a, n in list(self.tr.addresses.items())[:500]:
            iv = p.read_value(a, np.int32)
            fv = p.read_value(a, np.float32)
            vals = (p.fmt_addr(a), n, "??" if iv is None else iv, "??" if fv is None else fmt_value(fv))
            if self.tv.exists(str(a)):
                self.tv.item(str(a), values=vals)
            else:
                self.tv.insert("", "end", iid=str(a), values=vals)

    def stop(self):
        self.tr.stop()
        self.btn.config(state="disabled")

    def close(self):
        self.tr.stop()
        self.tr.join(3)
        super().close()

    def add(self):
        t = "8 Bytes" if self.tr.op_size == 8 else "4 Bytes"
        for iid in self.tv.selection():
            self.app.add_entry(new_entry(desc="Von Befehl", expr=self.app.proc.fmt_addr(int(iid)), type=t))

    def struct(self):
        for iid in self.tv.selection()[:1]:
            StructWindow(self.app, max(0, int(iid) - 0x40) & ~0xF)


# ---------------------------------------------------------------- Unity-Explorer
class UnityWindow(Tool):
    def __init__(self, app):
        super().__init__(app, "Unity-Explorer – Werte per Name finden", "1080x680")
        import unity
        self.unity_mod = unity
        self.cancel = threading.Event()
        self.objs = []
        self.field = None
        self.sub = None
        self.static_base = 0
        self.results = {}
        self.prog = {"v": 0.0}
        top = ttk.Frame(self, padding=6)
        top.pack(fill="x")
        self.status = ttk.Label(top, text="", foreground="#555")
        self.status.pack(side="left")
        ttk.Button(top, text="Neu einlesen", command=lambda: self.load(force=True)).pack(side="right")
        self.all_asm = tk.BooleanVar(value=False)
        ttk.Checkbutton(top, text="Auch System-/Unity-Bibliotheken", variable=self.all_asm).pack(side="right", padx=8)

        sbar = ttk.Frame(self, padding=(6, 0))
        sbar.pack(fill="x")
        ttk.Label(sbar, text="Suche (z. B. coins, gold, health, Player.hp – leer = Geld-Wörter):").pack(side="left")
        self.q = ttk.Entry(sbar, width=30)
        self.q.pack(side="left", padx=4)
        self.q.bind("<Return>", lambda _: self.search())
        ttk.Button(sbar, text="Suchen", command=self.search).pack(side="left")
        self.numeric = tk.BooleanVar(value=True)
        ttk.Checkbutton(sbar, text="Nur Zahlen", variable=self.numeric, command=self.search).pack(side="left", padx=6)
        self.ui = tk.BooleanVar(value=False)
        ttk.Checkbutton(sbar, text="UI-Klassen zeigen", variable=self.ui, command=self.search).pack(side="left")
        ttk.Button(sbar, text="Methoden der Klasse…", command=self.methods).pack(side="right")

        pw = ttk.PanedWindow(self, orient="vertical")
        pw.pack(fill="both", expand=True, padx=6, pady=6)
        f1 = ttk.Frame(pw)
        pw.add(f1, weight=3)
        self.tv = ttk.Treeview(f1, columns=("cls", "field", "type", "off", "st"), show="headings")
        for c, t, w in (("cls", "Klasse", 400), ("field", "Feld", 260), ("type", "Typ", 150), ("off", "Offset", 70),
                        ("st", "Statisch", 70)):
            self.tv.heading(c, text=t)
            self.tv.column(c, width=w, anchor="w")
        sb = ttk.Scrollbar(f1, command=self.tv.yview)
        self.tv.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.tv.pack(fill="both", expand=True)
        self.tv.bind("<<TreeviewSelect>>", lambda _: self.pick())
        self.tv.bind("<Double-1>", lambda _: self.find_objects())

        f2 = ttk.Frame(pw)
        pw.add(f2, weight=2)
        bar = ttk.Frame(f2)
        bar.pack(fill="x", pady=(0, 4))
        self.sel_lbl = ttk.Label(bar, text="Feld wählen → „Objekte suchen“ (Doppelklick)")
        self.sel_lbl.pack(side="left")
        for txt, cmd in (("Struktur ansehen", self.struct), ("→ Adressliste", self.add),
                         ("Objekte suchen", self.find_objects)):
            ttk.Button(bar, text=txt, command=cmd).pack(side="right", padx=(4, 0))
        self.pb = ttk.Progressbar(bar, maximum=1.0, length=140)
        self.pb.pack(side="right", padx=8)
        self.ov = ttk.Treeview(f2, columns=("obj", "addr", "val", "score"), show="headings", height=7)
        for c, t, w in (("obj", "Objekt", 220), ("addr", "Feld-Adresse", 220), ("val", "Wert (live)", 200),
                        ("score", "Plausibilität", 100)):
            self.ov.heading(c, text=t)
            self.ov.column(c, width=w, anchor="w")
        self.ov.pack(fill="both", expand=True)
        self.ov.bind("<Double-1>", lambda _: self.add())
        ttk.Label(f2, text="Mehrere Objekte? Oft sind es Kopien (alter Spielstand, Vorschau). Ändere den Wert im Spiel – "
                           "das Objekt, dessen Wert mitläuft, ist das echte. 🔓 = verschlüsselter Wert (ACTk), entschlüsselt "
                           "angezeigt.", foreground="#555", wraplength=1000, justify="left").pack(anchor="w", pady=(4, 0))
        self.load()
        self.every(300, self.refresh)
        self.every(150, lambda: self.pb.configure(value=self.prog["v"]))

    # -- Laden / Suchen
    def load(self, force=False):
        app = self.app
        if not force and getattr(app, "unity", None) and app.unity.proc is app.proc and \
                app.unity.loaded_all == self.all_asm.get():
            self.status.config(text=f"{app.unity.kind.upper()}: {len(app.unity.classes)} Klassen geladen")
            self.search()
            return
        try:
            u = self.unity_mod.UnityRuntime(app.proc)
        except self.unity_mod.UnityError as e:
            self.status.config(text=str(e), foreground="#b00")
            return
        self.status.config(text=f"{u.kind.upper()} erkannt – lese Klassen ein…")
        prog = self.prog

        def work():
            return u.load(self.all_asm.get(), lambda f, t="": prog.__setitem__("v", f))

        def done(res, err):
            if err:
                self.status.config(text=f"Fehler: {err}", foreground="#b00")
                return
            app.set_unity(res)
            self.status.config(text=f"{res.kind.upper()}: {len(res.classes)} Klassen, "
                                    f"{sum(len(c.fields) for c in res.classes)} Felder", foreground="#070")
            self.search()
        self.run_bg(work, done)

    def methods(self):
        s = self.tv.selection()
        if not s or not getattr(self.app, "unity", None):
            messagebox.showinfo("Methoden", "Erst eine Zeile (Klasse) in der Liste wählen.", parent=self)
            return
        import gui_actions
        gui_actions.MethodsWindow(self.app, self.results[s[0]].cls)

    def search(self):
        u = getattr(self.app, "unity", None)
        if not u:
            return
        res = u.search(self.q.get(), numeric_only=self.numeric.get(), include_ui=self.ui.get(), limit=1500)
        self.results = {str(i): f for i, f in enumerate(res)}
        self.tv.delete(*self.tv.get_children())
        for i, f in self.results.items():
            self.tv.insert("", "end", iid=i, values=(f.cls.full, f.name.replace("k__BackingField", "").strip("<>"),
                                                     f.short_type(), f"+{f.offset:X}", "✓" if f.static else ""))
        todo = [f for f in res[:300] if f.type_name is None and f.tenum not in self.unity_mod.NUMERIC]

        def work():
            u.describe_types(todo)

        def done(_, err):
            for i, f in self.results.items():
                if self.tv.exists(i):
                    self.tv.set(i, "type", f.short_type())
        if todo:
            self.run_bg(work, done)

    def pick(self):
        s = self.tv.selection()
        if s:
            f = self.results[s[0]]
            self.sel_lbl.config(text=f"{f.cls.full}.{f.name.replace('k__BackingField', '').strip('<>')}  ({f.short_type()})")

    def find_objects(self):
        s = self.tv.selection()
        if not s:
            return
        f = self.results[s[0]]
        u = self.app.unity
        self.field, self.objs, self.sub = f, [], None
        self.ov.delete(*self.ov.get_children())
        self.cancel.clear()
        prog = self.prog

        def work():
            sub = u.struct_fields(f) if f.tenum == 0x11 else None
            if sub:
                u.describe_types([f])
            if f.static:
                base = u.static_base(f.cls)
                return [("statisch", base, 0)] if base else [], sub
            known = set(u.by_ptr)
            objs = u.instances(f.cls, progress=lambda x: prog.__setitem__("v", x), cancel=self.cancel)
            return [(o, o, u._plausible(o, f.cls, known)) for o in objs], sub

        def done(res, err):
            if err:
                messagebox.showerror("Fehler", str(err), parent=self)
                return
            self.objs, self.sub = res
            for i, (o, base, score) in enumerate(self.objs):
                addr = u.field_addr(f, base if f.static else o, base if f.static else 0)
                self.ov.insert("", "end", iid=str(i), values=(
                    "statische Felder" if o == "statisch" else self.app.proc.fmt_addr(o),
                    self.app.proc.fmt_addr(addr) if addr else "–", "", score))
            if not self.objs:
                self.sel_lbl.config(text="Keine Objekte gefunden (Klasse evtl. noch nicht benutzt – im Spiel weiter "
                                         "spielen und erneut suchen).")
            self.refresh()
        self.run_bg(work, done)

    def _addr(self, i):
        o, base, _ = self.objs[i]
        return self.app.unity.field_addr(self.field, None if o == "statisch" else o, base if o == "statisch" else 0)

    def refresh(self):
        u = getattr(self.app, "unity", None)
        if not u or not self.field:
            return
        for iid in self.ov.get_children():
            a = self._addr(int(iid))
            self.ov.set(iid, "val", u.read_field(a, self.field, self.sub))

    def add(self):
        f = self.field
        if not f:
            return
        name = f"{f.cls.name}.{f.name.replace('k__BackingField', '').strip('<>')}"
        for iid in self.ov.selection() or self.ov.get_children()[:1]:
            a = self._addr(int(iid))
            if a is None:
                continue
            if f.tenum == 0x11 and self.sub:
                hv = next((s for s in self.sub if s.name == "hiddenValue"), None)
                if hv:
                    self.app.add_entry(new_entry(desc=name + " (verschlüsselt, Rohwert)",
                                                 expr=self.app.proc.fmt_addr(a - 0x10 + hv.offset), type=hv.mem_type))
                    messagebox.showinfo("Verschlüsselter Wert", "Der Wert ist mit dem Anti-Cheat-Toolkit verschlüsselt. "
                                        "Eingetragen wurde der Rohwert – direktes Ändern funktioniert nicht. Tipp: "
                                        "'Was schreibt hierhin?' und den Befehl per NOP ausschalten.", parent=self)
                    continue
            self.app.add_entry(new_entry(desc=name, expr=self.app.proc.fmt_addr(a), type=f.mem_type))

    def struct(self):
        for iid in self.ov.selection()[:1]:
            o, base, _ = self.objs[int(iid)]
            StructWindow(self.app, base if o == "statisch" else o)

    def close(self):
        self.cancel.set()
        super().close()


# ---------------------------------------------------------------- Such-Assistent
class AssistantWindow(Tool):
    """Führt Schritt für Schritt durch die Suche und gibt Tipps passend zum aktuellen Stand."""

    def __init__(self, app):
        super().__init__(app, "Such-Assistent", "460x560")
        self.attributes("-topmost", True)
        self.txt = tk.Text(self, wrap="word", height=22, relief="flat", background=self.cget("background"),
                           font=("Segoe UI", 10), padx=10, pady=8)
        self.txt.pack(fill="both", expand=True)
        self.txt.tag_configure("h", font=("Segoe UI", 11, "bold"))
        self.txt.tag_configure("k", foreground="#06c")
        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")
        self.btns = ttk.Frame(bar)
        self.btns.pack(fill="x")
        self.state = None
        self.every(500, self.update_tips)

    def _buttons(self, items):
        for w in self.btns.winfo_children():
            w.destroy()
        for txt, cmd in items:
            ttk.Button(self.btns, text=txt, command=cmd).pack(fill="x", pady=2)

    def _show(self, state, title, lines, buttons):
        if state == self.state:
            return
        self.state = state
        self.txt.config(state="normal")
        self.txt.delete("1.0", "end")
        self.txt.insert("end", title + "\n\n", "h")
        for ln in lines:
            self.txt.insert("end", ln + "\n", "k" if ln.startswith("⌨") else ())
        self.txt.config(state="disabled")
        self._buttons(buttons)

    def update_tips(self):
        app = self.app
        hot = "⌨ Scan-Hotkeys (im Spiel): Strg+Num+ erhöht · Strg+Num− verringert · Strg+Num0 unverändert · " \
              "Strg+Num* geändert · Strg+Num/ exakter Wert (Eingabefeld)"
        if not app.proc:
            self._show("noproc", "1. Spiel auswählen",
                       ["Starte das Spiel und klicke auf „Prozess wählen…“.",
                        "Tipp: Mit „nur Fenster“ siehst du nur Programme mit Fenster – das Spiel ist meist "
                        "der Eintrag mit dem Spieltitel."],
                       [("Prozess wählen…", app.choose_process)])
            return
        import unity
        is_unity = unity.detect(app.proc)
        if app.scanner is None:
            lines = ["Gib den aktuellen Wert ein (z. B. dein Geld) und klicke „Erster Scan“.",
                     "Datentyp „Alle Zahlentypen“ sucht 4/8 Bytes, Float, Double und Cent-Werte (×10, ×100) "
                     "gleichzeitig – du musst den Typ nicht kennen.",
                     "Wird der Wert gerundet angezeigt (z. B. 336 statt 336,7)? → Scan-Art „Ungefähr (gerundet)“.",
                     "Wert unbekannt (z. B. Lebensbalken)? → „Unbekannter Startwert“, dann „Rauschfilter“.", "", hot]
            buttons = [("Typ: Alle Zahlentypen + Exakter Wert", app.preset_multi)]
            if is_unity:
                lines.insert(0, f"✨ Unity-Spiel ({is_unity.upper()}) erkannt: Mit dem Unity-Explorer findest du Werte "
                                "direkt per Name (z. B. „coins“) – oft schneller als jede Suche.\n")
                buttons.insert(0, ("Unity-Explorer öffnen", app.open_unity))
            self._show(("first", bool(is_unity)), "2. Ersten Scan starten", lines, buttons)
            return
        n = app.scanner.count()
        if app.worker:
            return
        if n == 0:
            self._show("zero", "Keine Treffer",
                       ["Mögliche Gründe:", "• Falscher Typ → „Alle Zahlentypen“ verwenden.",
                        "• Angezeigter Wert ist gerundet → „Ungefähr (gerundet)“.",
                        "• Wert ist verschlüsselt → „Unbekannter Startwert“ + Erhöht/Verringert, "
                        "oder bei Unity den Unity-Explorer (zeigt 🔓 entschlüsselte Werte).",
                        "• Wert hat sich zwischen den Scans nicht wirklich geändert.",
                        "• Online-Spiel: Wert liegt auf dem Server – nicht änderbar."],
                       [("Rückgängig", app.undo_scan), ("Neuer Scan", app.new_scan)]
                       + ([("Unity-Explorer öffnen", app.open_unity)] if is_unity else []))
        elif n > 50:
            self._show(("many", n > 100000), "3. Weiter eingrenzen",
                       [f"Noch {n:,} Treffer.".replace(",", "."),
                        "Ändere den Wert im Spiel (Geld ausgeben/einsammeln) und scanne erneut – "
                        "mit dem neuen Wert oder „Erhöht“/„Verringert“.",
                        "Viele Treffer, die sich ständig ändern? Nichts tun und „Rauschfilter (5 s)“ klicken.",
                        "", hot],
                       [("Rauschfilter (5 s)", app.noise_filter), ("Scan-Hotkeys einschalten", app.enable_hotkeys)])
        else:
            self._show("few", "4. Treffer prüfen",
                       [f"Nur noch {n} Treffer – sehr gut!",
                        "Die Trefferliste aktualisiert sich live: grün = gestiegen, rot = gesunken.",
                        "Doppelklick → Adressliste. Dort per Doppelklick auf „Wert“ ändern und im Spiel prüfen.",
                        "Mehrere gleiche Werte? Oft Anzeige-Kopien. Die echte Adresse ist die, deren Änderung im "
                        "Spiel wirkt (Anzeige-Kopien werden zurückgesetzt).",
                        "Rechtsklick auf einen Treffer: Werteverlauf, Struktur, Wer zeigt hierhin?, Pointer-Scan "
                        "(damit die Adresse nach Neustart wieder stimmt)."],
                       [("Werteverlauf der Treffer", app.history_selected_or_all)])
