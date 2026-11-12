"""Werkzeug-Fenster des MemTrainers: Hex-Viewer, Pointer-Scan, AOB/Text-Suche,
Zugriffs-Debugger, Speedhack und Eintrags-Dialog."""
import json
import struct
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

import aob
import debugger
import pointer_scan
from scanner_core import HOTKEYS, TYPES, fmt_value, parse_value
from trainer_core import ALL_TYPES, FREEZE_MODES, HK_ACTIONS, PATCH, new_entry, resolve_expr

MONO = ("Consolas", 10)


def _hex_or_expr(app, text):
    addr = resolve_expr(app.proc, text.strip()) if app.proc else None
    if addr is None:
        messagebox.showerror("Adresse", f"Adresse „{text}“ ist ungültig oder nicht lesbar.")
    return addr


class Tool(tk.Toplevel):
    def __init__(self, app, title, size):
        super().__init__(app)
        self.app = app
        self.title(title)
        self.geometry(size)
        self._job = None
        self.protocol("WM_DELETE_WINDOW", self.close)

    def every(self, ms, fn):
        def loop():
            if self.winfo_exists():
                try:
                    fn()
                except tk.TclError:
                    return
                self._job = self.after(ms, loop)
        self._job = self.after(ms, loop)

    def close(self):
        self.destroy()

    def run_bg(self, work, done):
        """work() im Hintergrund, done(result, error) danach im GUI-Thread."""
        box = {}

        def run():
            try:
                box["r"] = work()
            except Exception as e:  # noqa: BLE001
                box["e"] = e

        t = threading.Thread(target=run, daemon=True)
        t.start()

        def poll():
            if t.is_alive():
                self.after(100, poll)
            elif self.winfo_exists():
                done(box.get("r"), box.get("e"))
        self.after(100, poll)


# ---------------------------------------------------------------- Hex-Viewer / Disassembler
class HexViewer(Tool):
    ROWS = 24

    def __init__(self, app, addr=None):
        super().__init__(app, "Speicher-Viewer", "820x600")
        self.base = (addr or 0) & ~0xF
        self.last = {}
        self.mode = tk.StringVar(value="hex")
        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")
        ttk.Label(bar, text="Adresse:").pack(side="left")
        self.addr_e = ttk.Entry(bar, width=36)
        self.addr_e.pack(side="left", padx=4)
        self.addr_e.insert(0, f"{addr:X}" if addr else "")
        self.addr_e.bind("<Return>", lambda _: self.goto())
        ttk.Button(bar, text="Gehe zu", command=self.goto).pack(side="left")
        ttk.Radiobutton(bar, text="Hex", variable=self.mode, value="hex", command=self.render).pack(side="left", padx=(12, 0))
        ttk.Radiobutton(bar, text="Disassembler", variable=self.mode, value="asm", command=self.render).pack(side="left")
        self.txt = tk.Text(self, font=MONO, wrap="none", height=self.ROWS + 1)
        self.txt.pack(fill="both", expand=True, padx=6)
        self.txt.tag_config("chg", foreground="#d00")
        self.txt.tag_config("dim", foreground="#888")
        self.txt.bind("<MouseWheel>", lambda e: self.scroll(-3 if e.delta > 0 else 3))
        self.info = ttk.Label(self, font=MONO, foreground="#333")
        self.info.pack(fill="x", padx=6, pady=(4, 0))
        wb = ttk.Frame(self, padding=6)
        wb.pack(fill="x")
        ttk.Label(wb, text="Bytes schreiben (hex) an Adresse:").pack(side="left")
        self.w_addr = ttk.Entry(wb, width=20)
        self.w_addr.pack(side="left", padx=4)
        self.w_bytes = ttk.Entry(wb, width=30)
        self.w_bytes.pack(side="left", padx=4)
        ttk.Button(wb, text="Schreiben", command=self.write).pack(side="left")
        self.render()
        self.every(500, self.render)

    def goto(self):
        a = _hex_or_expr(self.app, self.addr_e.get())
        if a is not None:
            self.base = a if self.mode.get() == "asm" else a & ~0xF
            self.last.clear()
            self.w_addr.delete(0, "end")
            self.w_addr.insert(0, f"{a:X}")
            self.render()

    def scroll(self, rows):
        self.base = max(0, self.base + rows * 16)
        self.render()

    def render(self):
        p = self.app.proc
        self.txt.config(state="normal")
        self.txt.delete("1.0", "end")
        if not p:
            self.txt.insert("end", "Kein Prozess verbunden.")
            return
        if self.mode.get() == "asm":
            self.render_asm(p)
        else:
            self.render_hex(p)
        v = p.read_bytes(self.base, 8)
        if v:
            i32, f32 = struct.unpack_from("<if", v + b"\0" * 8)
            i64, f64 = struct.unpack_from("<qd", v + v)
            self.info.config(text=f"@{p.fmt_addr(self.base)}  int32={i32}  float={fmt_value(f32)}  "
                                  f"int64={i64}  double={fmt_value(f64)}")
        self.txt.config(state="disabled")

    def render_hex(self, p):
        for r in range(self.ROWS):
            a = self.base + r * 16
            arr = p.read_array(a, 16, "uint8")
            data = bytes(arr) if arr is not None else b""
            self.txt.insert("end", f"{a:016X}  ", "dim")
            for i in range(16):
                if i < len(data):
                    b = data[i]
                    tag = "chg" if self.last.get(a + i, b) != b else ""
                    self.last[a + i] = b
                    self.txt.insert("end", f"{b:02X} ", tag)
                else:
                    self.txt.insert("end", "?? ")
            asc = "".join(chr(b) if 32 <= b < 127 else "." for b in data)
            self.txt.insert("end", f" {asc}\n", "dim")

    def render_asm(self, p):
        try:
            import capstone
        except ImportError:
            self.txt.insert("end", "Für den Disassembler: pip install capstone")
            return
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32 if p.is32 else capstone.CS_MODE_64)
        data = p.read_bytes(self.base, 256) or b""
        for n, ins in enumerate(md.disasm(data, self.base)):
            if n >= self.ROWS:
                break
            self.txt.insert("end", f"{p.fmt_addr(ins.address):<28}", "dim")
            self.txt.insert("end", f"{ins.bytes.hex(' '):<30} {ins.mnemonic} {ins.op_str}\n")

    def write(self):
        a = _hex_or_expr(self.app, self.w_addr.get())
        if a is None:
            return
        try:
            data = bytes.fromhex(self.w_bytes.get())
        except ValueError:
            messagebox.showerror("Bytes", "Bitte Hex-Bytes eingeben, z. B. 90 90 90")
            return
        if not self.app.proc.write_bytes(a, data, code=True):
            messagebox.showerror("Fehler", "Schreiben fehlgeschlagen.")
        self.render()


# ---------------------------------------------------------------- Pointer-Scan
class PointerScanWindow(Tool):
    def __init__(self, app, addr=None, type_name="4 Bytes"):
        super().__init__(app, "Pointer-Scanner", "860x560")
        self.type_name = type_name
        self.exprs = []
        self.cancel = threading.Event()
        top = ttk.Frame(self, padding=6)
        top.pack(fill="x")
        ttk.Label(top, text="Ziel-Adresse:").grid(row=0, column=0, sticky="w")
        self.target = ttk.Entry(top, width=24)
        self.target.grid(row=0, column=1, padx=4)
        if addr:
            self.target.insert(0, f"{addr:X}")
        ttk.Label(top, text="Max. Tiefe:").grid(row=0, column=2, padx=(10, 0))
        self.level = ttk.Spinbox(top, from_=1, to=7, width=4)
        self.level.set(5)
        self.level.grid(row=0, column=3)
        ttk.Label(top, text="Max. Offset (hex):").grid(row=0, column=4, padx=(10, 0))
        self.maxoff = ttk.Entry(top, width=8)
        self.maxoff.insert(0, "1000")
        self.maxoff.grid(row=0, column=5)
        self.btn = ttk.Button(top, text="Scannen", command=self.scan)
        self.btn.grid(row=0, column=6, padx=(10, 0))
        ttk.Button(top, text="Abbrechen", command=self.cancel.set).grid(row=0, column=7, padx=4)
        r2 = ttk.Frame(self, padding=(6, 0))
        r2.pack(fill="x")
        ttk.Label(r2, text="Nach Spiel-Neustart: Wert neu suchen, neue Adresse eintragen →").pack(side="left")
        self.new_addr = ttk.Entry(r2, width=20)
        self.new_addr.pack(side="left", padx=4)
        ttk.Button(r2, text="Rescan", command=self.rescan).pack(side="left")
        ttk.Button(r2, text="Laden", command=self.load).pack(side="right")
        ttk.Button(r2, text="Speichern", command=self.save).pack(side="right", padx=4)
        self.pb = ttk.Progressbar(self, maximum=1.0)
        self.pb.pack(fill="x", padx=6, pady=4)
        self.status = ttk.Label(self, text="Tipp: Nach dem Scan das Spiel neu starten, Wert neu finden, Rescan. "
                                           "Was übrig bleibt, ist stabil.", foreground="#555")
        self.status.pack(anchor="w", padx=6)
        self.tv = ttk.Treeview(self, columns=("expr", "val"), show="headings")
        self.tv.heading("expr", text="Zeigerkette")
        self.tv.heading("val", text="Wert")
        self.tv.column("expr", width=620)
        self.tv.column("val", width=120)
        self.tv.pack(fill="both", expand=True, padx=6, pady=6)
        self.tv.bind("<Double-1>", lambda _: self.add())
        ttk.Button(self, text="Ausgewählte → Adressliste", command=self.add).pack(pady=(0, 6))
        self.every(1000, self.refresh)

    def scan(self):
        p = self.app.proc
        target = _hex_or_expr(self.app, self.target.get())
        if target is None:
            return
        try:
            lvl, mo = int(self.level.get()), int(self.maxoff.get(), 16)
        except ValueError:
            messagebox.showerror("Eingabe", "Tiefe/Offset ungültig.")
            return
        self.cancel.clear()
        self.btn.config(state="disabled")
        self.status.config(text="Baue Pointer-Map (kann bei großen Spielen etwas dauern)…")
        prog = {"v": 0.0}

        def work():
            pm = pointer_scan.PointerMap(p, progress=lambda f: prog.update(v=f * 0.5), cancel=self.cancel)
            chains = pm.scan(target, lvl, mo, progress=lambda f: prog.update(v=0.5 + f * 0.5), cancel=self.cancel)
            return len(pm), [pointer_scan.chain_to_expr(p, b, o) for b, o in chains]

        def tick():
            if str(self.btn["state"]) == "disabled":
                self.pb["value"] = prog["v"]
                self.after(200, tick)
        tick()

        def done(res, err):
            self.btn.config(state="normal")
            self.pb["value"] = 1.0
            if err:
                self.status.config(text="Abgebrochen" if isinstance(err, InterruptedError) else f"Fehler: {err!r}")
                return
            n, self.exprs = res
            self.status.config(text=f"{len(self.exprs)} Zeigerketten gefunden ({n:,} Zeiger im Speicher).".replace(",", "."))
            self.fill()
        self.run_bg(work, done)

    def fill(self):
        self.tv.delete(*self.tv.get_children())
        for i, e in enumerate(self.exprs[:2000]):
            self.tv.insert("", "end", iid=str(i), values=(e, ""))
        self.refresh()

    def refresh(self):
        p = self.app.proc
        if not p:
            return
        dt = TYPES.get(self.type_name, "int32")
        for iid in self.tv.get_children()[:300]:
            a = resolve_expr(p, self.exprs[int(iid)])
            v = p.read_value(a, dt) if a else None
            self.tv.set(iid, "val", "??" if v is None else fmt_value(v))

    def rescan(self):
        a = _hex_or_expr(self.app, self.new_addr.get())
        if a is None:
            return
        before = len(self.exprs)
        self.exprs = pointer_scan.rescan(self.app.proc, self.exprs, a)
        self.status.config(text=f"Rescan: {len(self.exprs)} von {before} Ketten passen noch.")
        self.fill()

    def save(self):
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".ptr.json",
                                            filetypes=[("Zeigerketten", "*.json")])
        if path:
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"type": self.type_name, "chains": self.exprs}, f, indent=1)

    def load(self):
        path = filedialog.askopenfilename(parent=self, filetypes=[("Zeigerketten", "*.json")])
        if path:
            with open(path, encoding="utf-8") as f:
                d = json.load(f)
            self.exprs, self.type_name = d.get("chains", []), d.get("type", self.type_name)
            self.status.config(text=f"{len(self.exprs)} Ketten geladen. Jetzt Rescan mit neuer Adresse.")
            self.fill()

    def add(self):
        for iid in self.tv.selection():
            self.app.add_entry(new_entry(desc="Pointer", expr=self.exprs[int(iid)], type=self.type_name))


# ---------------------------------------------------------------- AOB- / Text-Suche
class SearchWindow(Tool):
    def __init__(self, app):
        super().__init__(app, "Muster- & Textsuche", "760x520")
        self.cancel = threading.Event()
        top = ttk.Frame(self, padding=6)
        top.pack(fill="x")
        self.kind = ttk.Combobox(top, state="readonly", width=18,
                                 values=["Byte-Muster (AOB)", "Text (UTF-8/ASCII)", "Text (UTF-16)"])
        self.kind.set("Byte-Muster (AOB)")
        self.kind.pack(side="left")
        self.q = ttk.Entry(top, width=40)
        self.q.pack(side="left", padx=4, fill="x", expand=True)
        self.q.bind("<Return>", lambda _: self.search())
        ttk.Label(top, text="Modul:").pack(side="left")
        self.mod = ttk.Combobox(top, width=18)
        self.mod.pack(side="left", padx=4)
        if app.proc:
            self.mod.config(values=[""] + [m[2] for m in app.proc.modules])
        self.btn = ttk.Button(top, text="Suchen", command=self.search)
        self.btn.pack(side="left")
        ttk.Label(self, text="AOB-Beispiel: 89 46 ?? 8B 45 F8   (?? = beliebig). Modul leer = ganzer Speicher. "
                             "Text-Suche ignoriert Groß/Klein.", foreground="#555").pack(anchor="w", padx=6)
        self.status = ttk.Label(self, text="")
        self.status.pack(anchor="w", padx=6)
        self.tv = ttk.Treeview(self, columns=("addr", "prev"), show="headings")
        self.tv.heading("addr", text="Adresse")
        self.tv.heading("prev", text="Vorschau")
        self.tv.column("addr", width=240)
        self.tv.column("prev", width=460)
        self.tv.pack(fill="both", expand=True, padx=6, pady=6)
        self.tv.bind("<Double-1>", lambda _: self.open_hex())
        bar = ttk.Frame(self, padding=(6, 0, 6, 6))
        bar.pack(fill="x")
        ttk.Button(bar, text="Im Speicher-Viewer öffnen", command=self.open_hex).pack(side="left")
        ttk.Button(bar, text="→ Adressliste", command=self.add).pack(side="left", padx=4)

    def search(self):
        p = self.app.proc
        if not p:
            return
        kind, q, mod = self.kind.get(), self.q.get(), self.mod.get().strip() or None
        try:
            if kind.startswith("Byte"):
                aob.parse_pattern(q)
        except ValueError as e:
            messagebox.showerror("Muster", str(e))
            return
        self.btn.config(state="disabled")
        self.status.config(text="Suche…")

        def work():
            if kind.startswith("Byte"):
                return aob.scan_aob(p, q, mod, limit=2000)
            return aob.scan_text(p, q, utf16="16" in kind, limit=2000)

        def done(hits, err):
            self.btn.config(state="normal")
            if err:
                self.status.config(text=f"Fehler: {err!r}")
                return
            self.status.config(text=f"{len(hits)} Treffer" + (" (Limit)" if len(hits) >= 2000 else ""))
            self.tv.delete(*self.tv.get_children())
            for a in hits:
                data = p.read_bytes(a, 24) or b""
                prev = data.hex(" ") if kind.startswith("Byte") else data.decode(
                    "utf-16-le" if "16" in kind else "utf-8", "replace")
                self.tv.insert("", "end", iid=str(a), values=(p.fmt_addr(a), prev))
        self.run_bg(work, done)

    def open_hex(self):
        sel = self.tv.selection()
        if sel:
            self.app.open_hex(int(sel[0]))

    def add(self):
        for iid in self.tv.selection():
            self.app.add_entry(new_entry(desc="Fund", expr=self.app.proc.fmt_addr(int(iid))))


# ---------------------------------------------------------------- Was schreibt/greift zu?
class WatchWindow(Tool):
    def __init__(self, app, addr, size=4, access="w"):
        what = "schreibt auf" if access == "w" else "greift zu auf"
        super().__init__(app, f"Was {what} {app.proc.fmt_addr(addr)}?", "860x420")
        self.watch = debugger.AccessWatcher(app.proc, addr, size, access)
        self.info = {}
        ttk.Label(self, text="Ändere den Wert jetzt im Spiel (z. B. Gold ausgeben). Gefundene Befehle erscheinen hier.\n"
                             "Achtung: Spiele mit Anti-Debug-Schutz können abstürzen.", foreground="#555",
                  padding=6).pack(anchor="w")
        self.tv = ttk.Treeview(self, columns=("n", "addr", "bytes", "ins"), show="headings")
        for c, t, w in (("n", "Anzahl", 70), ("addr", "Adresse", 230), ("bytes", "Bytes", 170), ("ins", "Befehl", 340)):
            self.tv.heading(c, text=t)
            self.tv.column(c, width=w, anchor="w")
        self.tv.pack(fill="both", expand=True, padx=6)
        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")
        self.btn_stop = ttk.Button(bar, text="Stopp", command=self.stop)
        self.btn_stop.pack(side="left")
        ttk.Button(bar, text="Befehl durch NOPs ersetzen → Adressliste", command=self.nop_entry).pack(side="left", padx=6)
        ttk.Button(bar, text="Im Disassembler zeigen", command=self.show).pack(side="left")
        self.status = ttk.Label(bar, text="Debugger läuft…", foreground="#070")
        self.status.pack(side="right")
        self.watch.start()
        self.every(300, self.refresh)

    def refresh(self):
        if self.watch.error:
            self.status.config(text=self.watch.error, foreground="#b00")
        elif not self.watch.running:
            self.status.config(text="Gestoppt", foreground="#555")
        for ip, n in list(self.watch.hits.items()):
            if ip not in self.info:
                self.info[ip] = debugger.find_instruction(self.app.proc, ip)
                ins = self.info[ip]
                start = ins[0] if ins else ip
                self.tv.insert("", "end", iid=str(ip), values=(
                    n, self.app.proc.fmt_addr(start), ins[2].hex(" ") if ins else "?",
                    ins[3] if ins else "(capstone fehlt / unbekannt)"))
            else:
                self.tv.set(str(ip), "n", n)

    def stop(self):
        self.watch.stop()
        self.btn_stop.config(state="disabled")

    def close(self):
        self.watch.stop()
        self.watch.join(3)
        super().close()

    def _selected(self):
        sel = self.tv.selection()
        if not sel:
            messagebox.showinfo("Hinweis", "Bitte einen Befehl auswählen.", parent=self)
            return None
        return self.info.get(int(sel[0]))

    def show(self):
        ins = self._selected()
        if ins:
            v = self.app.open_hex(ins[0])
            v.mode.set("asm")
            v.render()

    def nop_entry(self):
        ins = self._selected()
        if not ins:
            return
        p = self.app.proc
        start, size, data, text = ins
        loc = p.locate(start)
        sig = aob.make_signature(p, start, loc[0]) if loc else None
        self.app.add_entry(new_entry(
            desc=f"Patch: {text}", type=PATCH, expr=p.fmt_addr(start), orig=data.hex(), new="90" * size,
            aob=sig or "", aob_module=loc[0] if loc else "", aob_offset=0))
        messagebox.showinfo("Code-Patch", "Patch zur Adressliste hinzugefügt. Aktivieren = Befehl ausschalten "
                                          "(z. B. Gold wird nicht mehr abgezogen).", parent=self)


# ---------------------------------------------------------------- Speedhack
class SpeedWindow(Tool):
    PRESETS = (0.1, 0.25, 0.5, 1, 1.5, 2, 3, 5, 10)

    def __init__(self, app):
        super().__init__(app, "Speedhack", "480x400")
        self.var = tk.DoubleVar(value=(app.speed.get_speed() if app.speed else None) or 1.0)
        self._ready = False
        f = ttk.Frame(self, padding=10)
        f.pack(fill="both", expand=True)
        self.lbl = ttk.Label(f, text="", font=("Segoe UI", 16, "bold"))
        self.lbl.pack()
        self.scale = ttk.Scale(f, from_=-1.0, to=1.0, command=lambda v: self.apply(round(10 ** float(v), 2)))
        self.scale.pack(fill="x", pady=6)
        row = ttk.Frame(f)
        row.pack()
        for s in self.PRESETS:
            ttk.Button(row, text=f"{s}x", width=5, command=lambda s=s: self.apply(s)).pack(side="left", padx=1)
        ttk.Label(f, text="Wirkt auf QueryPerformanceCounter / GetTickCount / timeGetTime (64-bit Spiele).\n"
                          "Hotkeys für den Trainer legst du beim Export fest.", foreground="#555").pack(pady=(8, 0))

        cfg = app.settings.get("auto_inject", {})
        box = ttk.LabelFrame(f, text="Auto-Inject (beim Spielstart automatisch aktivieren)", padding=8)
        box.pack(fill="x", pady=(12, 0))
        self.auto_on = tk.BooleanVar(value=cfg.get("enabled", False))
        ttk.Checkbutton(box, text="Aktiv", variable=self.auto_on).grid(row=0, column=0, sticky="w")
        ttk.Label(box, text="Spiel (.exe):").grid(row=1, column=0, sticky="w", pady=(4, 0))
        self.auto_proc = ttk.Entry(box, width=26)
        self.auto_proc.insert(0, cfg.get("process") or (app.proc.name if app.proc else ""))
        self.auto_proc.grid(row=1, column=1, sticky="w", pady=(4, 0))
        ttk.Button(box, text="Aktuelles Spiel", command=self.use_current).grid(row=1, column=2, padx=4, pady=(4, 0))
        ttk.Label(box, text="Geschwindigkeit:").grid(row=2, column=0, sticky="w", pady=(4, 0))
        self.auto_speed = ttk.Entry(box, width=8)
        self.auto_speed.insert(0, f"{cfg.get('speed', 2.0):g}")
        self.auto_speed.grid(row=2, column=1, sticky="w", pady=(4, 0))
        ttk.Button(box, text="Übernehmen", command=self.save_auto).grid(row=3, column=0, columnspan=3, pady=(8, 0))
        ttk.Label(box, text="Tipp: Scanner zuerst starten, dann das Spiel – je früher der Inject, desto zuverlässiger.",
                  foreground="#555").grid(row=4, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self.show(self.var.get())
        self._ready = True

    def use_current(self):
        if self.app.proc:
            self.auto_proc.delete(0, "end")
            self.auto_proc.insert(0, self.app.proc.name)

    def save_auto(self):
        try:
            sp = float(self.auto_speed.get().replace(",", "."))
            if not 0.01 <= sp <= 100:
                raise ValueError
        except ValueError:
            messagebox.showerror("Auto-Inject", "Geschwindigkeit zwischen 0.01 und 100 angeben.", parent=self)
            return
        if self.auto_on.get() and not self.auto_proc.get().strip():
            messagebox.showerror("Auto-Inject", "Bitte den Namen der Spiel-.exe angeben.", parent=self)
            return
        self.app.set_auto_inject(self.auto_on.get(), self.auto_proc.get(), sp)
        if self.app.speed:
            self.show(self.app.speed.get_speed() or 1.0)

    def show(self, s):
        import math
        self.lbl.config(text=f"{s:g}x")
        self._ready, was = False, self._ready
        self.scale.set(math.log10(max(0.1, min(10, s))))
        self._ready = was

    def apply(self, s):
        if not self._ready or not self.app.ensure_speedhack():
            return
        self.app.speed.set_speed(s)
        self.var.set(s)
        self.show(s)


# ---------------------------------------------------------------- Eintrag bearbeiten
class EntryDialog(tk.Toplevel):
    def __init__(self, app, entry, groups, on_ok):
        super().__init__(app)
        self.title("Eintrag bearbeiten")
        self.transient(app)
        self.e, self.on_ok = entry, on_ok
        f = ttk.Frame(self, padding=10)
        f.pack(fill="both", expand=True)
        self.w = {}

        def row(r, label, widget, key):
            ttk.Label(f, text=label).grid(row=r, column=0, sticky="w", pady=2)
            widget.grid(row=r, column=1, sticky="ew", pady=2)
            self.w[key] = widget

        def entry(val, width=44):
            w = ttk.Entry(f, width=width)
            w.insert(0, "" if val is None else str(val))
            return w

        def combo(vals, val, ro=True):
            w = ttk.Combobox(f, values=vals, state="readonly" if ro else "normal", width=42)
            w.set(val)
            return w

        e = entry
        row(0, "Beschreibung", e(self.e["desc"]), "desc")
        row(1, "Adresse / Ausdruck", e(self.e["expr"]), "expr")
        row(2, "Typ", combo(ALL_TYPES, self.e["type"]), "type")
        row(3, "Gruppe", combo(groups, self.e["group"], ro=False), "group")
        row(4, "Einfrier-Modus", combo([f"{k}  {v}" for k, v in FREEZE_MODES.items()],
                                       f"{self.e['mode']}  {FREEZE_MODES[self.e['mode']]}"), "mode")
        row(5, "Einfrier-Wert", e(fmt_value(self.e["value"]) if self.e["value"] is not None else ""), "value")
        row(6, "Hotkey", combo([""] + list(HOTKEYS), self.e["hotkey"]), "hotkey")
        row(7, "Hotkey-Aktion", combo([f"{k}  {v}" for k, v in HK_ACTIONS.items()],
                                      f"{self.e['hk_action']}  {HK_ACTIONS[self.e['hk_action']]}"), "hk_action")
        row(8, "Hotkey-Wert", e("" if self.e["hk_value"] is None else fmt_value(self.e["hk_value"])), "hk_value")
        ttk.Separator(f).grid(row=9, column=0, columnspan=2, sticky="ew", pady=6)
        ttk.Label(f, text="Nur für Code-Patches:", foreground="#555").grid(row=10, column=0, sticky="w")
        row(11, "Original-Bytes (hex)", e(self.e["orig"]), "orig")
        row(12, "Patch-Bytes (hex)", e(self.e["new"]), "new")
        row(13, "Signatur (AOB)", e(self.e["aob"]), "aob")
        row(14, "Signatur-Modul", e(self.e["aob_module"]), "aob_module")
        bar = ttk.Frame(f)
        bar.grid(row=15, column=0, columnspan=2, pady=(10, 0))
        ttk.Button(bar, text="OK", command=self.ok).pack(side="left", padx=4)
        ttk.Button(bar, text="Abbrechen", command=self.destroy).pack(side="left")
        self.bind("<Return>", lambda _: self.ok())
        self.bind("<Escape>", lambda _: self.destroy())

    def ok(self):
        g = {k: w.get().strip() for k, w in self.w.items()}
        t = g["type"]
        try:
            num = None if t == PATCH else TYPES[t]
            val = parse_value(g["value"], num)[0] if g["value"] and num else None
            hkv = parse_value(g["hk_value"], num)[0] if g["hk_value"] and num else None
            if t == PATCH:
                o, n = bytes.fromhex(g["orig"]), bytes.fromhex(g["new"])
                if not o or len(o) != len(n):
                    raise ValueError("Original- und Patch-Bytes müssen gleich lang sein.")
                if g["aob"]:
                    aob.parse_pattern(g["aob"])
        except ValueError as ex:
            messagebox.showerror("Ungültig", str(ex), parent=self)
            return
        self.e.update(desc=g["desc"], expr=g["expr"], type=t, group=g["group"], mode=g["mode"].split()[0],
                      value=val if val is not None else (self.e["value"] if self.e["type"] == t else None),
                      hotkey=g["hotkey"], hk_action=g["hk_action"].split()[0], hk_value=hkv,
                      orig=g["orig"].replace(" ", ""), new=g["new"].replace(" ", ""),
                      aob=g["aob"], aob_module=g["aob_module"])
        self.on_ok(self.e)
        self.destroy()
