"""MemTrainer – Speicher-Scanner & Trainer-Baukasten fuer Singleplayer-Spiele (Windows).

Start:  python memtrainer.py   (Abhaengigkeiten: numpy, optional capstone + pyinstaller)
Hinweis: Nicht in Online-/Multiplayer-Spielen mit Anti-Cheat verwenden (Bann-Gefahr).
"""
import json
import os
import queue
import re
import shutil
import struct
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

import gui_tools as gt
from scanner_core import (FIRST_MODES, HOTKEYS, NEEDS_V1, NEXT_MODES, TYPES, Process, Scanner,
                          fmt_value, key_down, list_processes, parse_value, window_titles)
from trainer_core import (FREEZE_MODES, PATCH, CheatRunner, new_entry, parse_for_entry, table_from_json,
                          table_to_json)

RESULT_LIMIT = 500
SETTINGS_PATH = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "MemTrainer", "settings.json")
OLD_SETTINGS_PATH = os.path.join(os.environ.get("APPDATA", os.path.expanduser("~")), "UniversalScanner", "settings.json")


def load_settings():
    s = {"auto_inject": {"enabled": False, "process": "", "speed": 2.0}}
    for path in (SETTINGS_PATH, OLD_SETTINGS_PATH):  # alte Einstellungen (Universal Scanner) uebernehmen
        try:
            with open(path, encoding="utf-8") as f:
                s.update(json.load(f))
            break
        except (OSError, ValueError):
            continue
    return s


def save_settings(s):
    try:
        os.makedirs(os.path.dirname(SETTINGS_PATH), exist_ok=True)
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(s, f, indent=2)
    except OSError:
        pass
SRC_DIR = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
TRAINER_FILES = ("trainer_app.py", "scanner_core.py", "trainer_core.py", "aob.py", "speedhack.py")


class ProcessPicker(tk.Toplevel):
    def __init__(self, master, on_pick):
        super().__init__(master)
        self.title("Prozess wählen")
        self.geometry("560x520")
        self.transient(master)
        self.on_pick = on_pick
        self.filter = tk.StringVar()
        self.filter.trace_add("write", lambda *_: self.fill())
        self.only_windows = tk.BooleanVar(value=True)

        top = ttk.Frame(self, padding=(8, 8, 8, 4))
        top.pack(fill="x")
        ttk.Label(top, text="Filter (Name, PID oder Fenstertitel):").pack(anchor="w")
        row = ttk.Frame(top)
        row.pack(fill="x", pady=(2, 0))
        e = ttk.Entry(row, textvariable=self.filter)
        e.pack(side="left", fill="x", expand=True)
        e.focus_set()
        e.bind("<Down>", lambda _: self.move(1))
        e.bind("<Up>", lambda _: self.move(-1))
        e.bind("<Escape>", lambda _: self.filter.set("") if self.filter.get() else self.destroy())
        ttk.Button(row, text="✕", width=3, command=lambda: self.filter.set("")).pack(side="left", padx=(4, 0))
        ttk.Checkbutton(top, text="Nur Programme mit Fenster (Spiele, Apps)", variable=self.only_windows,
                        command=self.fill).pack(anchor="w", pady=(4, 0))

        self.tv = ttk.Treeview(self, columns=("name", "pid", "title"), show="headings", selectmode="browse")
        for c, t, w in (("name", "Prozess", 170), ("pid", "PID", 70), ("title", "Fenstertitel", 280)):
            self.tv.heading(c, text=t)
            self.tv.column(c, width=w, anchor="w")
        self.tv.pack(fill="both", expand=True, padx=8)
        self.tv.bind("<Double-1>", lambda _: self.pick())
        self.bind("<Return>", lambda _: self.pick())
        bar = ttk.Frame(self)
        bar.pack(fill="x", padx=8, pady=8)
        ttk.Button(bar, text="Aktualisieren", command=self.load).pack(side="left")
        self.count = ttk.Label(bar, foreground="#666")
        self.count.pack(side="left", padx=10)
        ttk.Button(bar, text="Öffnen", command=self.pick).pack(side="right")
        self.load()

    def load(self):
        titles = window_titles()
        self.procs = [(pid, name, titles.get(pid, "")) for pid, name in list_processes()]
        self.fill()

    def fill(self):
        words = self.filter.get().lower().split()
        self.tv.delete(*self.tv.get_children())
        n = 0
        for pid, name, title in self.procs:
            if self.only_windows.get() and not title:
                continue
            hay = f"{name} {pid} {title}".lower()
            if all(w in hay for w in words):
                self.tv.insert("", "end", iid=str(pid), values=(name, pid, title))
                n += 1
        self.count.config(text=f"{n} von {len(self.procs)} Prozessen")
        kids = self.tv.get_children()
        if kids:
            self.tv.selection_set(kids[0])

    def move(self, d):
        kids = self.tv.get_children()
        if not kids:
            return "break"
        sel = self.tv.selection()
        i = kids.index(sel[0]) + d if sel else 0
        i = max(0, min(len(kids) - 1, i))
        self.tv.selection_set(kids[i])
        self.tv.see(kids[i])
        return "break"

    def pick(self):
        sel = self.tv.selection()
        if sel:
            pid, name = int(sel[0]), self.tv.set(sel[0], "name")
            self.on_pick(pid, name)
            self.destroy()


class ExportDialog(tk.Toplevel):
    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.title("Trainer exportieren")
        self.transient(app)
        f = ttk.Frame(self, padding=12)
        f.pack(fill="both", expand=True)
        proc_name = app.proc.name if app.proc else app.table_process
        self.fields = {}

        def row(r, label, w, key):
            ttk.Label(f, text=label).grid(row=r, column=0, sticky="w", pady=3)
            w.grid(row=r, column=1, sticky="ew", pady=3)
            self.fields[key] = w

        def ent(v):
            w = ttk.Entry(f, width=40)
            w.insert(0, v)
            return w

        row(0, "Name des Trainers", ent(os.path.splitext(proc_name)[0] + " Trainer" if proc_name else "Mein Trainer"), "title")
        row(1, "Spiel-Prozess (.exe)", ent(proc_name or ""), "process")
        sp = ttk.Combobox(f, values=[""] + list(HOTKEYS), state="readonly", width=38)
        row(2, "Speedhack-Hotkey (optional)", sp, "speed_key")
        auto = app.settings.get("auto_inject", {})
        row(3, "Speedhack-Faktor", ent(f"{auto.get('speed', 2.0):g}"), "speed_factor")
        self.speed_auto = tk.BooleanVar(value=bool(auto.get("enabled")) and
                                        auto.get("process", "").lower() == (proc_name or "").lower())
        ttk.Checkbutton(f, text="Speedhack beim Spielstart automatisch aktivieren (Auto-Inject)",
                        variable=self.speed_auto).grid(row=10, column=0, columnspan=3, sticky="w")
        row(4, "Zielordner", ent(os.path.join(os.path.expanduser("~"), "Desktop")), "dir")
        ttk.Button(f, text="…", width=3, command=self.browse).grid(row=4, column=2, padx=(4, 0))
        self.exe = tk.BooleanVar(value=not getattr(sys, "frozen", False) or bool(shutil.which("python")))
        ttk.Checkbutton(f, text="Als .exe bauen (PyInstaller, dauert ~1 Minute)", variable=self.exe).grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(6, 0))
        self.admin = tk.BooleanVar(value=False)
        ttk.Checkbutton(f, text="Trainer immer als Administrator starten (nötig, wenn das Spiel als Admin läuft)",
                        variable=self.admin).grid(row=9, column=0, columnspan=3, sticky="w")
        ttk.Label(f, text="Exportiert werden alle Einträge der Adressliste inkl. Hotkeys, Einfrier-Werten und Patches.\n"
                          "Der Trainer verbindet sich automatisch, sobald das Spiel läuft.",
                  foreground="#555").grid(row=6, column=0, columnspan=3, sticky="w", pady=(8, 0))
        self.status = ttk.Label(f, text="")
        self.status.grid(row=7, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self.btn = ttk.Button(f, text="Exportieren", command=self.export)
        self.btn.grid(row=8, column=0, columnspan=3, pady=(10, 0))

    def browse(self):
        d = filedialog.askdirectory(parent=self)
        if d:
            self.fields["dir"].delete(0, "end")
            self.fields["dir"].insert(0, d)

    def export(self):
        g = {k: w.get().strip() for k, w in self.fields.items()}
        if not g["title"] or not g["process"]:
            messagebox.showerror("Export", "Name und Spiel-Prozess angeben.", parent=self)
            return
        try:
            factor = float(g["speed_factor"].replace(",", "."))
        except ValueError:
            messagebox.showerror("Export", "Speedhack-Faktor ungültig.", parent=self)
            return
        safe = re.sub(r"[^\w\- ]", "", g["title"]).strip() or "Trainer"
        out = os.path.join(g["dir"], safe)
        os.makedirs(out, exist_ok=True)
        auto = self.speed_auto.get()
        speed = {"hotkey": g["speed_key"], "factor": factor, "auto": auto} if g["speed_key"] or auto else {}
        entries = []
        for e in self.app.ordered_entries():
            e = dict(e)
            if e["type"] != PATCH and e["active"] and e["value"] is None:
                e["active"] = False
            entries.append(e)
        table = table_to_json(entries, g["process"], g["title"], speed)
        with open(os.path.join(out, "table.json"), "w", encoding="utf-8") as fh:
            json.dump(table, fh, indent=2, ensure_ascii=False)
        for fn in TRAINER_FILES:
            shutil.copy(os.path.join(SRC_DIR, fn), os.path.join(out, fn))
        with open(os.path.join(out, "Trainer starten.bat"), "w", encoding="utf-8") as fh:
            fh.write('@echo off\ncd /d "%~dp0"\nstart "" pythonw trainer_app.py table.json\n')
        if not self.exe.get():
            self.status.config(text=f"Fertig: {out}")
            return
        py = sys.executable if not getattr(sys, "frozen", False) else shutil.which("python")
        if not py:
            self.status.config(text="Kein Python gefunden – nur Quelldateien exportiert.")
            return
        self.btn.config(state="disabled")
        self.status.config(text="Baue .exe … (bitte warten)")
        cmd = [py, "-m", "PyInstaller", "--noconfirm", "--onefile", "--windowed",
               "--name", safe, "--add-data", "table.json;.", "trainer_app.py"]
        if self.admin.get():
            cmd.insert(5, "--uac-admin")

        def work():
            r = subprocess.run(cmd, cwd=out, capture_output=True, text=True,
                               creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            return r.returncode, r.stderr[-1500:]

        def poll(t, box):
            if t.is_alive():
                self.after(300, poll, t, box)
                return
            self.btn.config(state="normal")
            code, err = box.get("r", (1, "unbekannter Fehler"))
            exe = os.path.join(out, "dist", safe + ".exe")
            if code == 0 and os.path.exists(exe):
                self.status.config(text=f"Fertig: {exe}")
                messagebox.showinfo("Trainer", f"Trainer erstellt:\n{exe}", parent=self)
            else:
                self.status.config(text="Build fehlgeschlagen (Quelldateien liegen trotzdem im Ordner).")
                messagebox.showerror("PyInstaller", err or "Fehler", parent=self)

        box = {}
        t = threading.Thread(target=lambda: box.update(r=work()), daemon=True)
        t.start()
        poll(t, box)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("MemTrainer")
        self.geometry("1040x760")
        self.minsize(860, 580)
        self.proc = None
        self.runner = None
        self.speed = None
        self.scanner = None
        self.worker = None
        self.cancel = threading.Event()
        self.q = queue.Queue()
        self.entries = {}  # iid -> entry dict
        self.next_iid = 0
        self.key_state = {}
        self.ticks = 0
        self.table_process = ""
        self.speed_cfg = {}
        self.settings = load_settings()
        self.auto_msg = ""
        self.build()
        self.after(100, self.tick)

    # ---------------- UI ----------------
    def build(self):
        mb = tk.Menu(self)
        m = tk.Menu(mb, tearoff=0)
        m.add_command(label="Prozess wählen…", command=self.choose_process)
        m.add_separator()
        m.add_command(label="Tabelle laden…", command=self.load_table)
        m.add_command(label="Tabelle speichern…", command=self.save_table)
        m.add_command(label="Trainer exportieren…", command=lambda: ExportDialog(self))
        m.add_separator()
        m.add_command(label="Beenden", command=self.destroy)
        mb.add_cascade(label="Datei", menu=m)
        w = tk.Menu(mb, tearoff=0)
        w.add_command(label="Speicher-Viewer / Disassembler", command=lambda: self.need_proc() and self.open_hex())
        w.add_command(label="Pointer-Scanner", command=lambda: self.need_proc() and gt.PointerScanWindow(self))
        w.add_command(label="Muster- & Textsuche (AOB)", command=lambda: self.need_proc() and gt.SearchWindow(self))
        w.add_command(label="Speedhack / Auto-Inject", command=lambda: gt.SpeedWindow(self))
        mb.add_cascade(label="Werkzeuge", menu=w)
        self.config(menu=mb)

        top = ttk.Frame(self, padding=(8, 8, 8, 0))
        top.pack(fill="x")
        ttk.Button(top, text="Prozess wählen…", command=self.choose_process).pack(side="left")
        self.proc_lbl = ttk.Label(top, text="Kein Prozess verbunden", foreground="#b00")
        self.proc_lbl.pack(side="left", padx=10)
        self.auto_lbl = ttk.Label(top, text="", foreground="#06c")
        self.auto_lbl.pack(side="left", padx=6)
        for txt, cmd in (("Speedhack", lambda: gt.SpeedWindow(self)),
                         ("Pointer-Scan", lambda: self.need_proc() and gt.PointerScanWindow(self)),
                         ("Suche (AOB/Text)", lambda: self.need_proc() and gt.SearchWindow(self)),
                         ("Speicher-Viewer", lambda: self.need_proc() and self.open_hex())):
            ttk.Button(top, text=txt, command=cmd).pack(side="right", padx=(4, 0))

        pw = ttk.PanedWindow(self, orient="vertical")
        pw.pack(fill="both", expand=True, padx=8, pady=8)
        upper = ttk.Frame(pw)
        pw.add(upper, weight=3)

        left = ttk.Frame(upper)
        left.pack(side="left", fill="both", expand=True)
        self.count_lbl = ttk.Label(left, text="Treffer: 0")
        self.count_lbl.pack(anchor="w")
        self.res = ttk.Treeview(left, columns=("addr", "val", "prev"), show="headings", selectmode="extended")
        for c, t, wd in (("addr", "Adresse", 220), ("val", "Wert", 120), ("prev", "Vorher", 120)):
            self.res.heading(c, text=t)
            self.res.column(c, width=wd, anchor="w")
        sb = ttk.Scrollbar(left, command=self.res.yview)
        self.res.configure(yscrollcommand=sb.set)
        sb.pack(side="right", fill="y")
        self.res.pack(fill="both", expand=True)
        self.res.bind("<Double-1>", lambda _: self.add_selected())
        self.res.bind("<Button-3>", self.res_menu)

        right = ttk.Frame(upper, padding=(12, 0, 0, 0))
        right.pack(side="right", fill="y")
        ttk.Label(right, text="Wert").grid(row=0, column=0, sticky="w")
        self.v1 = ttk.Entry(right, width=22)
        self.v1.grid(row=1, column=0, columnspan=2, sticky="ew")
        self.v1.bind("<Return>", lambda _: self.scan())
        ttk.Label(right, text="bis (nur bei „Zwischen“)").grid(row=2, column=0, sticky="w", pady=(6, 0))
        self.v2 = ttk.Entry(right, width=22)
        self.v2.grid(row=3, column=0, columnspan=2, sticky="ew")
        ttk.Label(right, text="Scan-Art").grid(row=4, column=0, sticky="w", pady=(6, 0))
        self.mode = ttk.Combobox(right, values=FIRST_MODES, state="readonly", width=20)
        self.mode.set("Exakter Wert")
        self.mode.grid(row=5, column=0, columnspan=2, sticky="ew")
        ttk.Label(right, text="Datentyp").grid(row=6, column=0, sticky="w", pady=(6, 0))
        self.vtype = ttk.Combobox(right, values=list(TYPES), state="readonly", width=20)
        self.vtype.set("4 Bytes")
        self.vtype.grid(row=7, column=0, columnspan=2, sticky="ew")
        self.mapped = tk.BooleanVar(value=False)
        ttk.Checkbutton(right, text="Gemappten Speicher mitscannen", variable=self.mapped).grid(
            row=8, column=0, columnspan=2, sticky="w", pady=(6, 0))
        self.btn_scan = ttk.Button(right, text="Erster Scan", command=self.scan)
        self.btn_scan.grid(row=9, column=0, sticky="ew", pady=(12, 0))
        self.btn_new = ttk.Button(right, text="Neuer Scan", command=self.new_scan)
        self.btn_new.grid(row=9, column=1, sticky="ew", pady=(12, 0), padx=(4, 0))
        self.btn_undo = ttk.Button(right, text="Rückgängig", command=self.undo_scan)
        self.btn_undo.grid(row=10, column=0, sticky="ew", pady=(4, 0))
        self.btn_cancel = ttk.Button(right, text="Abbrechen", command=self.cancel.set, state="disabled")
        self.btn_cancel.grid(row=10, column=1, sticky="ew", pady=(4, 0), padx=(4, 0))
        self.pb = ttk.Progressbar(right, maximum=1.0)
        self.pb.grid(row=11, column=0, columnspan=2, sticky="ew", pady=(8, 0))
        self.status = ttk.Label(right, text="", wraplength=200, foreground="#555")
        self.status.grid(row=12, column=0, columnspan=2, sticky="w", pady=(4, 0))
        ttk.Button(right, text="Auswahl → Liste", command=self.add_selected).grid(
            row=13, column=0, columnspan=2, sticky="ew", pady=(14, 0))
        help_txt = ("So geht's:\n1. Prozess wählen\n2. Wert eingeben → Erster Scan\n"
                    "3. Wert im Spiel ändern → Nächster Scan\n4. Wiederholen bis wenige Treffer\n"
                    "5. Doppelklick → Liste\n6. Rechtsklick: Pointer-Scan, Was schreibt hierhin?…\n"
                    "7. Datei → Trainer exportieren")
        ttk.Label(right, text=help_txt, wraplength=210, foreground="#666", justify="left").grid(
            row=14, column=0, columnspan=2, sticky="w", pady=(14, 0))

        lower = ttk.Frame(pw)
        pw.add(lower, weight=2)
        bar = ttk.Frame(lower)
        bar.pack(fill="x", pady=(0, 4))
        ttk.Label(bar, text="Adressliste  (Doppelklick: Wert/Ein-Aus · Rechtsklick: mehr)").pack(side="left")
        for txt, cmd in (("Trainer exportieren…", lambda: ExportDialog(self)), ("Laden", self.load_table),
                         ("Speichern", self.save_table), ("Entfernen", self.remove_entries),
                         ("Gruppe +", self.add_group), ("Adresse +", self.add_manual)):
            ttk.Button(bar, text=txt, command=cmd).pack(side="right", padx=(4, 0))
        cols = (("frz", "Aktiv", 70), ("desc", "Beschreibung", 240), ("addr", "Adresse", 260),
                ("type", "Typ", 90), ("val", "Wert", 120), ("key", "Hotkey", 110))
        self.tab = ttk.Treeview(lower, columns=[c[0] for c in cols], show="tree headings", height=8)
        self.tab.column("#0", width=24, stretch=False)
        for c, t, wd in cols:
            self.tab.heading(c, text=t)
            self.tab.column(c, width=wd, anchor="w")
        self.tab.tag_configure("group", font=("Segoe UI", 9, "bold"))
        self.tab.pack(fill="both", expand=True)
        self.tab.bind("<Double-1>", self.dbl_entry)
        self.tab.bind("<Button-3>", self.tab_menu)
        self.tab.bind("<space>", lambda _: [self.toggle(i) for i in self.tab.selection()])
        self.tab.bind("<Delete>", lambda _: self.remove_entries())
        self.tab.bind("<Return>", lambda _: self.edit_selected())
        self.update_buttons()

    def need_proc(self):
        if not self.proc:
            messagebox.showinfo("Hinweis", "Bitte zuerst einen Prozess wählen.")
            return False
        return True

    # ---------------- Prozess ----------------
    def choose_process(self):
        ProcessPicker(self, self.attach)

    def attach(self, pid, name):
        try:
            proc = Process(pid, name)
        except OSError as e:
            messagebox.showerror("Fehler", str(e))
            return
        self.attach_proc(proc)

    def attach_proc(self, proc):
        pid, name = proc.pid, proc.name
        if self.proc:
            self.proc.close()
        self.proc, self.runner, self.speed = proc, CheatRunner(proc), None
        self.new_scan()
        bits = "32-bit" if proc.is32 else "64-bit"
        self.proc_lbl.config(text=f"Verbunden: {name} (PID {pid}, {bits})", foreground="#070")
        for e in self.entries.values():
            if e["type"] != PATCH:
                e["active"] = e["active"] and e["value"] is not None
            else:
                e["active"] = False
        self.render_all()

    def ensure_speedhack(self, quiet=False):
        if self.speed:
            return True
        if not self.proc:
            if not quiet:
                self.need_proc()
            return False
        try:
            from speedhack import SpeedHack
            self.speed = SpeedHack(self.proc)
            return True
        except Exception as e:  # noqa: BLE001
            if quiet:
                self.auto_msg = f"Speedhack: {e}"
            else:
                messagebox.showerror("Speedhack", str(e))
            return False

    def set_auto_inject(self, enabled, process, speed):
        self.settings["auto_inject"] = {"enabled": enabled, "process": process.strip(), "speed": speed}
        save_settings(self.settings)
        self.auto_msg = ""
        self.auto_inject_tick()

    def auto_inject_tick(self):
        """Wartet auf das eingestellte Spiel, verbindet sich und aktiviert den Speedhack automatisch."""
        cfg = self.settings.get("auto_inject", {})
        name = cfg.get("process", "").lower()
        if not cfg.get("enabled") or not name:
            self.auto_lbl.config(text="")
            return
        sp = cfg.get("speed", 2.0)
        if self.proc and self.proc.name.lower() == name and self.proc.alive():
            if not self.speed and self.ensure_speedhack(quiet=True):
                self.speed.set_speed(sp)
                self.auto_msg = ""
            txt = f"⚡ Auto-Inject aktiv: {sp:g}x" if self.speed else f"⚡ {self.auto_msg or 'Inject…'}"
            self.auto_lbl.config(text=txt)
            return
        if self.proc and self.proc.alive():
            self.auto_lbl.config(text=f"⚡ Auto-Inject wartet (verbunden mit anderem Prozess)")
            return
        for pid, n in list_processes():
            if n.lower() == name:
                try:
                    proc = Process(pid, n)
                except OSError as e:
                    self.auto_lbl.config(text=f"⚡ {e}")
                    return
                self.attach_proc(proc)
                self.auto_inject_tick()
                return
        self.auto_lbl.config(text=f"⚡ Auto-Inject wartet auf {cfg['process']} ({sp:g}x)")

    def open_hex(self, addr=None):
        return gt.HexViewer(self, addr)

    # ---------------- Scannen ----------------
    def new_scan(self):
        if self.worker:
            return
        self.scanner = None
        self.res.delete(*self.res.get_children())
        self.count_lbl.config(text="Treffer: 0")
        self.status.config(text="")
        self.pb["value"] = 0
        self.update_buttons()

    def undo_scan(self):
        if self.scanner and not self.worker and self.scanner.undo():
            self.status.config(text=f"Zurück zu Scan {self.scanner.scans}")
            self.show_results()
        self.update_buttons()

    def update_buttons(self):
        busy = self.worker is not None
        first = self.scanner is None
        self.btn_scan.config(text="Erster Scan" if first else "Nächster Scan", state="disabled" if busy else "normal")
        self.btn_new.config(state="disabled" if busy or first else "normal")
        self.btn_undo.config(state="normal" if not busy and self.scanner and self.scanner.history else "disabled")
        self.btn_cancel.config(state="normal" if busy else "disabled")
        self.vtype.config(state="readonly" if first and not busy else "disabled")
        modes = FIRST_MODES if first else NEXT_MODES
        self.mode.config(values=modes)
        if self.mode.get() not in modes:
            self.mode.set("Exakter Wert")

    def scan(self):
        if self.worker:
            return
        if not self.proc or not self.proc.alive():
            messagebox.showinfo("Hinweis", "Bitte zuerst einen (laufenden) Prozess wählen.")
            return
        mode = self.mode.get()
        dtype = TYPES[self.vtype.get()]
        v1 = v2 = None
        tol = 0
        try:
            if mode in NEEDS_V1:
                v1, tol = parse_value(self.v1.get(), dtype)
            if mode == "Zwischen":
                v2, tol2 = parse_value(self.v2.get(), dtype)
                tol = max(tol, tol2)
        except ValueError as e:
            messagebox.showerror("Ungültiger Wert", str(e))
            return
        first = self.scanner is None
        sc = self.scanner or Scanner(self.proc, self.vtype.get(), self.mapped.get())
        self.cancel.clear()
        self.status.config(text="Scanne…")
        fn = sc.first_scan if first else sc.next_scan

        def run():
            try:
                ok = fn(mode, v1, v2, tol, progress=lambda f: self.q.put(("p", f)), cancel=self.cancel)
                self.q.put(("done", (sc, ok, None)))
            except Exception as e:  # noqa: BLE001
                self.q.put(("done", (sc, False, e)))

        self.worker = threading.Thread(target=run, daemon=True)
        self.worker.start()
        self.update_buttons()

    def scan_finished(self, sc, ok, err):
        self.worker = None
        if err:
            messagebox.showerror("Scan-Fehler", repr(err))
        elif ok:
            self.scanner = sc
        self.status.config(text="Abgebrochen" if not ok and not err else f"Scan {sc.scans} fertig")
        self.update_buttons()
        self.show_results()

    def show_results(self):
        self.res.delete(*self.res.get_children())
        if not self.scanner:
            return
        n = self.scanner.count()
        if not self.scanner.listable():
            self.count_lbl.config(text=f"Treffer: {n:,} – zu viele zum Anzeigen, weiter eingrenzen".replace(",", "."))
            return
        rows = self.scanner.results(RESULT_LIMIT)
        extra = f" (zeige {len(rows)})" if n > len(rows) else ""
        self.count_lbl.config(text=f"Treffer: {n:,}{extra}".replace(",", "."))
        for addr, prev in rows:
            self.res.insert("", "end", iid=str(addr),
                            values=(self.proc.fmt_addr(addr), fmt_value(prev), fmt_value(prev)))

    def refresh_results(self):
        if not self.proc or not self.scanner:
            return
        dt = self.scanner.dtype
        for iid in self.res.get_children():
            v = self.proc.read_value(int(iid), dt)
            self.res.set(iid, "val", "??" if v is None else fmt_value(v))

    def res_menu(self, ev):
        iid = self.res.identify_row(ev.y)
        if not iid:
            return
        if iid not in self.res.selection():
            self.res.selection_set(iid)
        a = int(iid)
        size = self.scanner.size if self.scanner else 4
        tname = self.scanner.type_name if self.scanner else "4 Bytes"
        m = tk.Menu(self, tearoff=0)
        m.add_command(label="→ Adressliste", command=self.add_selected)
        m.add_command(label="Im Speicher-Viewer öffnen", command=lambda: self.open_hex(a))
        m.add_separator()
        m.add_command(label="Was schreibt auf diese Adresse?", command=lambda: gt.WatchWindow(self, a, size, "w"))
        m.add_command(label="Was greift auf diese Adresse zu?", command=lambda: gt.WatchWindow(self, a, size, "rw"))
        m.add_command(label="Pointer-Scan für diese Adresse", command=lambda: gt.PointerScanWindow(self, a, tname))
        m.tk_popup(ev.x_root, ev.y_root)

    # ---------------- Adressliste ----------------
    def group_iid(self, name):
        if not name:
            return ""
        iid = "g:" + name
        if not self.tab.exists(iid):
            self.tab.insert("", "end", iid=iid, open=True, values=("", name, "", "", "", ""), tags=("group",))
        return iid

    def groups(self):
        return [i[2:] for i in self.tab.get_children() if i.startswith("g:")]

    def add_group(self):
        name = simpledialog.askstring("Neue Gruppe", "Name der Gruppe:", parent=self)
        if name:
            self.group_iid(name.strip())

    def add_entry(self, e):
        iid = f"e{self.next_iid}"
        self.next_iid += 1
        self.entries[iid] = e
        self.tab.insert(self.group_iid(e["group"]), "end", iid=iid, values=("",) * 6)
        self.render_entry(iid)
        return iid

    def add_selected(self):
        if not self.scanner or not self.proc:
            return
        for iid in self.res.selection():
            self.add_entry(new_entry(expr=self.proc.fmt_addr(int(iid)), type=self.scanner.type_name))

    def add_manual(self):
        e = new_entry()
        gt.EntryDialog(self, e, self.groups(), lambda e: self.add_entry(e))

    def ordered_entries(self):
        out = []
        for top in self.tab.get_children():
            kids = self.tab.get_children(top) if top.startswith("g:") else [top]
            out.extend(self.entries[k] for k in kids if k in self.entries)
        return out

    def render_entry(self, iid):
        e = self.entries[iid]
        val = self.runner.display(e) if self.runner else "??"
        act = ("☑" if e["active"] else "☐") + ("" if e["mode"] == "=" or e["type"] == PATCH else f" {e['mode']}")
        key = e["hotkey"]
        if key and e["hk_action"] != "toggle" and e["type"] != PATCH:
            key += f" ({'=' if e['hk_action'] == 'set' else '+'}{fmt_value(e['hk_value']) if e['hk_value'] is not None else '?'})"
        self.tab.item(iid, values=(act, e["desc"], e["expr"], e["type"], val, key))

    def render_all(self):
        for iid in self.entries:
            self.render_entry(iid)

    def selected_entries(self):
        out = []
        for i in self.tab.selection():
            if i.startswith("g:"):
                out.extend(k for k in self.tab.get_children(i) if k in self.entries)
            elif i in self.entries:
                out.append(i)
        return list(dict.fromkeys(out))

    def remove_entries(self):
        for i in self.tab.selection():
            if not self.tab.exists(i):
                continue
            if i.startswith("g:"):
                for k in self.tab.get_children(i):
                    self.entries.pop(k, None)
            self.entries.pop(i, None)
            self.tab.delete(i)

    def toggle(self, iid):
        if not self.runner:
            return
        if iid.startswith("g:"):
            kids = [k for k in self.tab.get_children(iid) if k in self.entries]
            on = not all(self.entries[k]["active"] for k in kids)
            for k in kids:
                if self.entries[k]["active"] != on:
                    self.runner.set_active(self.entries[k], on)
                    self.render_entry(k)
            return
        e = self.entries[iid]
        if not self.runner.set_active(e, not e["active"]):
            messagebox.showwarning("Hinweis", "Adresse nicht lesbar/schreibbar (Spiel neu gestartet? Pointer ungültig?).")
        self.render_entry(iid)

    def change_value(self, iid):
        e = self.entries[iid]
        if not self.runner or e["type"] == PATCH:
            return
        s = simpledialog.askstring("Wert ändern", f"Neuer Wert für „{e['desc']}“:", parent=self)
        if s is None:
            return
        try:
            v = parse_for_entry(e, s)
        except ValueError as ex:
            messagebox.showerror("Ungültiger Wert", str(ex))
            return
        if not self.runner.write(e, v):
            messagebox.showerror("Fehler", "Schreiben fehlgeschlagen.")
        if e["active"]:
            e["value"] = v
        self.render_entry(iid)

    def edit(self, iid):
        e = self.entries[iid]
        old_group = e["group"]

        def done(e):
            if e["group"] != old_group:
                self.tab.move(iid, self.group_iid(e["group"]), "end")
            if self.runner:
                self.runner._patch_addr.pop(id(e), None)
            self.render_entry(iid)
        gt.EntryDialog(self, e, self.groups(), done)

    def edit_selected(self):
        sel = [i for i in self.tab.selection() if i in self.entries]
        if sel:
            self.edit(sel[0])

    def dbl_entry(self, ev):
        iid = self.tab.identify_row(ev.y)
        col = self.tab.identify_column(ev.x)
        if not iid:
            return
        if iid.startswith("g:"):
            if col == "#1":
                self.toggle(iid)
            return
        if col == "#1":
            self.toggle(iid)
        elif col == "#5" and self.entries[iid]["type"] != PATCH:
            self.change_value(iid)
        else:
            self.edit(iid)

    def tab_menu(self, ev):
        iid = self.tab.identify_row(ev.y)
        if not iid:
            return
        if iid not in self.tab.selection():
            self.tab.selection_set(iid)
        m = tk.Menu(self, tearoff=0)
        if iid.startswith("g:"):
            m.add_command(label="Gruppe ein/aus", command=lambda: self.toggle(iid))
            m.add_command(label="Gruppe umbenennen…", command=lambda: self.rename_group(iid))
            m.add_command(label="Gruppe entfernen (mit Einträgen)", command=self.remove_entries)
            m.tk_popup(ev.x_root, ev.y_root)
            return
        e = self.entries[iid]
        addr = self.runner.address(e) if self.runner else None
        size = 1 if e["type"] == PATCH else struct.calcsize({"Byte": "B", "2 Bytes": "h", "4 Bytes": "i",
                                                             "8 Bytes": "q", "Float": "f", "Double": "d"}[e["type"]])
        m.add_command(label="Ein/Aus", command=lambda: self.toggle(iid))
        if e["type"] != PATCH:
            m.add_command(label="Wert ändern…", command=lambda: self.change_value(iid))
        m.add_command(label="Bearbeiten… (Hotkey, Modus, Gruppe)", command=lambda: self.edit(iid))
        if addr is not None:
            m.add_separator()
            m.add_command(label="Im Speicher-Viewer öffnen", command=lambda: self.open_hex(addr))
            if e["type"] != PATCH:
                m.add_command(label="Was schreibt auf diese Adresse?", command=lambda: gt.WatchWindow(self, addr, size, "w"))
                m.add_command(label="Was greift auf diese Adresse zu?", command=lambda: gt.WatchWindow(self, addr, size, "rw"))
                m.add_command(label="Pointer-Scan für diese Adresse",
                              command=lambda: gt.PointerScanWindow(self, addr, e["type"]))
        m.add_separator()
        gm = tk.Menu(m, tearoff=0)
        for g in [""] + self.groups():
            gm.add_command(label=g or "(keine Gruppe)", command=lambda g=g: self.set_group(g))
        m.add_cascade(label="In Gruppe verschieben", menu=gm)
        m.add_command(label="Entfernen", command=self.remove_entries)
        m.tk_popup(ev.x_root, ev.y_root)

    def set_group(self, g):
        for iid in self.selected_entries():
            self.entries[iid]["group"] = g
            self.tab.move(iid, self.group_iid(g), "end")

    def rename_group(self, giid):
        name = simpledialog.askstring("Gruppe umbenennen", "Neuer Name:", initialvalue=giid[2:], parent=self)
        if not name or name == giid[2:]:
            return
        new = self.group_iid(name.strip())
        for k in self.tab.get_children(giid):
            self.entries[k]["group"] = name.strip()
            self.tab.move(k, new, "end")
        self.tab.delete(giid)

    # ---------------- Tabellen ----------------
    def save_table(self):
        path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("Tabelle", "*.json")])
        if not path:
            return
        proc = self.proc.name if self.proc else self.table_process
        data = table_to_json(self.ordered_entries(), proc, speed=self.speed_cfg)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    def load_table(self):
        path = filedialog.askopenfilename(filetypes=[("Tabelle", "*.json")])
        if not path:
            return
        try:
            with open(path, encoding="utf-8") as f:
                t = table_from_json(json.load(f))
        except (OSError, ValueError, KeyError, TypeError) as ex:
            messagebox.showerror("Fehler", f"Tabelle konnte nicht geladen werden: {ex}")
            return
        self.table_process, self.speed_cfg = t["process"], t["speed"]
        for e in t["entries"]:
            if e["type"] == PATCH:
                e["active"] = False
            self.add_entry(e)

    # ---------------- Hauptschleife ----------------
    def tick(self):
        try:
            while True:
                kind, val = self.q.get_nowait()
                if kind == "p":
                    self.pb["value"] = val
                else:
                    self.scan_finished(*val)
        except queue.Empty:
            pass

        if self.proc:
            for iid, e in list(self.entries.items()):
                k = e["hotkey"]
                if k:
                    down = key_down(HOTKEYS[k])
                    if down and not self.key_state.get((iid, k)):
                        self.runner.hotkey(e)
                        self.render_entry(iid)
                    self.key_state[(iid, k)] = down
            self.runner.tick(self.entries.values())
            self.ticks += 1
            if self.ticks % 20 == 0:
                if not self.proc.alive():
                    self.proc_lbl.config(text=f"{self.proc.name} wurde beendet", foreground="#b00")
                    self.proc.close()
                    self.proc = self.runner = self.speed = None
                else:
                    self.render_all()
                    if not self.worker:
                        self.refresh_results()
            if self.speed:
                self.speed.maybe_hook_new_modules()
        self.ticks += 0 if self.proc else 1
        if self.ticks % 10 == 0:
            self.auto_inject_tick()
        self.after(50, self.tick)


if __name__ == "__main__":
    if struct.calcsize("P") != 8:
        sys.exit("Bitte 64-bit Python verwenden.")
    App().mainloop()
