"""Aktionen: Spiel-Methoden (Unity/IL2CPP) per Knopf, Hotkey oder Timer auslösen – z. B. Kill-all.

Eine Aktion ist ein Aufruf wie  GameManager::RosaryDamage(true, 1.8)  (mehrere mit ';' getrennt).
Ausgeführt wird im Hauptthread des Spiels (siehe remote.MainThreadHook), in einem eigenen
Hintergrund-Thread von MemTrainer, damit die Oberfläche nicht hängt.
"""
import queue
import threading
import time
import tkinter as tk
from tkinter import messagebox, ttk

from gui_tools import Tool
from scanner_core import HOTKEYS, key_down
from trainer_core import new_action


class ActionExecutor:
    """Arbeitet Aktionen nacheinander ab und meldet Ergebnisse über app.q ('a', (aktion, text, ok))."""

    def __init__(self, app):
        self.app = app
        self.jobs = queue.Queue()
        self.busy = set()
        threading.Thread(target=self._loop, daemon=True).start()

    def submit(self, action):
        if id(action) in self.busy:
            return False  # läuft noch (z. B. Timer schneller als das Spiel)
        self.busy.add(id(action))
        self.jobs.put(action)
        return True

    def _loop(self):
        while True:
            a = self.jobs.get()
            try:
                u = self.app.unity
                if u is None:
                    raise RuntimeError("Unity-Daten werden noch geladen…")
                t0 = time.time()
                res = u.run_call(a["call"])
                text, ok = f"OK ({len(res)} Aufruf{'e' if len(res) != 1 else ''}, {time.time() - t0:.2f} s)", True
            except Exception as e:  # noqa: BLE001 - Meldung für die Oberfläche
                text, ok = f"Fehler: {e}", False
            finally:
                self.busy.discard(id(a))
            self.app.q.put(("a", (a, text, ok)))


class ActionScheduler:
    """Hotkeys und Timer der Aktionen (wird aus App.tick aufgerufen)."""

    def __init__(self, app):
        self.app = app
        self.keys = {}
        self.due = {}

    def tick(self, actions):
        now = time.time()
        for a in actions:
            k = a.get("hotkey")
            if k in HOTKEYS:
                down = key_down(HOTKEYS[k])
                if down and not self.keys.get(id(a)):
                    self.app.run_action(a)
                self.keys[id(a)] = down
            if a.get("timer") and float(a.get("interval") or 0) > 0:
                if now >= self.due.get(id(a), 0):
                    self.due[id(a)] = now + float(a["interval"])
                    self.app.run_action(a)
            else:
                self.due.pop(id(a), None)


class ActionDialog(tk.Toplevel):
    def __init__(self, master, action, on_ok):
        super().__init__(master)
        self.title("Aktion")
        self.transient(master)
        self.action, self.on_ok = action, on_ok
        f = ttk.Frame(self, padding=10)
        f.pack(fill="both", expand=True)
        self.w = {}

        def row(r, label, widget, key):
            ttk.Label(f, text=label).grid(row=r, column=0, sticky="w", pady=3)
            widget.grid(row=r, column=1, sticky="ew", pady=3)
            self.w[key] = widget

        e = ttk.Entry(f, width=70)
        e.insert(0, action["desc"])
        row(0, "Beschreibung", e, "desc")
        e = ttk.Entry(f, width=70)
        e.insert(0, action["call"])
        row(1, "Aufruf", e, "call")
        c = ttk.Combobox(f, values=[""] + list(HOTKEYS), state="readonly", width=12)
        c.set(action.get("hotkey", ""))
        row(2, "Hotkey", c, "hotkey")
        e = ttk.Entry(f, width=12)
        e.insert(0, str(action.get("interval") or 0))
        row(3, "Timer (Sekunden)", e, "interval")
        ttk.Label(f, text="Aufruf: Klasse::Methode(arg1, arg2) – mehrere mit ';' trennen.\n"
                          "Objekt per Pfad: GameManager::_playerOptions.UnlockStage(StageX)\n"
                          "Enum-Argument '*' = alle Werte, 'keys:feld.dict' = alle Schlüssel eines Dictionary.\n"
                          "Timer 0 = nur per Knopf/Hotkey. Sonst wird die Aktion bei eingeschaltetem Timer "
                          "alle n Sekunden ausgeführt.", foreground="#555", justify="left"
                  ).grid(row=4, column=0, columnspan=2, sticky="w", pady=(6, 6))
        b = ttk.Frame(f)
        b.grid(row=5, column=0, columnspan=2, sticky="e")
        ttk.Button(b, text="OK", command=self.ok).pack(side="left", padx=4)
        ttk.Button(b, text="Abbrechen", command=self.destroy).pack(side="left")
        f.columnconfigure(1, weight=1)

    def ok(self):
        try:
            interval = max(0.0, float(self.w["interval"].get().replace(",", ".") or 0))
        except ValueError:
            messagebox.showerror("Aktion", "Timer bitte als Zahl (Sekunden).", parent=self)
            return
        call = self.w["call"].get().strip()
        if "::" not in call or "(" not in call:
            messagebox.showerror("Aktion", "Aufruf bitte als Klasse::Methode(…).", parent=self)
            return
        self.action.update(desc=self.w["desc"].get().strip() or "Aktion", call=call,
                           hotkey=self.w["hotkey"].get(), interval=interval)
        self.on_ok(self.action)
        self.destroy()


class ActionsWindow(Tool):
    """Liste der Aktionen: ausführen, Timer ein/aus, bearbeiten."""
    COLS = (("desc", "Beschreibung", 200), ("call", "Aufruf", 380), ("hotkey", "Hotkey", 70),
            ("timer", "Timer", 90), ("last", "Letztes Ergebnis", 260))

    def __init__(self, app):
        super().__init__(app, "Aktionen & Timer", "1060x640")
        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")
        for text, fn in (("Neu…", self.new), ("Bearbeiten…", self.edit), ("▶ Ausführen", self.run),
                         ("Timer ein/aus", self.toggle_timer), ("Entfernen", self.remove)):
            ttk.Button(bar, text=text, command=fn).pack(side="left", padx=2)
        self.status = ttk.Label(bar, text="", foreground="#555")
        self.status.pack(side="left", padx=10)
        self.tv = ttk.Treeview(self, columns=[c for c, _, _ in self.COLS], show="headings", selectmode="browse")
        for c, t, w in self.COLS:
            self.tv.heading(c, text=t)
            self.tv.column(c, width=w, anchor="w")
        self.tv.pack(fill="both", expand=True, padx=6)
        self.tv.bind("<Double-1>", lambda _: self.run())
        ttk.Label(self, text="Verlauf (läuft gerade ⏳ / fertig ✓ / Fehler ✗):").pack(anchor="w", padx=6, pady=(8, 0))
        self.hv = ttk.Treeview(self, columns=("time", "what", "dur", "res"), show="headings", height=9)
        for c, t, w in (("time", "Zeit", 70), ("what", "Vorgang", 560), ("dur", "Dauer", 80), ("res", "Ergebnis", 300)):
            self.hv.heading(c, text=t)
            self.hv.column(c, width=w, anchor="w")
        self.hv.pack(fill="both", expand=False, padx=6)
        ttk.Label(self, text="Aktionen rufen Funktionen des Spiels auf (nur Unity/IL2CPP). Sie werden mit der Tabelle "
                             "gespeichert. Was den Spielstand ändert (z. B. Freischalten), bleibt dauerhaft – vorher "
                             "den Spielstand sichern.", foreground="#555", wraplength=1000, justify="left"
                  ).pack(anchor="w", padx=6, pady=4)
        self.render()
        self.every(500, self.refresh)

    def render(self):
        sel = self.tv.selection()
        self.tv.delete(*self.tv.get_children())
        for i, a in enumerate(self.app.actions):
            self.tv.insert("", "end", iid=str(i), values=self._row(a))
        if sel and self.tv.exists(sel[0]):
            self.tv.selection_set(sel[0])
        self.refresh()

    @staticmethod
    def _row(a):
        iv = float(a.get("interval") or 0)
        timer = "—" if iv <= 0 else f"{'AN' if a.get('timer') else 'aus'} · {iv:g} s"
        return (a["desc"], a["call"], a.get("hotkey", ""), timer, a.get("_last", ""))

    def refresh(self):
        for i, a in enumerate(self.app.actions):
            if self.tv.exists(str(i)):
                self.tv.item(str(i), values=self._row(a))
        u = self.app.unity
        self.status.config(text="Unity bereit" if u else ("Unity wird geladen…" if self.app.unity_loading
                                                            else "Kein Unity-Spiel verbunden"))
        self.fill_history()

    def fill_history(self):
        u = self.app.unity
        rows = []
        if self.app.unity_loading:
            rows.append(("jetzt", "⏳ Unity-Daten laden", f"{time.time() - self.app.unity_loading:.1f} s", "läuft"))
        if u is not None:
            rows += [("jetzt", f"⏳ {t}", f"{d:.1f} s", "läuft") for t, d in u.running()]
            rows += [(when, f"{'✓' if ok else '✗'} {text}", f"{dur:.2f} s" if dur >= 0.005 else "",
                      msg or ("OK" if ok else "Fehler")) for when, text, dur, ok, msg in reversed(list(u.log))]
        rows = rows[:200]
        kids = self.hv.get_children()
        for i, r in enumerate(rows):
            if i < len(kids):
                if self.hv.item(kids[i], "values") != r:
                    self.hv.item(kids[i], values=r)
            else:
                self.hv.insert("", "end", values=r)
        for k in kids[len(rows):]:
            self.hv.delete(k)

    def _sel(self):
        s = self.tv.selection()
        return self.app.actions[int(s[0])] if s else None

    def new(self, call=""):
        def add(a):
            self.app.actions.append(a)
            self.render()
        ActionDialog(self, new_action(call=call), add)

    def edit(self):
        a = self._sel()
        if a:
            ActionDialog(self, a, lambda _: self.render())

    def run(self):
        a = self._sel()
        if a:
            self.app.run_action(a, confirm=True)

    def toggle_timer(self):
        a = self._sel()
        if not a:
            return
        if float(a.get("interval") or 0) <= 0:
            messagebox.showinfo("Timer", "Erst unter „Bearbeiten…“ einen Timer in Sekunden eintragen.", parent=self)
            return
        a["timer"] = not a.get("timer")
        self.refresh()

    def remove(self):
        a = self._sel()
        if a:
            self.app.actions.remove(a)
            self.render()


class MethodsWindow(Tool):
    """Methoden einer Unity-Klasse anzeigen und als Aktion übernehmen."""

    def __init__(self, app, cls):
        super().__init__(app, f"Methoden: {cls.full}", "900x520")
        self.cls = cls
        bar = ttk.Frame(self, padding=6)
        bar.pack(fill="x")
        ttk.Label(bar, text="Filter:").pack(side="left")
        self.q = ttk.Entry(bar, width=30)
        self.q.pack(side="left", padx=4)
        self.q.bind("<KeyRelease>", lambda _: self.fill())
        self.inh = tk.BooleanVar(value=False)
        ttk.Checkbutton(bar, text="geerbte zeigen", variable=self.inh, command=self.fill).pack(side="left", padx=6)
        ttk.Button(bar, text="→ Als Aktion…", command=self.to_action).pack(side="right")
        self.tv = ttk.Treeview(self, columns=("cls", "sig", "ok"), show="headings")
        for c, t, w in (("cls", "Klasse", 160), ("sig", "Signatur", 620), ("ok", "aufrufbar", 80)):
            self.tv.heading(c, text=t)
            self.tv.column(c, width=w, anchor="w")
        self.tv.pack(fill="both", expand=True, padx=6)
        self.tv.bind("<Double-1>", lambda _: self.to_action())
        ttk.Label(self, text="„aufrufbar“: höchstens 2–3 einfache Parameter (Zahl, bool, Text, Enum, Objekt). "
                             "Struct-Parameter wie Vector3 gehen nicht.", foreground="#555").pack(anchor="w", padx=6, pady=4)
        self.items = {}
        self.fill()

    def fill(self):
        u = self.app.unity
        self.tv.delete(*self.tv.get_children())
        self.items = {}
        k, depth = self.cls, 0
        q = self.q.get().lower()
        try:
            while k is not None and depth < (8 if self.inh.get() else 1):
                for m in u.methods(k):
                    if q in m.name.lower():
                        iid = str(len(self.items))
                        self.items[iid] = m
                        self.tv.insert("", "end", iid=iid, values=(k.name, m.signature, "✓" if m.callable else ""))
                k, depth = u.by_ptr.get(k.parent), depth + 1
        except Exception as e:  # noqa: BLE001
            messagebox.showerror("Methoden", str(e), parent=self)

    def to_action(self):
        s = self.tv.selection()
        if not s:
            return
        m = self.items[s[0]]
        args = ", ".join("*" if p[3] else ("true" if p[1] == 2 else "0") for p in m.params)
        call = f"{self.cls.name}::{m.name}({args})"
        win = self.app.open_actions()
        win.new(call)
