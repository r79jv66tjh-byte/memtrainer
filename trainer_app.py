"""Eigenstaendiger Trainer – wird vom MemTrainer exportiert.

Start: python trainer_app.py table.json   (oder als .exe mit eingebetteter table.json)
Verbindet sich automatisch mit dem Spiel, sobald es laeuft.
"""
import json
import os
import sys
import tkinter as tk
from tkinter import messagebox, ttk

from scanner_core import HOTKEYS, Process, fmt_value, key_down, list_processes
from trainer_core import PATCH, CheatRunner, parse_for_entry, table_from_json


def find_table():
    if len(sys.argv) > 1:
        return sys.argv[1]
    for d in (getattr(sys, "_MEIPASS", ""), os.path.dirname(os.path.abspath(sys.argv[0]))):
        p = os.path.join(d, "table.json")
        if d and os.path.exists(p):
            return p
    return None


class Trainer(tk.Tk):
    def __init__(self, table):
        super().__init__()
        self.t = table
        self.entries = table["entries"]
        self.wanted = {id(e): e["active"] for e in self.entries}  # gewuenschter Zustand beim Verbinden
        for e in self.entries:
            e["active"] = False
        self.proc = self.runner = self.speed = None
        self.speed_on = False
        self.speed_wanted = False
        self.keys = {}
        self.ticks = 0
        self.title(table["title"] or "Trainer")
        self.resizable(False, False)
        self.build()
        self.after(50, self.tick)

    def build(self):
        head = ttk.Frame(self, padding=10)
        head.pack(fill="x")
        ttk.Label(head, text=self.t["title"] or "Trainer", font=("Segoe UI", 14, "bold")).pack(anchor="w")
        self.status = ttk.Label(head, text=f"Warte auf {self.t['process']} …", foreground="#b60")
        self.status.pack(anchor="w")
        body = ttk.Frame(self, padding=(10, 0, 10, 10))
        body.pack(fill="both")
        self.rows = []
        group = None
        r = 0
        for e in self.entries:
            if e["group"] != group:
                group = e["group"]
                if group:
                    ttk.Label(body, text=group, font=("Segoe UI", 10, "bold")).grid(row=r, column=0, columnspan=4,
                                                                                    sticky="w", pady=(8, 2))
                    r += 1
            var = tk.BooleanVar(value=False)
            cb = ttk.Checkbutton(body, text=e["desc"], variable=var, command=lambda e=e, v=var: self.toggle(e, v))
            cb.grid(row=r, column=0, sticky="w", padx=(10 if group else 0, 0))
            ttk.Label(body, text=self.key_text(e), foreground="#555", width=14).grid(row=r, column=1, sticky="w")
            val = ttk.Label(body, text="", width=12)
            val.grid(row=r, column=2, sticky="w")
            if e["type"] != PATCH:
                ent = ttk.Entry(body, width=10)
                ent.grid(row=r, column=3, padx=2)
                ent.bind("<Return>", lambda _, e=e, w=ent: self.set_value(e, w))
                ttk.Button(body, text="Setzen", width=7,
                           command=lambda e=e, w=ent: self.set_value(e, w)).grid(row=r, column=4)
            self.rows.append((e, var, val))
            r += 1
        sp = self.t.get("speed") or {}
        self.speed_var = tk.BooleanVar(value=False)
        if sp.get("hotkey") or sp.get("auto"):
            ttk.Separator(body).grid(row=r, column=0, columnspan=5, sticky="ew", pady=6)
            label = f"Speedhack {sp['factor']:g}x" + ("  (Auto-Inject)" if sp.get("auto") else "")
            ttk.Checkbutton(body, text=label, variable=self.speed_var,
                            command=lambda: self.set_speed(self.speed_var.get())).grid(row=r + 1, column=0, sticky="w")
            ttk.Label(body, text=sp.get("hotkey", ""), foreground="#555").grid(row=r + 1, column=1, sticky="w")
        ttk.Label(self, text="Nur für Singleplayer-/Offline-Spiele.", foreground="#999", padding=(10, 0, 10, 8)).pack(anchor="w")

    def key_text(self, e):
        k = e["hotkey"]
        if not k:
            return ""
        if e["type"] == PATCH or e["hk_action"] == "toggle":
            return k
        sign = "=" if e["hk_action"] == "set" else "+"
        return f"{k}  {sign}{fmt_value(e['hk_value']) if e['hk_value'] is not None else ''}"

    # --- Aktionen ---
    def toggle(self, e, var):
        if not self.runner:
            self.wanted[id(e)] = var.get()
            return
        if not self.runner.set_active(e, var.get(), capture=e["value"] is None):
            var.set(e["active"])

    def set_value(self, e, w):
        if not self.runner:
            return
        try:
            v = parse_for_entry(e, w.get())
        except ValueError as ex:
            messagebox.showerror("Wert", str(ex))
            return
        self.runner.write(e, v)
        if e["active"]:
            e["value"] = v

    def set_speed(self, on):
        if not self.proc:
            return
        try:
            if not self.speed:
                from speedhack import SpeedHack
                self.speed = SpeedHack(self.proc)
            self.speed.set_speed(self.t["speed"]["factor"] if on else 1.0)
            self.speed_on = on
            self.speed_var.set(on)
        except Exception as ex:  # noqa: BLE001
            messagebox.showerror("Speedhack", str(ex))

    # --- Verbindung ---
    def connect(self):
        name = self.t["process"].lower()
        for pid, n in list_processes():
            if n.lower() == name:
                try:
                    self.proc = Process(pid, n)
                except OSError as ex:
                    self.status.config(text=f"{ex}", foreground="#b00")
                    return
                if not self.proc.alive():
                    self.proc.close()
                    self.proc = None
                    continue
                self.runner = CheatRunner(self.proc)
                self.status.config(text=f"Verbunden mit {n} (PID {pid})", foreground="#070")
                if (self.t.get("speed") or {}).get("auto") or self.speed_wanted:
                    self.set_speed(True)  # Auto-Inject: so frueh wie moeglich
                for e, var, _ in self.rows:
                    if self.wanted.get(id(e)):
                        self.runner.set_active(e, True, capture=e["value"] is None)
                    var.set(e["active"])
                return

    def disconnect(self):
        for e in self.entries:
            self.wanted[id(e)] = e["active"]
            e["active"] = False
        self.speed_wanted = self.speed_on
        self.speed_on = False
        self.proc = self.runner = self.speed = None
        self.status.config(text=f"Warte auf {self.t['process']} …", foreground="#b60")

    def tick(self):
        self.ticks += 1
        if not self.proc:
            if self.ticks % 10 == 1:  # alle 0,5 s nach dem Spiel suchen (frueher Inject)
                self.connect()
        else:
            for e, var, _ in self.rows:
                k = e["hotkey"]
                if k:
                    down = key_down(HOTKEYS[k])
                    if down and not self.keys.get(id(e)):
                        self.runner.hotkey(e)
                        var.set(e["active"])
                    self.keys[id(e)] = down
            sp = self.t.get("speed") or {}
            if sp.get("hotkey"):
                down = key_down(HOTKEYS[sp["hotkey"]])
                if down and not self.keys.get("speed"):
                    self.set_speed(not self.speed_on)
                self.keys["speed"] = down
            self.runner.tick(self.entries)
            if self.ticks % 10 == 0:
                for e, var, lbl in self.rows:
                    lbl.config(text=self.runner.display(e))
            if self.ticks % 20 == 0 and not self.proc.alive():
                self.disconnect()
            elif self.speed:
                self.speed.maybe_hook_new_modules()
        self.after(50, self.tick)


if __name__ == "__main__":
    path = find_table()
    if not path:
        sys.exit("table.json nicht gefunden")
    with open(path, encoding="utf-8") as f:
        Trainer(table_from_json(json.load(f))).mainloop()
