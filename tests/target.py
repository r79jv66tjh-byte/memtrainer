"""Testziel: hält bekannte Werte im Speicher und ändert sie auf Befehl (stdin).

Ausgabe beim Start (eine JSON-Zeile): Adressen der Werte.
Befehle: "add <name> <wert>", "noise", "quit".
Ein Hintergrund-Thread ändert ständig 'noise' (simuliert Timer) und ruft GetTickCount64 auf.
"""
import ctypes
import json
import sys
import threading
import time


class Player(ctypes.Structure):
    _fields_ = [("hp", ctypes.c_int32), ("gold", ctypes.c_float), ("cents", ctypes.c_int32),
                ("big", ctypes.c_int64), ("noise", ctypes.c_int32), ("pad", ctypes.c_int32),
                ("xp", ctypes.c_double)]


p = Player(100, 336.7, 1234, 5_000_000_000, 0, 0, 12.5)
holder = (ctypes.c_void_p * 4)(None, ctypes.addressof(p), None, None)  # Zeiger auf p (für "Wer zeigt hierhin?")
stop = False


def busy():
    k32 = ctypes.WinDLL("kernel32")
    k32.GetTickCount64.restype = ctypes.c_uint64
    try:
        while not stop:
            p.noise += 1
            k32.GetTickCount64()
            time.sleep(0.01)
    except Exception:  # noqa: BLE001 - beim Beenden des Interpreters
        pass


threading.Thread(target=busy, daemon=True).start()
base = ctypes.addressof(p)
print(json.dumps({"base": base, "hp": base, "gold": base + 4, "cents": base + 8, "big": base + 16,
                  "noise": base + 24, "xp": base + 32, "holder": ctypes.addressof(holder) + 8}), flush=True)
for line in sys.stdin:
    cmd = line.split()
    if not cmd:
        continue
    if cmd[0] == "add":
        f = cmd[1]
        setattr(p, f, type(getattr(p, f))(getattr(p, f) + float(cmd[2]) if f in ("gold", "xp") else
                                         getattr(p, f) + int(cmd[2])))
    elif cmd[0] == "quit":
        break
    print("ok", flush=True)
stop = True
