"""Kern des MemTrainers: Prozesse auflisten, Speicher lesen/schreiben, scannen.

Nur Windows, 64-bit Python. Gedacht fuer Singleplayer-/Offline-Spiele.
"""
import bisect
import ctypes
import time
import ctypes.wintypes as wt

import numpy as np

k32 = ctypes.WinDLL("kernel32", use_last_error=True)
u32 = ctypes.WinDLL("user32", use_last_error=True)

PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_VM_OPERATION = 0x0008
PROCESS_QUERY_INFORMATION = 0x0400
ACCESS = PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_QUERY_INFORMATION

MEM_COMMIT = 0x1000
MEM_MAPPED = 0x40000
PAGE_NOACCESS = 0x01
PAGE_GUARD = 0x100
WRITABLE = 0x04 | 0x08 | 0x40 | 0x80  # RW, WRITECOPY, EXEC_RW, EXEC_WRITECOPY

TH32CS_SNAPPROCESS = 0x2
TH32CS_SNAPMODULE = 0x8
TH32CS_SNAPMODULE32 = 0x10
INVALID_HANDLE = ctypes.c_void_p(-1).value
STILL_ACTIVE = 259
MAX_ADDR = 0x7FFFFFFFFFFF
CHUNK = 16 * 1024 * 1024


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p), ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", wt.DWORD), ("PartitionId", wt.WORD),
                ("RegionSize", ctypes.c_size_t), ("State", wt.DWORD),
                ("Protect", wt.DWORD), ("Type", wt.DWORD)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ProcessID", wt.DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t), ("th32ModuleID", wt.DWORD),
                ("cntThreads", wt.DWORD), ("th32ParentProcessID", wt.DWORD),
                ("pcPriClassBase", ctypes.c_long), ("dwFlags", wt.DWORD),
                ("szExeFile", wt.WCHAR * 260)]


class MODULEENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("th32ModuleID", wt.DWORD), ("th32ProcessID", wt.DWORD),
                ("GlblcntUsage", wt.DWORD), ("ProccntUsage", wt.DWORD),
                ("modBaseAddr", ctypes.c_void_p), ("modBaseSize", wt.DWORD),
                ("hModule", wt.HMODULE), ("szModule", wt.WCHAR * 256),
                ("szExePath", wt.WCHAR * 260)]


def _sig(fn, res, *args):
    fn.restype = res
    fn.argtypes = list(args)


_sig(k32.OpenProcess, wt.HANDLE, wt.DWORD, wt.BOOL, wt.DWORD)
_sig(k32.CloseHandle, wt.BOOL, wt.HANDLE)
_sig(k32.ReadProcessMemory, wt.BOOL, wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
     ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
_sig(k32.WriteProcessMemory, wt.BOOL, wt.HANDLE, ctypes.c_void_p, ctypes.c_void_p,
     ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t))
_sig(k32.VirtualQueryEx, ctypes.c_size_t, wt.HANDLE, ctypes.c_void_p,
     ctypes.POINTER(MBI), ctypes.c_size_t)
_sig(k32.CreateToolhelp32Snapshot, wt.HANDLE, wt.DWORD, wt.DWORD)
_sig(k32.Process32FirstW, wt.BOOL, wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
_sig(k32.Process32NextW, wt.BOOL, wt.HANDLE, ctypes.POINTER(PROCESSENTRY32W))
_sig(k32.Module32FirstW, wt.BOOL, wt.HANDLE, ctypes.POINTER(MODULEENTRY32W))
_sig(k32.Module32NextW, wt.BOOL, wt.HANDLE, ctypes.POINTER(MODULEENTRY32W))
_sig(k32.GetExitCodeProcess, wt.BOOL, wt.HANDLE, ctypes.POINTER(wt.DWORD))
_sig(u32.GetAsyncKeyState, ctypes.c_short, ctypes.c_int)
_sig(k32.IsWow64Process, wt.BOOL, wt.HANDLE, ctypes.POINTER(wt.BOOL))
_sig(k32.VirtualProtectEx, wt.BOOL, wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD,
     ctypes.POINTER(wt.DWORD))
_sig(k32.VirtualAllocEx, ctypes.c_void_p, wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD, wt.DWORD)
_sig(k32.FlushInstructionCache, wt.BOOL, wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t)

PAGE_EXECUTE_READWRITE = 0x40
PAGE_READWRITE = 0x04
MEM_RESERVE = 0x2000
MEM_FREE = 0x10000
READABLE = 0x02 | 0x04 | 0x08 | 0x20 | 0x40 | 0x80
EXECUTABLE = 0x10 | 0x20 | 0x40 | 0x80

TYPES = {"Byte": np.uint8, "2 Bytes": np.int16, "4 Bytes": np.int32,
         "8 Bytes": np.int64, "Float": np.float32, "Double": np.float64}

APPROX = "Ungefähr (gerundet)"
FIRST_MODES = ["Exakter Wert", APPROX, "Größer als", "Kleiner als", "Zwischen", "Unbekannter Startwert"]
NEXT_MODES = ["Exakter Wert", APPROX, "Größer als", "Kleiner als", "Zwischen", "Erhöht", "Verringert",
              "Erhöht um", "Verringert um", "Geändert", "Unverändert"]
NEEDS_V1 = {"Exakter Wert", APPROX, "Größer als", "Kleiner als", "Zwischen", "Erhöht um", "Verringert um"}

# "Alle Zahlentypen": diese Typen werden gleichzeitig gesucht (Typ, Faktor). Faktor 100 findet
# z. B. Geld, das intern in Cent gespeichert ist (12,34 € -> 1234).
MULTI = "Alle Zahlentypen"
MULTI_SET = [("4 Bytes", 1), ("Float", 1), ("Double", 1), ("8 Bytes", 1), ("4 Bytes", 10), ("4 Bytes", 100)]
TYPE_CHOICES = [MULTI] + list(TYPES)


def list_processes():
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap in (None, INVALID_HANDLE):
        return []
    out = []
    try:
        e = PROCESSENTRY32W()
        e.dwSize = ctypes.sizeof(e)
        ok = k32.Process32FirstW(snap, ctypes.byref(e))
        while ok:
            if e.th32ProcessID:
                out.append((e.th32ProcessID, e.szExeFile))
            ok = k32.Process32NextW(snap, ctypes.byref(e))
    finally:
        k32.CloseHandle(snap)
    return sorted(out, key=lambda p: p[1].lower())


_WNDENUMPROC = ctypes.WINFUNCTYPE(wt.BOOL, wt.HWND, wt.LPARAM)
_sig(u32.EnumWindows, wt.BOOL, _WNDENUMPROC, wt.LPARAM)
_sig(u32.IsWindowVisible, wt.BOOL, wt.HWND)
_sig(u32.GetWindowTextLengthW, ctypes.c_int, wt.HWND)
_sig(u32.GetWindowTextW, ctypes.c_int, wt.HWND, wt.LPWSTR, ctypes.c_int)
_sig(u32.GetWindowThreadProcessId, wt.DWORD, wt.HWND, ctypes.POINTER(wt.DWORD))


def window_titles():
    """PID -> Titel des ersten sichtbaren Fensters mit Titel."""
    titles = {}

    def cb(hwnd, _):
        if u32.IsWindowVisible(hwnd):
            n = u32.GetWindowTextLengthW(hwnd)
            if n:
                buf = ctypes.create_unicode_buffer(n + 1)
                u32.GetWindowTextW(hwnd, buf, n + 1)
                pid = wt.DWORD()
                u32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                titles.setdefault(pid.value, buf.value)
        return True

    u32.EnumWindows(_WNDENUMPROC(cb), 0)
    return titles


def parse_value(text, dtype):
    """Text -> (Wert, Toleranz). Akzeptiert Komma als Dezimaltrenner und 0x-Hex."""
    t = text.strip().replace(",", ".")
    if not t:
        raise ValueError("Bitte einen Wert eingeben.")
    dtype = np.dtype(dtype)
    if dtype.kind == "f":
        v = float(t)
        dec = len(t.split(".")[1]) if "." in t and "e" not in t.lower() else 0
        return v, 0.5 * 10 ** -dec
    v = int(t, 16) if t.lower().startswith(("0x", "-0x")) else int(t)
    info = np.iinfo(dtype)
    if not info.min <= v <= info.max:
        raise ValueError(f"Wert muss zwischen {info.min} und {info.max} liegen.")
    return v, 0


def fmt_value(v):
    if isinstance(v, (float, np.floating)):
        if not np.isfinite(v):
            return str(v)
        s = f"{float(v):.4f}".rstrip("0").rstrip(".")
        return s if s not in ("", "-0") else "0"
    return str(int(v))


def match(mode, cur, prev, v1, v2, tol):
    is_float = cur.dtype.kind == "f"

    def eq(a, v):
        if is_float:
            return np.abs(a - v) <= tol
        if tol:
            return np.abs(a.astype(np.float64) - v) <= tol
        return a == v

    with np.errstate(all="ignore"):
        if mode in ("Exakter Wert", APPROX):
            return eq(cur, v1)
        if mode == "Größer als":
            return cur > v1
        if mode == "Kleiner als":
            return cur < v1
        if mode == "Zwischen":
            lo, hi = min(v1, v2), max(v1, v2)
            return (cur >= lo) & (cur <= hi)
        if mode == "Erhöht":
            return cur > prev
        if mode == "Verringert":
            return cur < prev
        if mode == "Erhöht um":
            return eq(cur - prev, v1)
        if mode == "Verringert um":
            return eq(prev - cur, v1)
        if mode == "Geändert":
            return cur != prev
        if mode == "Unverändert":
            return cur == prev
    raise ValueError(mode)


class Process:
    def __init__(self, pid, name):
        self.pid, self.name = pid, name
        self.h = k32.OpenProcess(ACCESS, False, pid)
        if not self.h:
            err = ctypes.get_last_error()
            hint = " (evtl. als Administrator starten)" if err == 5 else ""
            raise OSError(f"Prozess {name} ({pid}) konnte nicht geöffnet werden, Fehler {err}{hint}")
        wow = wt.BOOL()
        k32.IsWow64Process(self.h, ctypes.byref(wow))
        self.is32 = bool(wow.value)
        self.ptr_size = 4 if self.is32 else 8
        self.ptr_dtype = np.dtype(np.uint32 if self.is32 else np.uint64)
        self.refresh_modules()

    def close(self):
        if self.h:
            k32.CloseHandle(self.h)
            self.h = None

    def alive(self):
        code = wt.DWORD()
        return bool(self.h) and k32.GetExitCodeProcess(self.h, ctypes.byref(code)) and code.value == STILL_ACTIVE

    # --- Module (fuer "spiel.exe+1234"-Adressen) ---
    def refresh_modules(self):
        mods = []
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, self.pid)
        if snap not in (None, INVALID_HANDLE):
            try:
                e = MODULEENTRY32W()
                e.dwSize = ctypes.sizeof(e)
                ok = k32.Module32FirstW(snap, ctypes.byref(e))
                while ok:
                    mods.append((e.modBaseAddr or 0, e.modBaseSize, e.szModule))
                    ok = k32.Module32NextW(snap, ctypes.byref(e))
            finally:
                k32.CloseHandle(snap)
        mods.sort()
        self.modules = mods
        self._mod_bases = [m[0] for m in mods]

    def locate(self, addr):
        i = bisect.bisect_right(self._mod_bases, addr) - 1
        if i >= 0:
            base, size, name = self.modules[i]
            if addr < base + size:
                return name, addr - base
        return None

    def module_base(self, name):
        for base, _, n in self.modules:
            if n.lower() == name.lower():
                return base
        return None

    def fmt_addr(self, addr):
        loc = self.locate(addr)
        if not loc:
            return f"{addr:X}"
        name = loc[0]
        if any(c in name for c in ' []+-"'):
            name = f'"{name}"'
        return f"{name}+{loc[1]:X}"

    # --- Speicher ---
    def regions(self, include_mapped=False):
        out, addr, mbi = [], 0, MBI()
        while addr < MAX_ADDR:
            if not k32.VirtualQueryEx(self.h, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            base, size = mbi.BaseAddress or 0, mbi.RegionSize
            if (mbi.State == MEM_COMMIT and mbi.Protect & WRITABLE
                    and not mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)
                    and (include_mapped or mbi.Type != MEM_MAPPED)):
                out.append((base, size))
            if size == 0:
                break
            addr = base + size
        return out

    def all_regions(self, executable_only=False):
        """Alle lesbaren Regionen (auch Code/Read-only) als (base, size, protect)."""
        out, addr, mbi = [], 0, MBI()
        while addr < MAX_ADDR:
            if not k32.VirtualQueryEx(self.h, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)):
                break
            base, size = mbi.BaseAddress or 0, mbi.RegionSize
            if (mbi.State == MEM_COMMIT and mbi.Protect & READABLE
                    and not mbi.Protect & (PAGE_GUARD | PAGE_NOACCESS)
                    and (not executable_only or mbi.Protect & EXECUTABLE)):
                out.append((base, size, mbi.Protect))
            if size == 0:
                break
            addr = base + size
        return out

    def module_range(self, name):
        for base, size, n in self.modules:
            if n.lower() == name.lower():
                return base, size
        return None

    def read_bytes(self, addr, size):
        arr = self.read_array(addr, size, np.uint8)
        return None if arr is None or arr.size < size else arr.tobytes()

    def read_ptr(self, addr):
        return self.read_value(addr, self.ptr_dtype)

    def write_bytes(self, addr, data, code=False):
        """Schreibt Bytes, aendert notfalls kurz den Seitenschutz (z. B. fuer Code-Patches)."""
        n = ctypes.c_size_t()
        old = wt.DWORD()
        prot = k32.VirtualProtectEx(self.h, addr, len(data), PAGE_EXECUTE_READWRITE, ctypes.byref(old))
        ok = k32.WriteProcessMemory(self.h, addr, data, len(data), ctypes.byref(n))
        if prot:
            k32.VirtualProtectEx(self.h, addr, len(data), old.value, ctypes.byref(wt.DWORD()))
        if code:
            k32.FlushInstructionCache(self.h, addr, len(data))
        return bool(ok)

    def alloc(self, size, near=None):
        """Speicher im Zielprozess reservieren (optional innerhalb +-2 GB von 'near')."""
        flags = MEM_COMMIT | MEM_RESERVE
        if near is None:
            return k32.VirtualAllocEx(self.h, None, size, flags, PAGE_EXECUTE_READWRITE)
        mbi = MBI()
        step = 0x10000
        for direction in (-1, 1):
            addr = (near & ~(step - 1)) + direction * step
            while abs(addr - near) < 0x7FF00000 and 0x10000 < addr < MAX_ADDR:
                if k32.VirtualQueryEx(self.h, addr, ctypes.byref(mbi), ctypes.sizeof(mbi)) and mbi.State == MEM_FREE:
                    p = k32.VirtualAllocEx(self.h, addr, size, flags, PAGE_EXECUTE_READWRITE)
                    if p:
                        return p
                addr += direction * step
        return None

    def read_array(self, addr, size, dtype):
        buf = bytearray(size)
        cbuf = (ctypes.c_char * size).from_buffer(buf)
        n = ctypes.c_size_t()
        k32.ReadProcessMemory(self.h, addr, cbuf, size, ctypes.byref(n))
        del cbuf
        dtype = np.dtype(dtype)
        cnt = n.value // dtype.itemsize
        return np.frombuffer(buf, dtype, count=cnt) if cnt else None

    def read_value(self, addr, dtype):
        arr = self.read_array(addr, np.dtype(dtype).itemsize, dtype)
        return None if arr is None else arr[0].item()

    def write_value(self, addr, dtype, value):
        data = np.array([value], dtype=dtype).tobytes()
        n = ctypes.c_size_t()
        return bool(k32.WriteProcessMemory(self.h, addr, data, len(data), ctypes.byref(n)))


def _chunks(proc, include_mapped):
    out = []
    for base, size in proc.regions(include_mapped):
        off = 0
        while off < size:
            n = min(CHUNK, size - off)
            out.append((base + off, n))
            off += n
    return out


class Scanner:
    """Haelt die Trefferliste. blocks: base -> (indices|None, vorherige Werte).

    scale: gespeicherter Wert = angezeigter Wert * scale (z. B. 100 bei Cent-Beträgen).
    """

    def __init__(self, proc, type_name, include_mapped=False, scale=1):
        self.proc = proc
        self.type_name = type_name
        self.scale = scale
        self.dtype = np.dtype(TYPES[type_name])
        self.size = self.dtype.itemsize
        self.include_mapped = include_mapped
        self.blocks = {}
        self.scans = 0
        self.history = []
        self.last_changed = 0  # Treffer, deren Wert sich beim letzten Scan geändert hat

    @property
    def label(self):
        return self.type_name + (f" ×{self.scale}" if self.scale != 1 else "")

    def parse(self, mode, t1, t2=""):
        """Eingabetexte -> (v1, v2, Toleranz) in gespeicherten Einheiten. ValueError, wenn unpassend."""
        if mode not in NEEDS_V1:
            return None, None, 0
        v1, tol = self._parse_one(t1, mode)
        v2 = None
        if mode == "Zwischen":
            v2, tol2 = self._parse_one(t2, mode)
            tol = max(tol, tol2)
        return v1, v2, tol

    def _parse_one(self, text, mode):
        t = (text or "").strip().replace(",", ".")
        if self.scale == 1 or self.dtype.kind == "f":
            v, tol = parse_value(text or "", self.dtype)
            if mode == APPROX:
                dec = len(t.split(".")[1]) if "." in t else 0
                tol = max(tol, 1.0 if dec == 0 else 10.0 ** -dec)
                if self.dtype.kind != "f":
                    tol = 0.999
            return v, tol
        if not t:
            raise ValueError("Bitte einen Wert eingeben.")
        f = float(t) * self.scale
        if mode == APPROX:
            return f, self.scale * 0.999
        if mode in ("Exakter Wert", "Erhöht um", "Verringert um") and abs(f - round(f)) > 1e-6:
            raise ValueError("passt nicht zu diesem Faktor")
        v = int(round(f))
        info = np.iinfo(self.dtype)
        if not info.min <= v <= info.max:
            raise ValueError("Wert zu groß")
        return v, 0

    def display(self, raw):
        """Gespeicherter Wert -> angezeigter Wert."""
        if raw is None:
            return None
        return raw / self.scale if self.scale != 1 else raw

    def count(self):
        return sum(p.size for _, p in self.blocks.values())

    def listable(self):
        return all(idx is not None for idx, _ in self.blocks.values())

    def first_scan(self, mode, v1, v2, tol, progress=lambda f: None, cancel=None):
        return first_scan_many([(self, v1, v2, tol)], mode, progress, cancel)

    def _first_chunk(self, base, raw, mode, v1, v2, tol):
        """raw: gelesene Bytes (uint8). Bei 'Unbekannt' wird der Puffer geteilt statt kopiert."""
        cnt = raw.size // self.size
        if not cnt:
            return
        arr = raw[:cnt * self.size].view(self.dtype)
        if mode == "Unbekannter Startwert":
            self.blocks[base] = (None, arr)
            return
        idx = np.flatnonzero(match(mode, arr, None, v1, v2, tol))
        if idx.size:
            self.blocks[base] = (idx.astype(np.uint32), arr[idx].copy())

    def next_scan(self, mode, v1, v2, tol, progress=lambda f: None, cancel=None, keep_history=False):
        items = sorted(self.blocks.items())
        total, new, changed = len(items) or 1, {}, 0
        for i, (base, (idx, prev)) in enumerate(items):
            if cancel is not None and cancel.is_set():
                return False
            progress((i + 1) / total)
            if idx is None:
                cur = self.proc.read_array(base, prev.size * self.size, self.dtype)
                if cur is None:
                    continue
                m = min(cur.size, prev.size)
                cur, prev = cur[:m], prev[:m]
                nidx = np.flatnonzero(match(mode, cur, prev, v1, v2, tol))
                if nidx.size:
                    new[base] = (nidx.astype(np.uint32), cur[nidx].copy())
                    changed += int(np.count_nonzero(cur[nidx] != prev[nidx]))
            else:
                lo, hi = int(idx[0]), int(idx[-1])
                arr = self.proc.read_array(base + lo * self.size, (hi - lo + 1) * self.size, self.dtype)
                if arr is None:
                    continue
                rel = idx.astype(np.int64) - lo
                ok = rel < arr.size
                idx, prev, cur = idx[ok], prev[ok], arr[rel[ok]]
                m = match(mode, cur, prev, v1, v2, tol)
                if m.any():
                    new[base] = (idx[m], cur[m].copy())
                    changed += int(np.count_nonzero(cur[m] != prev[m]))
        if not keep_history:
            self.history.append((self.blocks, self.scans))
            del self.history[:-5]  # max. 5 Schritte zurueck
            self.scans += 1
        self.blocks = new
        self.last_changed = changed
        return True

    def filter_noise(self, seconds=5.0, progress=lambda f: None, cancel=None):
        """'Rauschfilter': wiederholt 'Unverändert' scannen, solange der Spieler nichts tut.
        Entfernt Zähler, Timer, Positionen usw. Zählt als ein Rückgängig-Schritt."""
        state = (self.blocks, self.scans)
        end = time.time() + seconds
        while time.time() < end:
            if cancel is not None and cancel.is_set():
                self.blocks, self.scans = state
                return False
            self.next_scan("Unverändert", None, None, 0, cancel=cancel, keep_history=True)
            progress(1 - max(0.0, end - time.time()) / seconds)
            time.sleep(0.2)
        self.history.append(state)
        del self.history[:-5]
        self.scans += 1
        return True

    def undo(self):
        if not self.history:
            return False
        self.blocks, self.scans = self.history.pop()
        return True

    def results(self, limit=500):
        out = []
        for base in sorted(self.blocks):
            idx, prev = self.blocks[base]
            if idx is None:
                return out
            take = min(len(idx), limit - len(out))
            out.extend((base + int(idx[j]) * self.size, prev[j].item()) for j in range(take))
            if len(out) >= limit:
                break
        return out

    def rows(self, limit=500):
        """(adresse, scanner, vorheriger Rohwert) – einheitlich für Einzel- und Mehrfach-Scan."""
        return [(a, self, v) for a, v in self.results(limit)]

    def scan(self, first, mode, t1, t2, progress=lambda f: None, cancel=None):
        """Gemeinsame Schnittstelle mit MultiScanner: Werte aus Text parsen und scannen."""
        v1, v2, tol = self.parse(mode, t1, t2)
        fn = self.first_scan if first else self.next_scan
        return fn(mode, v1, v2, tol, progress, cancel)

    def by_type(self):
        return {self.label: self.count()}


def first_scan_many(jobs, mode, progress=lambda f: None, cancel=None):
    """Erster Scan für mehrere Scanner auf einmal; jede Speicherseite wird nur einmal gelesen.
    jobs: [(scanner, v1, v2, tol)]."""
    if not jobs:
        return True
    proc, mapped = jobs[0][0].proc, jobs[0][0].include_mapped
    chunks = _chunks(proc, mapped)
    total = sum(n for _, n in chunks) or 1
    new = {id(j[0]): {} for j in jobs}
    old = [(j[0], j[0].blocks) for j in jobs]
    for sc, *_ in jobs:
        sc.blocks = new[id(sc)]
    done = 0
    for base, n in chunks:
        if cancel is not None and cancel.is_set():
            for sc, b in old:
                sc.blocks = b
            return False
        raw = proc.read_array(base, n, np.uint8)
        done += n
        progress(done / total)
        if raw is None:
            continue
        for sc, v1, v2, tol in jobs:
            sc._first_chunk(base, raw, mode, v1, v2, tol)
    for sc, *_ in jobs:
        sc.scans = 1
        sc.history = []
    return True


class MultiScanner:
    """Sucht mehrere Datentypen gleichzeitig ('Alle Zahlentypen'). Gleiche Schnittstelle wie Scanner."""

    type_name = label = MULTI
    size = 4
    scale = 1

    def __init__(self, proc, include_mapped=False, combos=None):
        self.proc = proc
        self.include_mapped = include_mapped
        self.subs = [Scanner(proc, t, include_mapped, sc) for t, sc in (combos or MULTI_SET)]
        self.scans = 0
        self.history = []  # Liste der Sub-Zustände für Rückgängig
        self.skipped = []  # Typen, zu denen der Wert nicht passte

    def count(self):
        return sum(s.count() for s in self.subs)

    def listable(self):
        return all(s.listable() for s in self.subs)

    @property
    def last_changed(self):
        return sum(s.last_changed for s in self.subs)

    def _jobs(self, mode, t1, t2, first):
        jobs, self.skipped = [], []
        for s in self.subs:
            if first and mode == "Unbekannter Startwert" and s.scale != 1:
                continue  # skalierte Varianten verhalten sich bei Vergleichen gleich
            if not first and not s.blocks:
                continue
            try:
                jobs.append((s,) + s.parse(mode, t1, t2))
            except (ValueError, OverflowError):
                self.skipped.append(s.label)
        return jobs

    def scan(self, first, mode, t1, t2, progress=lambda f: None, cancel=None):
        jobs = self._jobs(mode, t1, t2, first)
        if not jobs:
            raise ValueError("Der Wert passt zu keinem Datentyp.")
        state = [(s, s.blocks, s.scans) for s in self.subs]
        active = {id(j[0]) for j in jobs}
        if first:
            for s in self.subs:
                s.blocks = {}
            ok = first_scan_many(jobs, mode, progress, cancel)
        else:
            ok = True
            for i, (s, v1, v2, tol) in enumerate(jobs):
                ok = s.next_scan(mode, v1, v2, tol, lambda f, i=i: progress((i + f) / len(jobs)), cancel)
                if not ok:
                    break
        if not ok:
            for s, b, n in state:
                s.blocks, s.scans = b, n
            return False
        for s in self.subs:
            if id(s) not in active:
                s.blocks = {}  # Typ passt nicht (mehr) -> verwerfen
        if not first:
            self.history.append(state)
            del self.history[:-5]
        self.scans = 1 if first else self.scans + 1
        return True

    def filter_noise(self, seconds=5.0, progress=lambda f: None, cancel=None):
        state = [(s, s.blocks, s.scans) for s in self.subs]
        end = time.time() + seconds
        while time.time() < end:
            if cancel is not None and cancel.is_set():
                for s, b, n in state:
                    s.blocks, s.scans = b, n
                return False
            for s in self.subs:
                if s.blocks:
                    s.next_scan("Unverändert", None, None, 0, cancel=cancel, keep_history=True)
            progress(1 - max(0.0, end - time.time()) / seconds)
            time.sleep(0.2)
        self.history.append(state)
        del self.history[:-5]
        self.scans += 1
        return True

    def undo(self):
        if not self.history:
            return False
        for s, b, n in self.history.pop():
            s.blocks, s.scans = b, n
        self.scans -= 1
        return True

    def rows(self, limit=500):
        out = []
        for s in self.subs:
            if len(out) >= limit:
                break
            out.extend(s.rows(limit - len(out)))
        return out

    def by_type(self):
        """{Typ-Label: Trefferzahl} – zeigt, welcher Datentyp wahrscheinlich ist."""
        return {s.label: s.count() for s in self.subs if s.blocks}


def key_down(vk):
    return bool(u32.GetAsyncKeyState(vk) & 0x8000)


HOTKEYS = {**{f"F{i}": 0x6F + i for i in range(1, 13)},
           **{f"Num{i}": 0x60 + i for i in range(10)},
           **{str(i): 0x30 + i for i in range(10)}}
