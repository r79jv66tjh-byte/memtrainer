"""Speedhack: Spielzeit schneller/langsamer laufen lassen (nur 64-bit Spiele).

Technik: kleiner Maschinencode im Spiel + Umbiegen der Import-Tabellen (IAT) aller Module fuer
QueryPerformanceCounter, GetTickCount(64) und timeGetTime. Kein DLL-Inject noetig.
Spiele, die Zeit anders messen (z. B. eigene rdtsc-Uhr), werden nicht beeinflusst.
"""
import ctypes
import ctypes.wintypes as wt
import os
import struct
import time

from scanner_core import Process, k32, _sig

_sig(k32.QueryPerformanceCounter, wt.BOOL, ctypes.POINTER(ctypes.c_int64))
_sig(k32.QueryPerformanceFrequency, wt.BOOL, ctypes.POINTER(ctypes.c_int64))
_sig(k32.GetTickCount64, ctypes.c_uint64)
_sig(k32.LoadLibraryW, wt.HMODULE, wt.LPCWSTR)
_sig(k32.GetProcAddress, ctypes.c_void_p, wt.HMODULE, ctypes.c_char_p)

# Daten-Offsets im reservierten Block
SPEED, LOCK, LAST_REAL, FAKE, TICK_BASE, QPC_BASE, RTLQPC, TGT_BASE, MS_PER_TICK = 0, 8, 16, 24, 40, 48, 56, 64, 72
CODE = 0x100

HOOKS = {  # Funktion -> (Module, in denen sie exportiert sein kann)
    "QueryPerformanceCounter": ("kernel32.dll", "kernelbase.dll"),
    "RtlQueryPerformanceCounter": ("ntdll.dll",),
    "GetTickCount64": ("kernel32.dll", "kernelbase.dll"),
    "GetTickCount": ("kernel32.dll", "kernelbase.dll"),
    "timeGetTime": ("winmm.dll", "winmmbase.dll"),
}


def _fake_qpc(d):
    """F(): liefert gefaelschten QPC-Wert in rax. d = Adresse Datenblock."""
    return (b"\x53"                                   # push rbx
            b"\x48\x83\xEC\x30"                       # sub rsp,30h
            + b"\x48\xBB" + struct.pack("<Q", d) +    # mov rbx, D
            b"\x48\x8D\x4C\x24\x20"                   # lea rcx,[rsp+20h]
            b"\xFF\x53\x38"                           # call [rbx+38h]  (echtes RtlQueryPerformanceCounter)
            b"\xB8\x01\x00\x00\x00"                   # spin: mov eax,1
            b"\x48\x87\x43\x08"                       # xchg [rbx+8],rax   (Spinlock)
            b"\x48\x85\xC0"                           # test rax,rax
            b"\x74\x04"                               # jz got
            b"\xF3\x90"                               # pause
            b"\xEB\xEE"                               # jmp spin
            b"\x48\x8B\x4C\x24\x20"                   # got: mov rcx,[rsp+20h]  (real)
            b"\x48\x8B\x53\x10"                       # mov rdx,[rbx+10h]      (last_real)
            b"\x45\x31\xC0"                           # xor r8d,r8d
            b"\x48\x89\xC8"                           # mov rax,rcx
            b"\x48\x29\xD0"                           # sub rax,rdx            (delta)
            b"\x49\x0F\x4C\xC0"                       # cmovl rax,r8           (delta<0 -> 0)
            b"\x48\x0F\x4C\xCA"                       # cmovl rcx,rdx
            b"\x48\x89\x4B\x10"                       # mov [rbx+10h],rcx
            b"\xF2\x48\x0F\x2A\xC0"                   # cvtsi2sd xmm0,rax
            b"\xF2\x0F\x59\x03"                       # mulsd xmm0,[rbx]       (* speed)
            b"\xF2\x0F\x58\x43\x18"                   # addsd xmm0,[rbx+18h]   (+ fake)
            b"\xF2\x0F\x11\x43\x18"                   # movsd [rbx+18h],xmm0
            b"\xF2\x48\x0F\x2C\xC0"                   # cvttsd2si rax,xmm0
            b"\x48\xC7\x43\x08\x00\x00\x00\x00"       # mov qword [rbx+8],0   (unlock)
            b"\x48\x83\xC4\x30"                       # add rsp,30h
            b"\x5B"                                   # pop rbx
            b"\xC3")                                  # ret


def _call(from_end, target):
    return b"\xE8" + struct.pack("<i", target - from_end)


def _qpc_hook(at, f):
    code = b"\x56\x48\x83\xEC\x20\x48\x89\xCE"        # push rsi; sub rsp,20h; mov rsi,rcx
    code += _call(at + len(code) + 5, f)
    code += (b"\x48\x89\x06"                           # mov [rsi],rax
             b"\xB8\x01\x00\x00\x00"                   # mov eax,1
             b"\x48\x83\xC4\x20\x5E\xC3")              # add rsp,20h; pop rsi; ret
    return code


def _tick_hook(at, f, d, base_off):
    code = b"\x48\x83\xEC\x28"                         # sub rsp,28h
    code += _call(at + len(code) + 5, f)
    code += (b"\x48\xB9" + struct.pack("<Q", d) +      # mov rcx, D
             b"\x48\x2B\x41" + bytes([QPC_BASE]) +     # sub rax,[rcx+qpc_base]
             b"\xF2\x48\x0F\x2A\xC0"                   # cvtsi2sd xmm0,rax
             b"\xF2\x0F\x59\x41" + bytes([MS_PER_TICK]) +  # mulsd xmm0,[rcx+ms_per_tick]
             b"\xF2\x48\x0F\x2C\xC0"                   # cvttsd2si rax,xmm0
             b"\x48\x03\x41" + bytes([base_off]) +     # add rax,[rcx+base]
             b"\x48\x83\xC4\x28\xC3")                  # add rsp,28h; ret
    return code


class SpeedHack:
    def __init__(self, proc):
        if proc.is32:
            raise RuntimeError("Speedhack geht nur bei 64-bit Spielen.")
        self.proc = proc
        self.patched = []  # (iat_adresse, original)
        self.hooked_modules = set()
        self.installed_at = time.monotonic()
        self._install()

    def poll_interval(self):
        """Kurz nach dem Inject (Spielstart, Module laden nach) oft pruefen, danach selten."""
        return 0.25 if time.monotonic() - self.installed_at < 60 else 2.0

    def _remote_exports(self):
        me = Process(os.getpid(), "self")
        out = {}
        for fn, mods in HOOKS.items():
            for m in mods:
                h = k32.LoadLibraryW(m)
                if not h:
                    continue
                a = k32.GetProcAddress(h, fn.encode())
                loc = me.locate(a) if a else None
                if loc:
                    base = self.proc.module_base(loc[0])
                    if base is not None:
                        out[base + loc[1]] = fn
        me.close()
        return out

    def _install(self):
        p = self.proc
        p.refresh_modules()
        exports = self._remote_exports()
        rtl = next((a for a, f in exports.items() if f == "RtlQueryPerformanceCounter"), None)
        if rtl is None:
            raise RuntimeError("RtlQueryPerformanceCounter im Spiel nicht gefunden.")
        d = p.alloc(0x1000)
        if not d:
            raise RuntimeError("Konnte keinen Speicher im Spiel reservieren.")
        freq, now = ctypes.c_int64(), ctypes.c_int64()
        k32.QueryPerformanceFrequency(ctypes.byref(freq))
        k32.QueryPerformanceCounter(ctypes.byref(now))
        tick = k32.GetTickCount64()
        try:
            winmm = ctypes.WinDLL("winmm")
            winmm.timeGetTime.restype = wt.DWORD
            tgt = winmm.timeGetTime()
        except OSError:
            tgt = tick
        data = bytearray(CODE)
        struct.pack_into("<d", data, SPEED, 1.0)
        struct.pack_into("<q", data, LAST_REAL, now.value)
        struct.pack_into("<d", data, FAKE, float(now.value))
        struct.pack_into("<q", data, TICK_BASE, tick)
        struct.pack_into("<q", data, QPC_BASE, now.value)
        struct.pack_into("<Q", data, RTLQPC, rtl)
        struct.pack_into("<q", data, TGT_BASE, tgt)
        struct.pack_into("<d", data, MS_PER_TICK, 1000.0 / freq.value)

        f = d + CODE
        code = bytearray(_fake_qpc(d))
        q = f + len(code)
        code += _qpc_hook(q, f)
        t = f + len(code)
        code += _tick_hook(t, f, d, TICK_BASE)
        tg = f + len(code)
        code += _tick_hook(tg, f, d, TGT_BASE)
        p.write_bytes(d, bytes(data) + bytes(code), code=True)
        self.data = d
        self.code = bytes(code)
        self.code_addr = f
        target = {"QueryPerformanceCounter": q, "RtlQueryPerformanceCounter": q,
                  "GetTickCount64": t, "GetTickCount": t, "timeGetTime": tg}
        self.redirect = {a: target[fn] for a, fn in exports.items()}
        self.hook_new_modules()

    def _imports(self, base):
        """Liefert alle IAT-Slot-Adressen eines Moduls."""
        p = self.proc
        hdr = p.read_bytes(base, 0x40)
        if not hdr or hdr[:2] != b"MZ":
            return
        nt = base + struct.unpack_from("<I", hdr, 0x3C)[0]
        opt = p.read_bytes(nt + 24, 128)
        if not opt or struct.unpack_from("<H", opt, 0)[0] != 0x20B:
            return
        rva, size = struct.unpack_from("<II", opt, 120)
        if not rva:
            return
        for i in range(2048):
            desc = p.read_bytes(base + rva + i * 20, 20)
            if not desc:
                return
            oft, _, _, name, ft = struct.unpack("<IIIII", desc)
            if not name and not ft:
                return
            for j in range(8192):
                slot = base + ft + j * 8
                v = p.read_ptr(slot)
                if not v:
                    break
                yield slot, v

    def maybe_hook_new_modules(self):
        """Aus einer Timer-Schleife aufrufen; haelt das passende Intervall selbst ein."""
        now = time.monotonic()
        if now - getattr(self, "_last_poll", 0) >= self.poll_interval():
            self._last_poll = now
            return self.hook_new_modules()
        return 0

    def hook_new_modules(self):
        """Neu geladene Module ebenfalls umbiegen (regelmaessig aufrufen)."""
        self.proc.refresh_modules()
        n = 0
        for base, _, name in self.proc.modules:
            if base in self.hooked_modules:
                continue
            self.hooked_modules.add(base)
            for slot, v in self._imports(base):
                new = self.redirect.get(v)
                if new and self.proc.write_bytes(slot, struct.pack("<Q", new)):
                    self.patched.append((slot, v))
                    n += 1
        return n

    def set_speed(self, speed):
        self.proc.write_bytes(self.data + SPEED, struct.pack("<d", float(speed)))

    def get_speed(self):
        b = self.proc.read_bytes(self.data + SPEED, 8)
        return struct.unpack("<d", b)[0] if b else None

    def remove(self, restore_iat=False):
        """Zurueck auf 1.0x. Die Hooks bleiben standardmaessig aktiv, sonst wuerde die Spielzeit
        auf die echte Zeit zurueckspringen (kann Spiele verwirren)."""
        self.set_speed(1.0)
        if not restore_iat:
            return
        for slot, orig in self.patched:
            self.proc.write_bytes(slot, struct.pack("<Q", orig))
        self.patched.clear()
