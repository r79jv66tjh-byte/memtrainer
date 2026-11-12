"""Funktionen im Zielprozess aufrufen (nur 64-bit) und Exporte fremder Module finden.

Grundlage für die Unity-Hilfe: Ein kleiner Maschinencode-Interpreter im Spiel arbeitet eine
Tabelle von Aufrufen ab (fn, a1..a4 -> Ergebnis). So genügen wenige Remote-Threads auch für
zehntausende Aufrufe. Optional wird der Thread vorher bei der Laufzeit angemeldet
(z. B. il2cpp_thread_attach) und danach wieder abgemeldet.
"""
import ctypes
import ctypes.wintypes as wt
import struct

from scanner_core import k32, _sig

PROCESS_CREATE_THREAD = 0x0002
PROCESS_VM_OPERATION = 0x0008
PROCESS_VM_READ = 0x0010
PROCESS_VM_WRITE = 0x0020
PROCESS_QUERY_INFORMATION = 0x0400
SYNCHRONIZE = 0x00100000
MEM_COMMIT_RESERVE = 0x3000
MEM_RELEASE = 0x8000
PAGE_RW = 0x04
PAGE_RWX = 0x40
WAIT_OBJECT_0 = 0

_sig(k32.CreateRemoteThread, wt.HANDLE, wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, ctypes.c_void_p,
     ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD))
_sig(k32.VirtualFreeEx, wt.BOOL, wt.HANDLE, ctypes.c_void_p, ctypes.c_size_t, wt.DWORD)
_sig(k32.WaitForSingleObject, wt.DWORD, wt.HANDLE, wt.DWORD)
_sig(k32.GetExitCodeThread, wt.BOOL, wt.HANDLE, ctypes.POINTER(wt.DWORD))

ENTRY = 0x30   # fn, a1, a2, a3, a4, ergebnis
HEADER = 0x20  # attach_fn, attach_arg, detach_fn, anzahl


class RemoteError(RuntimeError):
    pass


def _batch_code():
    """Interpreter: rcx = Header. Ruft optional attach(arg) auf, dann alle Einträge, dann detach(thread)."""
    loop_body = (b"\x48\x8B\x4B\x08"      # mov rcx,[rbx+8]
                 b"\x48\x8B\x53\x10"      # mov rdx,[rbx+10h]
                 b"\x4C\x8B\x43\x18"      # mov r8,[rbx+18h]
                 b"\x4C\x8B\x4B\x20"      # mov r9,[rbx+20h]
                 b"\xFF\x13"              # call [rbx]
                 b"\x48\x89\x43\x28"      # mov [rbx+28h],rax
                 b"\x48\x83\xC3\x30"      # add rbx,30h
                 b"\x48\xFF\xCE")         # dec rsi
    loop = b"\x48\x85\xF6" + b"\x74" + bytes([len(loop_body) + 2]) + loop_body  # test rsi,rsi; jz end
    loop += b"\xEB" + struct.pack("<b", -(len(loop) + 2))                       # jmp loop
    attach = (b"\x48\x8B\x4B\x08"         # mov rcx,[rbx+8]
              b"\xFF\xD0"                 # call rax
              b"\x48\x89\xC7")            # mov rdi,rax
    detach = b"\x48\x89\xF9\x41\xFF\xD4"  # mov rcx,rdi; call r12
    return (b"\x53\x56\x57\x41\x54"       # push rbx/rsi/rdi/r12
            b"\x48\x83\xEC\x28"           # sub rsp,28h (Stack 16-Byte-ausgerichtet + Schattenbereich)
            b"\x48\x89\xCB"               # mov rbx,rcx
            b"\x31\xFF"                   # xor edi,edi
            b"\x4C\x8B\x63\x10"           # mov r12,[rbx+10h]  (detach_fn)
            b"\x48\x8B\x03"               # mov rax,[rbx]      (attach_fn)
            b"\x48\x85\xC0"               # test rax,rax
            + b"\x74" + bytes([len(attach)]) + attach +
            b"\x48\x8B\x73\x18"           # mov rsi,[rbx+18h]  (anzahl)
            b"\x48\x83\xC3\x20"           # add rbx,20h        (erster Eintrag)
            + loop +
            b"\x4D\x85\xE4"               # test r12,r12
            + b"\x74" + bytes([len(detach)]) + detach +
            b"\x31\xC0"                   # xor eax,eax
            b"\x48\x83\xC4\x28"           # add rsp,28h
            b"\x41\x5C\x5F\x5E\x5B"       # pop r12/rdi/rsi/rbx
            b"\xC3")                      # ret


# Callback für mono_assembly_foreach(cb, user): user = {anzahl, zeiger[]}
APPEND_CB = (b"\x48\x8B\x02"              # mov rax,[rdx]
             b"\x48\x89\x4C\xC2\x08"      # mov [rdx+rax*8+8],rcx
             b"\x48\xFF\x02"              # inc qword [rdx]
             b"\xC3")


def remote_exports(proc, module):
    """Name -> absolute Adresse aller (nicht weitergeleiteten) Exporte eines Moduls im Zielprozess."""
    base = proc.module_base(module)
    if base is None:
        return {}
    hdr = proc.read_bytes(base, 0x400)
    if not hdr or hdr[:2] != b"MZ":
        return {}
    pe = struct.unpack_from("<I", hdr, 0x3C)[0]
    magic = struct.unpack_from("<H", hdr, pe + 0x18)[0]
    dd = pe + 0x18 + (0x70 if magic == 0x20B else 0x60)
    rva, size = struct.unpack_from("<II", hdr, dd)
    if not rva:
        return {}
    exp = proc.read_bytes(base + rva, 40)
    if not exp:
        return {}
    n_funcs, n_names, a_funcs, a_names, a_ords = struct.unpack_from("<IIIII", exp, 20)
    funcs = proc.read_bytes(base + a_funcs, n_funcs * 4) or b""
    names = proc.read_bytes(base + a_names, n_names * 4) or b""
    ords = proc.read_bytes(base + a_ords, n_names * 2) or b""
    out = {}
    blob_lo = min(struct.unpack_from(f"<{n_names}I", names)) if n_names and names else 0
    blob_hi = max(struct.unpack_from(f"<{n_names}I", names)) + 256 if n_names and names else 0
    blob = proc.read_bytes(base + blob_lo, blob_hi - blob_lo) if blob_hi else None
    for i in range(min(n_names, len(names) // 4, len(ords) // 2)):
        nrva = struct.unpack_from("<I", names, i * 4)[0]
        if blob is not None:
            s = blob[nrva - blob_lo:nrva - blob_lo + 256]
        else:
            s = proc.read_bytes(base + nrva, 128) or b""
        name = s.split(b"\0", 1)[0].decode("ascii", "replace")
        o = struct.unpack_from("<H", ords, i * 2)[0]
        if o * 4 + 4 > len(funcs):
            continue
        frva = struct.unpack_from("<I", funcs, o * 4)[0]
        if rva <= frva < rva + size:  # Weiterleitung („forwarder“)
            continue
        out[name] = base + frva
    return out


class RemoteCaller:
    """Führt Funktionsaufrufe im Zielprozess aus."""

    def __init__(self, proc, timeout_ms=60000):
        if proc.is32:
            raise RemoteError("Nur für 64-bit Spiele.")
        self.proc = proc
        self.timeout = timeout_ms
        rights = (PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_READ | PROCESS_VM_WRITE
                  | PROCESS_QUERY_INFORMATION | SYNCHRONIZE)
        self.h = k32.OpenProcess(rights, False, proc.pid)
        if not self.h:
            raise RemoteError(f"Prozess nicht zugreifbar (Fehler {ctypes.get_last_error()}).")
        code = _batch_code()
        self.code = self._alloc(0x1000, PAGE_RWX)
        self.cb = self.code + 0x800
        self._write(self.code, code)
        self._write(self.cb, APPEND_CB)
        self.attach = (0, 0, 0)  # attach_fn, arg, detach_fn

    def close(self):
        if self.h:
            k32.VirtualFreeEx(self.h, self.code, 0, MEM_RELEASE)
            k32.CloseHandle(self.h)
            self.h = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    # -- Speicher -----------------------------------------------------------
    def _alloc(self, size, prot=PAGE_RW):
        p = k32.VirtualAllocEx(self.h, None, size, MEM_COMMIT_RESERVE, prot)
        if not p:
            raise RemoteError(f"Kein Speicher im Spiel reservierbar (Fehler {ctypes.get_last_error()}).")
        return p

    def _write(self, addr, data):
        n = ctypes.c_size_t()
        if not k32.WriteProcessMemory(self.h, addr, data, len(data), ctypes.byref(n)):
            raise RemoteError("Schreiben in den Spielspeicher fehlgeschlagen.")

    def alloc(self, size):
        """Arbeitsspeicher im Ziel (z. B. für Ausgabe-Parameter). Mit free() freigeben."""
        return self._alloc(max(size, 16))

    def free(self, addr):
        k32.VirtualFreeEx(self.h, addr, 0, MEM_RELEASE)

    def write(self, addr, data):
        self._write(addr, data)

    def cstring(self, text):
        data = text.encode("utf-8") + b"\0"
        p = self.alloc(len(data))
        self._write(p, data)
        return p

    # -- Aufrufe ------------------------------------------------------------
    def call(self, fn, *args):
        return self.batch([(fn, *args)])[0]

    def batch(self, calls, chunk=20000):
        """calls: Liste von (fn, a1, ...) mit bis zu 4 Argumenten. Liefert Liste der Rückgabewerte (rax)."""
        out = []
        for i in range(0, len(calls), chunk):
            out.extend(self._run(calls[i:i + chunk]))
        return out

    def _run(self, calls):
        if not calls:
            return []
        n = len(calls)
        buf = bytearray(HEADER + n * ENTRY)
        struct.pack_into("<QQQQ", buf, 0, *self.attach, n)
        for i, c in enumerate(calls):
            if not c[0]:
                raise RemoteError("Funktion im Spiel nicht gefunden.")
            args = list(c[1:]) + [0] * (4 - len(c) + 1)
            struct.pack_into("<QQQQQQ", buf, HEADER + i * ENTRY, c[0], *[a & 0xFFFFFFFFFFFFFFFF for a in args[:4]], 0)
        mem = self._alloc(len(buf))
        try:
            self._write(mem, bytes(buf))
            tid = wt.DWORD()
            th = k32.CreateRemoteThread(self.h, None, 0, self.code, mem, 0, ctypes.byref(tid))
            if not th:
                raise RemoteError(f"Remote-Thread konnte nicht gestartet werden (Fehler {ctypes.get_last_error()}).")
            try:
                if k32.WaitForSingleObject(th, self.timeout) != WAIT_OBJECT_0:
                    raise RemoteError("Zeitüberschreitung beim Aufruf im Spiel.")
            finally:
                k32.CloseHandle(th)
            res = self.proc.read_bytes(mem, len(buf))
            if res is None:
                raise RemoteError("Ergebnisse nicht lesbar.")
            return [struct.unpack_from("<Q", res, HEADER + i * ENTRY + 0x28)[0] for i in range(n)]
        finally:
            k32.VirtualFreeEx(self.h, mem, 0, MEM_RELEASE)
