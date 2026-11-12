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
                 b"\xF3\x0F\x7E\x43\x08"  # movq xmm0,[rbx+8]   (Float-/Double-Argumente: gleiche Position)
                 b"\xF3\x0F\x7E\x4B\x10"  # movq xmm1,[rbx+10h]
                 b"\xF3\x0F\x7E\x53\x18"  # movq xmm2,[rbx+18h]
                 b"\xF3\x0F\x7E\x5B\x20"  # movq xmm3,[rbx+20h]
                 b"\xFF\x13"           # call [rbx]
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


# -- Aufrufe im Hauptthread ----------------------------------------------------------
# Viele Spiel-Funktionen (Unity!) dürfen nur aus dem Hauptthread laufen. Dafür hängt sich
# MainThreadHook an den Anfang einer Funktion, die das Spiel jedes Bild aufruft (z. B. ein
# Update()). Der Einsprung prüft eine Marke; ist ein Auftrag da, arbeitet er ihn mit dem
# Batch-Interpreter ab und läuft dann normal weiter.

H_FLAG, H_REQ = 0x400, 0x408   # Marke (0 frei, 1 Auftrag, 3 läuft, 2 fertig), Zeiger auf Auftrag
H_THIS = 0x410                 # rcx beim letzten Aufruf (bei Methoden: das Objekt, „this“)
H_STUB = 0x200


def _relocate(code, src, dst):
    """Mindestens 5 Byte ab src nach dst verschieben (RIP-relative Adressen anpassen)."""
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    out, n = bytearray(), 0
    for ins in md.disasm(code, src):
        if ins.mnemonic in ("ret", "int3"):
            raise RemoteError("Funktion ist zu kurz zum Einhängen.")
        b = bytearray(ins.bytes)
        new = dst + len(out)
        if capstone.CS_GRP_BRANCH_RELATIVE in ins.groups:
            if ins.mnemonic not in ("call", "jmp") or len(b) != 5:
                raise RemoteError(f"Funktionsanfang nicht verschiebbar ({ins.mnemonic} {ins.op_str}).")
            target = ins.operands[0].imm
            b[1:5] = struct.pack("<i", target - (new + 5))
        elif any(o.type == capstone.x86.X86_OP_MEM and o.mem.base == capstone.x86.X86_REG_RIP
                 for o in ins.operands):
            off = ins.disp_offset
            disp = struct.unpack_from("<i", b, off)[0]
            nd = disp + ins.address - new
            if not -2**31 <= nd < 2**31:
                raise RemoteError("Ausweichcode liegt zu weit weg.")
            struct.pack_into("<i", b, off, nd)
        out += b
        n += ins.size
        if n >= 5:
            return bytes(out), n
    raise RemoteError("Funktionsanfang nicht lesbar.")


def _stub(base, relocated, back):
    """Einsprung: Register sichern, ggf. Auftrag ausführen, Register zurück, Original weiter."""
    here = base + H_STUB
    s = bytearray()
    s += b"\x48\x89\x0D" + struct.pack("<i", base + H_THIS - (here + 7))  # mov [this],rcx
    s += b"\x50\x51\x52\x41\x50\x41\x51\x41\x52\x41\x53\x9C"   # push rax,rcx,rdx,r8-r11; pushfq
    s += b"\x48\x81\xEC\x88\x00\x00\x00"                         # sub rsp,88h (ausgerichtet + Schatten)
    for i in range(6):                                           # movdqu [rsp+20h+i*16],xmm i
        s += b"\xF3\x0F\x7F" + bytes([0x44 | (i << 3), 0x24, 0x20 + i * 16])
    s += b"\xB8\x01\x00\x00\x00"                                 # mov eax,1
    s += b"\xB9\x03\x00\x00\x00"                                 # mov ecx,3
    s += b"\xF0\x0F\xB1\x0D" + struct.pack("<i", base + H_FLAG - (here + len(s) + 8))  # lock cmpxchg [flag],ecx
    s += b"\x75\x00"
    jne = len(s) - 1
    s += b"\x48\x8B\x0D" + struct.pack("<i", base + H_REQ - (here + len(s) + 7))      # mov rcx,[req]
    s += b"\xE8" + struct.pack("<i", base - (here + len(s) + 5))                      # call Interpreter
    s += b"\xC7\x05" + struct.pack("<i", base + H_FLAG - (here + len(s) + 10)) + b"\x02\x00\x00\x00"  # mov [flag],2
    s[jne] = len(s) - jne - 1
    for i in range(6):                                           # movdqu xmm i,[rsp+20h+i*16]
        s += b"\xF3\x0F\x6F" + bytes([0x44 | (i << 3), 0x24, 0x20 + i * 16])
    s += b"\x48\x81\xC4\x88\x00\x00\x00"                         # add rsp,88h
    s += b"\x9D\x41\x5B\x41\x5A\x41\x59\x41\x58\x5A\x59\x58"   # popfq; pop r11..rax
    rel_at = len(s)
    s += relocated
    s += b"\xFF\x25\x00\x00\x00\x00" + struct.pack("<Q", back)   # jmp [rip+0] -> zurück
    return bytes(s), rel_at


_OPEN_HOOKS = set()


def _close_open_hooks():
    for h in list(_OPEN_HOOKS):
        try:
            h.close()
        except Exception:  # noqa: BLE001 - beim Beenden nichts mehr melden
            pass


import atexit  # noqa: E402

atexit.register(_close_open_hooks)


class MainThreadHook:
    """Ruft Funktionen im Thread auf, der 'hook_addr' ausführt (z. B. Unitys Hauptthread).

    Ablauf: hook = MainThreadHook(proc, GameManager.Update); hook.batch([(fn, a1, a2)]); hook.close()
    Das Spiel muss dabei laufen (nicht minimiert/eingefroren), sonst gibt es eine Zeitüberschreitung.
    """

    def __init__(self, proc, hook_addr, attach=(0, 0, 0)):
        if proc.is32:
            raise RemoteError("Nur für 64-bit Spiele.")
        import threading
        self.lock = threading.Lock()
        self.proc, self.addr, self.attach = proc, hook_addr, attach
        self.rc = RemoteCaller(proc)
        self.base = proc.alloc(0x1000, near=hook_addr)
        if not self.base:
            raise RemoteError("Kein Speicher in der Nähe der Funktion frei.")
        orig = proc.read_bytes(hook_addr, 32)
        if not orig:
            raise RemoteError("Funktion nicht lesbar.")
        relocated, n = _relocate(orig, hook_addr, self.base + H_STUB + 0x80)  # vorläufig, s. u.
        stub, rel_at = _stub(self.base, b"\x90" * len(relocated), hook_addr + n)
        relocated, n = _relocate(orig, hook_addr, self.base + H_STUB + rel_at)
        stub, _ = _stub(self.base, relocated, hook_addr + n)
        self.orig = orig[:n]
        self.rc.write(self.base, _batch_code())
        self.rc.write(self.base + H_STUB, stub)
        self.rc.write(self.base + H_FLAG, b"\0" * 24)
        jmp = b"\xE9" + struct.pack("<i", self.base + H_STUB - (hook_addr + 5)) + b"\x90" * (n - 5)
        if not proc.write_bytes(hook_addr, jmp, code=True):
            raise RemoteError("Einhängen fehlgeschlagen.")
        self.hooked = True
        _OPEN_HOOKS.add(self)

    def batch(self, calls, timeout=5.0):
        """Wie RemoteCaller.batch, aber im Hauptthread. Wartet, bis das Spiel die Funktion aufruft."""
        with self.lock:
            return self._batch(calls, timeout)

    def _batch(self, calls, timeout):
        import time
        n = len(calls)
        buf = bytearray(HEADER + n * ENTRY)
        struct.pack_into("<QQQQ", buf, 0, *self.attach, n)
        for i, c in enumerate(calls):
            if not c[0]:
                raise RemoteError("Funktion im Spiel nicht gefunden.")
            args = list(c[1:]) + [0] * 4
            struct.pack_into("<QQQQQQ", buf, HEADER + i * ENTRY, c[0], *[a & 0xFFFFFFFFFFFFFFFF for a in args[:4]], 0)
        mem = self.rc.alloc(len(buf))
        self.rc.write(mem, bytes(buf))
        self.rc.write(self.base + H_REQ, struct.pack("<Q", mem))
        self.rc.write(self.base + H_FLAG, struct.pack("<I", 1))
        end = time.time() + timeout
        while True:
            flag = struct.unpack("<I", self.proc.read_bytes(self.base + H_FLAG, 4))[0]
            if flag == 2:
                break
            if time.time() > end:
                if flag == 1:  # Auftrag zurückziehen (Puffer bleibt reserviert, falls er gerade startet)
                    self.rc.write(self.base + H_FLAG, struct.pack("<I", 0))
                    raise RemoteError("Zeitüberschreitung: Das Spiel hat die Funktion nicht aufgerufen "
                                          "(Spiel im Menü, pausiert oder minimiert?).")
                end = time.time() + 30  # läuft schon: abwarten
            time.sleep(0.005)
        res = self.proc.read_bytes(mem, len(buf))
        self.rc.write(self.base + H_FLAG, struct.pack("<I", 0))
        self.rc.free(mem)
        return [struct.unpack_from("<Q", res, HEADER + i * ENTRY + 0x28)[0] for i in range(n)]

    def call(self, fn, *args, timeout=5.0):
        return self.batch([(fn, *args)], timeout)[0]

    def last_this(self):
        """rcx beim letzten Durchlauf der eingehängten Funktion (0, wenn sie noch nicht lief)."""
        return struct.unpack("<Q", self.proc.read_bytes(self.base + H_THIS, 8))[0]

    def fires(self, timeout=1.0):
        """True, wenn das Spiel die eingehängte Funktion gerade regelmäßig aufruft."""
        import time
        self.rc.write(self.base + H_THIS, b"\0" * 8)
        end = time.time() + timeout
        while time.time() < end:
            if self.last_this():
                return True
            time.sleep(0.01)
        return False

    def close(self):
        """Original wiederherstellen. Der Ausweichcode bleibt im Spiel (ein Thread könnte noch darin sein)."""
        if getattr(self, "hooked", False):
            self.proc.write_bytes(self.addr, self.orig, code=True)
            self.hooked = False
        _OPEN_HOOKS.discard(self)
        self.rc.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
