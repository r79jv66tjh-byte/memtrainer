"""'Was schreibt/greift auf diese Adresse zu?' per Hardware-Breakpoint (Debug-Register DR0/DR7).

Haengt sich kurz als Debugger an den Prozess, sammelt die Code-Adressen, die auf die Adresse
zugreifen, und loest sich danach wieder (das Spiel laeuft normal weiter).
Hinweis: Spiele mit Anti-Debug-Schutz koennen dabei abstuerzen.
"""
import collections
import ctypes
import ctypes.wintypes as wt
import struct
import threading
import time

from scanner_core import k32, _sig

DBG_CONTINUE = 0x00010002
DBG_EXCEPTION_NOT_HANDLED = 0x80010001
EXCEPTION_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, CREATE_PROCESS_DEBUG_EVENT = 1, 2, 3
EXIT_THREAD_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT, LOAD_DLL_DEBUG_EVENT = 4, 5, 6
EXC_BREAKPOINT, EXC_SINGLE_STEP = 0x80000003, 0x80000004
WX86_BREAKPOINT, WX86_SINGLE_STEP = 0x4000001F, 0x4000001E
THREAD_ACCESS = 0x0002 | 0x0008 | 0x0010 | 0x0040  # suspend/resume, get/set context, query
TH32CS_SNAPTHREAD = 0x4

# x64 CONTEXT (1232 Bytes, 16-Byte-ausgerichtet)
CTX64_SIZE, CTX64_FLAGS = 1232, 0x100013  # CONTROL | INTEGER | DEBUG_REGISTERS
CTX64 = {"flags": 48, "dr0": 72, "dr6": 104, "dr7": 112, "ip": 248, "eflags": 0x44,
         "rax": 0x78, "rcx": 0x80, "rdx": 0x88, "rbx": 0x90, "rsp": 0x98, "rbp": 0xA0, "rsi": 0xA8,
         "rdi": 0xB0, "r8": 0xB8, "r9": 0xC0, "r10": 0xC8, "r11": 0xD0, "r12": 0xD8, "r13": 0xE0,
         "r14": 0xE8, "r15": 0xF0}
# WOW64_CONTEXT (32-bit Spiele)
CTX32_SIZE, CTX32_FLAGS = 716, 0x10013
CTX32 = {"flags": 0, "dr0": 4, "dr6": 20, "dr7": 24, "ip": 184, "eflags": 0xC0,
         "edi": 0x9C, "esi": 0xA0, "ebx": 0xA4, "edx": 0xA8, "ecx": 0xAC, "eax": 0xB0, "ebp": 0xB4,
         "esp": 0xC4}
DWORD_KEYS = {"flags", "eflags"}
RESUME_FLAG = 0x10000


class EXCEPTION_RECORD(ctypes.Structure):
    _fields_ = [("ExceptionCode", wt.DWORD), ("ExceptionFlags", wt.DWORD),
                ("ExceptionRecord", ctypes.c_void_p), ("ExceptionAddress", ctypes.c_void_p),
                ("NumberParameters", wt.DWORD), ("ExceptionInformation", ctypes.c_size_t * 15)]


class EXCEPTION_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("ExceptionRecord", EXCEPTION_RECORD), ("dwFirstChance", wt.DWORD)]


class CREATE_THREAD_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hThread", wt.HANDLE), ("lpThreadLocalBase", ctypes.c_void_p),
                ("lpStartAddress", ctypes.c_void_p)]


class CREATE_PROCESS_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", wt.HANDLE), ("hProcess", wt.HANDLE), ("hThread", wt.HANDLE),
                ("lpBaseOfImage", ctypes.c_void_p), ("dwDebugInfoFileOffset", wt.DWORD),
                ("nDebugInfoSize", wt.DWORD), ("lpThreadLocalBase", ctypes.c_void_p),
                ("lpStartAddress", ctypes.c_void_p), ("lpImageName", ctypes.c_void_p),
                ("fUnicode", wt.WORD)]


class LOAD_DLL_DEBUG_INFO(ctypes.Structure):
    _fields_ = [("hFile", wt.HANDLE), ("lpBaseOfDll", ctypes.c_void_p),
                ("dwDebugInfoFileOffset", wt.DWORD), ("nDebugInfoSize", wt.DWORD),
                ("lpImageName", ctypes.c_void_p), ("fUnicode", wt.WORD)]


class _U(ctypes.Union):
    _fields_ = [("Exception", EXCEPTION_DEBUG_INFO), ("CreateThread", CREATE_THREAD_DEBUG_INFO),
                ("CreateProcessInfo", CREATE_PROCESS_DEBUG_INFO), ("LoadDll", LOAD_DLL_DEBUG_INFO),
                ("raw", ctypes.c_byte * 160)]


class DEBUG_EVENT(ctypes.Structure):
    _fields_ = [("dwDebugEventCode", wt.DWORD), ("dwProcessId", wt.DWORD),
                ("dwThreadId", wt.DWORD), ("u", _U)]


class THREADENTRY32(ctypes.Structure):
    _fields_ = [("dwSize", wt.DWORD), ("cntUsage", wt.DWORD), ("th32ThreadID", wt.DWORD),
                ("th32OwnerProcessID", wt.DWORD), ("tpBasePri", ctypes.c_long),
                ("tpDeltaPri", ctypes.c_long), ("dwFlags", wt.DWORD)]


_sig(k32.DebugActiveProcess, wt.BOOL, wt.DWORD)
_sig(k32.DebugActiveProcessStop, wt.BOOL, wt.DWORD)
_sig(k32.DebugSetProcessKillOnExit, wt.BOOL, wt.BOOL)
_sig(k32.WaitForDebugEvent, wt.BOOL, ctypes.POINTER(DEBUG_EVENT), wt.DWORD)
_sig(k32.ContinueDebugEvent, wt.BOOL, wt.DWORD, wt.DWORD, wt.DWORD)
_sig(k32.GetThreadContext, wt.BOOL, wt.HANDLE, ctypes.c_void_p)
_sig(k32.SetThreadContext, wt.BOOL, wt.HANDLE, ctypes.c_void_p)
_sig(k32.Wow64GetThreadContext, wt.BOOL, wt.HANDLE, ctypes.c_void_p)
_sig(k32.Wow64SetThreadContext, wt.BOOL, wt.HANDLE, ctypes.c_void_p)
_sig(k32.OpenThread, wt.HANDLE, wt.DWORD, wt.BOOL, wt.DWORD)
_sig(k32.SuspendThread, wt.DWORD, wt.HANDLE)
_sig(k32.ResumeThread, wt.DWORD, wt.HANDLE)
_sig(k32.Thread32First, wt.BOOL, wt.HANDLE, ctypes.POINTER(THREADENTRY32))
_sig(k32.Thread32Next, wt.BOOL, wt.HANDLE, ctypes.POINTER(THREADENTRY32))


class _Ctx:
    """Ausgerichteter CONTEXT-Puffer."""

    def __init__(self, is32):
        self.is32 = is32
        self.size, self.flags, self.off = (CTX32_SIZE, CTX32_FLAGS, CTX32) if is32 else (CTX64_SIZE, CTX64_FLAGS, CTX64)
        self.raw = ctypes.create_string_buffer(self.size + 16)
        self.addr = (ctypes.addressof(self.raw) + 15) & ~15
        self.buf = (ctypes.c_char * self.size).from_address(self.addr)

    def get(self, th):
        ctypes.memset(self.addr, 0, self.size)
        struct.pack_into("<I", self.buf, self.off["flags"], self.flags)
        fn = k32.Wow64GetThreadContext if self.is32 else k32.GetThreadContext
        return bool(fn(th, self.addr))

    def set(self, th):
        fn = k32.Wow64SetThreadContext if self.is32 else k32.SetThreadContext
        return bool(fn(th, self.addr))

    def _fmt(self, k):
        return "<I" if self.is32 or k in DWORD_KEYS else "<Q"

    def __getitem__(self, k):
        return struct.unpack_from(self._fmt(k), self.buf, self.off[k])[0]

    def __setitem__(self, k, v):
        struct.pack_into(self._fmt(k), self.buf, self.off[k], v)

    def reg(self, name):
        """Registerwert per Name (rax, r8d -> r8, eax -> rax bei 64-bit …); None, wenn unbekannt."""
        name = name.lower()
        if name in self.off and name not in ("flags", "dr0", "dr6", "dr7"):
            return self[name]
        if not self.is32:
            alias = {"e" + n[1:]: n for n in ("rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi")}
            if name in alias:
                return self[alias[name]] & 0xFFFFFFFF
            if name.startswith("r") and name[-1] in "dwb" and name[1:-1].isdigit():
                mask = {"d": 0xFFFFFFFF, "w": 0xFFFF, "b": 0xFF}[name[-1]]
                return self[name[:-1]] & mask
        return None


def _dr7(size, access):
    """access: 'w' = schreiben, 'rw' = lesen/schreiben, 'x' = ausführen."""
    if access == "x":
        return 1
    rw = 0b01 if access == "w" else 0b11
    ln = {1: 0b00, 2: 0b01, 4: 0b11, 8: 0b10}[size]
    return 1 | (rw << 16) | (ln << 18)


class AccessWatcher:
    """Startet einen Debug-Thread. hits: Counter {Instruktions-Endadresse: Anzahl}."""

    def __init__(self, proc, addr, size=4, access="w"):
        if access == "x" or size not in (1, 2, 4, 8) or addr % size:
            size = 1
        self.proc, self.addr, self.size, self.access = proc, addr, size, access
        self.hits = collections.Counter()
        self.error = None
        self.running = False
        self._stop = threading.Event()
        self._threads = {}
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self.running = True
        self._thread.start()

    def stop(self):
        self._stop.set()

    def join(self, timeout=None):
        self._thread.join(timeout)

    def _apply(self, th, enable):
        ctx = _Ctx(self.proc.is32)
        if not ctx.get(th):
            return
        if enable:
            ctx["dr0"] = self.addr
            ctx["dr7"] = (ctx["dr7"] & ~0xF0003) | _dr7(self.size, self.access)
        else:
            ctx["dr0"] = 0
            ctx["dr7"] = ctx["dr7"] & ~0xF0003
        ctx["dr6"] = 0
        ctx.set(th)

    def _run(self):
        pid = self.proc.pid
        if not k32.DebugActiveProcess(pid):
            self.error = f"Debugger konnte nicht angehängt werden (Fehler {ctypes.get_last_error()})."
            self.running = False
            return
        k32.DebugSetProcessKillOnExit(False)
        ev = DEBUG_EVENT()
        self._seen_bp = set()
        exited = False
        try:
            while not self._stop.is_set():
                if not k32.WaitForDebugEvent(ctypes.byref(ev), 100):
                    continue
                if self._dispatch(ev, draining=False):
                    exited = True
                    break
        finally:
            if not exited:
                self._cleanup()
                exited = self._drain(ev)
                if not exited:
                    k32.DebugActiveProcessStop(pid)
            self.running = False

    def _drain(self, ev, quiet_ms=150, max_s=3.0):
        """Noch anstehende Ereignisse abarbeiten, bevor sich der Debugger löst. Sonst reicht Windows einen
        bereits ausgelösten Breakpoint beim Lösen als unbehandelte Ausnahme weiter -> Spiel stürzt ab."""
        end = time.time() + max_s
        while time.time() < end:
            if not k32.WaitForDebugEvent(ctypes.byref(ev), quiet_ms):
                return False
            if self._dispatch(ev, draining=True):
                return True
        return False

    def _dispatch(self, ev, draining):
        """Ein Debug-Ereignis behandeln und fortsetzen. True, wenn der Prozess beendet wurde."""
        code, status = ev.dwDebugEventCode, DBG_CONTINUE
        if code == CREATE_PROCESS_DEBUG_EVENT:
            info = ev.u.CreateProcessInfo
            if info.hFile:
                k32.CloseHandle(info.hFile)
            self._threads[ev.dwThreadId] = info.hThread
            if not draining:
                self._apply(info.hThread, True)
        elif code == CREATE_THREAD_DEBUG_EVENT:
            self._threads[ev.dwThreadId] = ev.u.CreateThread.hThread
            if not draining:
                self._apply(ev.u.CreateThread.hThread, True)
        elif code == EXIT_THREAD_DEBUG_EVENT:
            self._threads.pop(ev.dwThreadId, None)
        elif code == LOAD_DLL_DEBUG_EVENT:
            if ev.u.LoadDll.hFile:
                k32.CloseHandle(ev.u.LoadDll.hFile)
        elif code == EXIT_PROCESS_DEBUG_EVENT:
            k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)
            return True
        elif code == EXCEPTION_DEBUG_EVENT:
            exc = ev.u.Exception.ExceptionRecord.ExceptionCode
            if exc in (EXC_SINGLE_STEP, WX86_SINGLE_STEP):
                th = self._threads.get(ev.dwThreadId)
                ctx = _Ctx(self.proc.is32)
                ok = bool(th) and ctx.get(th)
                if ok and (ctx["dr6"] & 1 or draining):
                    if ctx["dr6"] & 1 and not draining:
                        self._on_hit(ctx)
                    ctx["dr6"] = 0
                    if self.access == "x":  # Befehl beim Fortsetzen nicht erneut anhalten
                        ctx["eflags"] = ctx["eflags"] | RESUME_FLAG
                    if draining:
                        ctx["dr7"] = ctx["dr7"] & ~0xF0003
                    ctx.set(th)
                elif not draining:
                    status = DBG_EXCEPTION_NOT_HANDLED
            elif exc in (EXC_BREAKPOINT, WX86_BREAKPOINT) and exc not in self._seen_bp:
                self._seen_bp.add(exc)  # Anhalte-Breakpoint beim Anhaengen (WoW64: zwei)
            else:
                status = DBG_EXCEPTION_NOT_HANDLED
        k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status)
        return False

    def _on_hit(self, ctx):
        self.hits[ctx["ip"]] += 1

    def _cleanup(self):
        """Debug-Register in allen Threads zuruecksetzen."""
        snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0)
        te = THREADENTRY32()
        te.dwSize = ctypes.sizeof(te)
        ok = k32.Thread32First(snap, ctypes.byref(te))
        while ok:
            if te.th32OwnerProcessID == self.proc.pid:
                th = k32.OpenThread(THREAD_ACCESS, False, te.th32ThreadID)
                if th:
                    k32.SuspendThread(th)
                    self._apply(th, False)
                    k32.ResumeThread(th)
                    k32.CloseHandle(th)
            ok = k32.Thread32Next(snap, ctypes.byref(te))
        k32.CloseHandle(snap)


def find_instruction(proc, end_addr):
    """Bestimmt die Instruktion, die direkt VOR end_addr endet (Hardware-BP meldet die Adresse danach).

    Liefert (start, size, bytes, text). text nur mit capstone.
    """
    window = 32
    data = proc.read_bytes(end_addr - window, window)
    if data is None:
        return None
    try:
        import capstone
    except ImportError:
        return None
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32 if proc.is32 else capstone.CS_MODE_64)
    votes = collections.Counter()
    for start in range(window):
        last = None
        pos = start
        for ins in md.disasm(data[start:], end_addr - window + start):
            pos = ins.address + ins.size - (end_addr - window)
            last = ins
            if pos >= window:
                break
        if last is not None and pos == window:
            votes[(last.address, last.size, f"{last.mnemonic} {last.op_str}".strip())] += 1
    if not votes:
        return None
    (start, size, text), _ = votes.most_common(1)[0]
    return start, size, proc.read_bytes(start, size), text


class InstructionTracer(AccessWatcher):
    """'Welche Adressen nutzt dieser Befehl?': Ausführungs-Breakpoint auf einen Befehl; bei jedem
    Durchlauf wird die Speicheradresse des Operanden aus den Registern berechnet.
    addresses: Counter {Adresse: Anzahl}."""

    def __init__(self, proc, ins_addr):
        super().__init__(proc, ins_addr, 1, "x")
        self.addresses = collections.Counter()
        self.mem = None   # (basis, index, scale, disp, Größe) des Speicheroperanden
        self.text = ""
        self.op_size = 4
        try:
            import capstone
        except ImportError:
            self.error = "capstone fehlt (pip install capstone)."
            return
        data = proc.read_bytes(ins_addr, 16)
        md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32 if proc.is32 else capstone.CS_MODE_64)
        md.detail = True
        ins = next(md.disasm(data or b"", ins_addr), None)
        if ins is None:
            self.error = "Befehl nicht lesbar."
            return
        self.text = f"{ins.mnemonic} {ins.op_str}"
        from capstone import x86
        for op in ins.operands:
            if op.type == x86.X86_OP_MEM:
                m = op.mem
                self.mem = (ins.reg_name(m.base) if m.base else None, ins.reg_name(m.index) if m.index else None,
                            m.scale, m.disp, ins.address + ins.size)
                self.op_size = op.size or 4
                break
        if self.mem is None:
            self.error = "Dieser Befehl greift nicht auf Speicher zu."

    def start(self):
        if self.error:
            return
        super().start()

    def _on_hit(self, ctx):
        self.hits[ctx["ip"]] += 1
        base, index, scale, disp, next_ip = self.mem
        if base in ("rip", "eip"):
            addr = next_ip + disp
        else:
            b = ctx.reg(base) if base else 0
            i = ctx.reg(index) if index else 0
            if b is None or i is None:
                return
            addr = b + i * scale + disp
        self.addresses[addr & (0xFFFFFFFF if self.proc.is32 else 0xFFFFFFFFFFFFFFFF)] += 1
