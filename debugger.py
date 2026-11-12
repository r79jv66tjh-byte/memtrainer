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
CTX64_SIZE, CTX64_FLAGS = 1232, 0x100011  # CONTROL | DEBUG_REGISTERS
CTX64 = {"flags": 48, "dr0": 72, "dr6": 104, "dr7": 112, "ip": 248}
# WOW64_CONTEXT (32-bit Spiele)
CTX32_SIZE, CTX32_FLAGS = 716, 0x10011
CTX32 = {"flags": 0, "dr0": 4, "dr6": 20, "dr7": 24, "ip": 184}


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

    def _fmt(self):
        return "<I" if self.is32 else "<Q"

    def __getitem__(self, k):
        return struct.unpack_from(self._fmt(), self.buf, self.off[k])[0]

    def __setitem__(self, k, v):
        struct.pack_into(self._fmt(), self.buf, self.off[k], v)


def _dr7(size, access):
    """access: 'w' = schreiben, 'rw' = lesen/schreiben."""
    rw = 0b01 if access == "w" else 0b11
    ln = {1: 0b00, 2: 0b01, 4: 0b11, 8: 0b10}[size]
    return 1 | (rw << 16) | (ln << 18)


class AccessWatcher:
    """Startet einen Debug-Thread. hits: Counter {Instruktions-Endadresse: Anzahl}."""

    def __init__(self, proc, addr, size=4, access="w"):
        if size not in (1, 2, 4, 8) or addr % size:
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
        seen_bp = set()
        exited = False
        try:
            while not self._stop.is_set():
                if not k32.WaitForDebugEvent(ctypes.byref(ev), 100):
                    continue
                code, status = ev.dwDebugEventCode, DBG_CONTINUE
                if code == CREATE_PROCESS_DEBUG_EVENT:
                    info = ev.u.CreateProcessInfo
                    if info.hFile:
                        k32.CloseHandle(info.hFile)
                    self._threads[ev.dwThreadId] = info.hThread
                    self._apply(info.hThread, True)
                elif code == CREATE_THREAD_DEBUG_EVENT:
                    self._threads[ev.dwThreadId] = ev.u.CreateThread.hThread
                    self._apply(ev.u.CreateThread.hThread, True)
                elif code == EXIT_THREAD_DEBUG_EVENT:
                    self._threads.pop(ev.dwThreadId, None)
                elif code == LOAD_DLL_DEBUG_EVENT:
                    if ev.u.LoadDll.hFile:
                        k32.CloseHandle(ev.u.LoadDll.hFile)
                elif code == EXIT_PROCESS_DEBUG_EVENT:
                    exited = True
                    k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, DBG_CONTINUE)
                    break
                elif code == EXCEPTION_DEBUG_EVENT:
                    exc = ev.u.Exception.ExceptionRecord.ExceptionCode
                    if exc in (EXC_SINGLE_STEP, WX86_SINGLE_STEP):
                        th = self._threads.get(ev.dwThreadId)
                        ctx = _Ctx(self.proc.is32)
                        if th and ctx.get(th) and ctx["dr6"] & 1:
                            self.hits[ctx["ip"]] += 1
                            ctx["dr6"] = 0
                            ctx.set(th)
                        else:
                            status = DBG_EXCEPTION_NOT_HANDLED
                    elif exc in (EXC_BREAKPOINT, WX86_BREAKPOINT) and exc not in seen_bp:
                        seen_bp.add(exc)  # Anhalte-Breakpoint beim Anhaengen (WoW64: zwei)
                    else:
                        status = DBG_EXCEPTION_NOT_HANDLED
                k32.ContinueDebugEvent(ev.dwProcessId, ev.dwThreadId, status)
        finally:
            if not exited:
                self._cleanup()
                k32.DebugActiveProcessStop(pid)
            self.running = False

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
