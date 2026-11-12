"""Tests gegen einen echten Testprozess (tests/target.py). Nur Windows, 64-bit Python.

    python -m unittest discover -s tests
"""
import json
import os
import subprocess
import sys
import time
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

import debugger  # noqa: E402
import pointer_scan  # noqa: E402
import remote  # noqa: E402
from scanner_core import MULTI, MultiScanner, Process, Scanner  # noqa: E402


class Target:
    def __init__(self):
        self.p = subprocess.Popen([sys.executable, os.path.join(ROOT, "tests", "target.py")],
                                  stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True)
        self.addr = json.loads(self.p.stdout.readline())
        self.proc = Process(self.p.pid, "python.exe")

    def send(self, cmd):
        self.p.stdin.write(cmd + "\n")
        self.p.stdin.flush()
        self.p.stdout.readline()

    def close(self):
        try:
            self.send("quit")
        except OSError:
            pass
        self.p.wait(5)
        self.proc.close()


class ScanTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.t = Target()

    @classmethod
    def tearDownClass(cls):
        cls.t.close()

    def rows(self, sc):
        return {(a, s.label) for a, s, _ in sc.rows(100000)}

    def test_multi_finds_float_and_cents(self):
        a = self.t.addr
        sc = MultiScanner(self.t.proc)
        self.assertEqual(sc.type_name, MULTI)
        self.assertTrue(sc.scan(True, "Exakter Wert", "336,7", ""))
        self.assertIn((a["gold"], "Float"), self.rows(sc))
        self.assertTrue(sc.scan(True, "Exakter Wert", "12,34", ""))
        self.assertIn((a["cents"], "4 Bytes ×100"), self.rows(sc))
        self.assertIn("4 Bytes", sc.skipped)  # 12,34 ist keine Ganzzahl

    def test_multi_next_scan_and_undo(self):
        a = self.t.addr
        sc = MultiScanner(self.t.proc)
        sc.scan(True, "Exakter Wert", "1234", "")
        self.t.send("add cents 10")
        self.assertTrue(sc.scan(False, "Erhöht um", "10", ""))
        self.assertIn((a["cents"], "4 Bytes"), self.rows(sc))
        n = sc.count()
        self.t.send("add cents -10")
        sc.scan(False, "Erhöht", "", "")
        self.assertNotIn((a["cents"], "4 Bytes"), self.rows(sc))
        self.assertTrue(sc.undo())
        self.assertEqual(sc.count(), n)

    def test_approx(self):
        sc = Scanner(self.t.proc, "Float")
        self.assertTrue(sc.scan(True, "Ungefähr (gerundet)", "336", ""))
        self.assertIn(self.t.addr["gold"], [r[0] for r in sc.rows(100000)])

    def test_unknown_then_noise_filter(self):
        a = self.t.addr
        sc = Scanner(self.t.proc, "4 Bytes")
        self.assertTrue(sc.scan(True, "Unbekannter Startwert", "", ""))
        self.assertTrue(sc.filter_noise(1.0))
        self.t.send("add hp -5")
        sc.scan(False, "Verringert", "", "")
        addrs = [r[0] for r in sc.rows(100000)] if sc.listable() else []
        self.assertIn(a["hp"], addrs)
        self.assertNotIn(a["noise"], addrs)

    def test_refs(self):
        refs = pointer_scan.find_refs(self.t.proc, self.t.addr["gold"], 0x100)
        self.assertIn((self.t.addr["holder"], 4), [(r[0], r[1]) for r in refs])


class RemoteTest(unittest.TestCase):
    def test_batch_calls(self):
        t = Target()
        try:
            ex = remote.remote_exports(t.proc, "kernel32.dll")
            with remote.RemoteCaller(t.proc) as rc:
                s = rc.cstring("abcdef")
                self.assertEqual(rc.call(ex["GetCurrentProcessId"]), t.p.pid)
                self.assertEqual(rc.batch([(ex["lstrlenA"], s)] * 1000), [6] * 1000)
        finally:
            t.close()


class DebuggerDetachTest(unittest.TestCase):
    def test_target_survives_repeated_watch(self):
        """Regression: Beim Lösen anstehende Breakpoint-Treffer ließen das Spiel abstürzen."""
        t = Target()
        try:
            for _ in range(5):
                w = debugger.AccessWatcher(t.proc, t.addr["noise"], 4, "w")
                w.start()
                time.sleep(0.4)
                w.stop()
                w.join(5)
                self.assertTrue(w.hits)
                time.sleep(0.2)
                self.assertTrue(t.proc.alive(), "Testziel nach dem Lösen des Debuggers abgestürzt")
            t.send("add hp 1")
        finally:
            t.close()


class TracerTest(unittest.TestCase):
    def test_instruction_tracer(self):
        """Ausführungs-Breakpoint auf den ersten Speicherzugriff in GetTickCount64."""
        t = Target()
        try:
            ex = remote.remote_exports(t.proc, "kernel32.dll")  # ctypes ruft die kernel32-Version auf
            import capstone
            fn = ex["GetTickCount64"]
            md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
            md.detail = True
            ins = next(i for i in md.disasm(t.proc.read_bytes(fn, 64), fn)
                       if any(o.type == capstone.x86.X86_OP_MEM for o in i.operands))
            tr = debugger.InstructionTracer(t.proc, ins.address)
            self.assertIsNone(tr.error)
            tr.start()
            deadline = time.time() + 5
            while not tr.addresses and time.time() < deadline:
                time.sleep(0.1)
            tr.stop()
            tr.join(5)
            self.assertTrue(tr.addresses, "keine Adressen erfasst")
            # GetTickCount64 liest KUSER_SHARED_DATA (0x7FFE0000)
            self.assertTrue(any(0x7FFE0000 <= a < 0x7FFE1000 for a in tr.addresses), tr.addresses)
            t.send("add hp 1")  # Prozess läuft nach dem Lösen weiter
        finally:
            t.close()


if __name__ == "__main__":
    unittest.main()
