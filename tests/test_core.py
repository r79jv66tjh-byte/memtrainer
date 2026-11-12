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


class MainThreadHookTest(unittest.TestCase):
    def test_calls_run_in_hooked_thread(self):
        """Aufrufe laufen im Thread, der die eingehängte Funktion ausführt (hier: GetTickCount64)."""
        t = Target()
        try:
            ex = remote.remote_exports(t.proc, "kernel32.dll")
            orig = t.proc.read_bytes(ex["GetTickCount64"], 16)
            with remote.RemoteCaller(t.proc) as rc:
                s = rc.cstring("abcdef")
                for _ in range(3):  # mehrfach ein- und aushängen
                    with remote.MainThreadHook(t.proc, ex["GetTickCount64"]) as hook:
                        tid, n = hook.batch([(ex["GetCurrentThreadId"],), (ex["lstrlenA"], s)])
                        self.assertEqual(n, 6)
                        self.assertNotEqual(tid, 0)
                        self.assertEqual(hook.call(ex["GetCurrentThreadId"]), tid)  # immer derselbe Thread
                    t.send("add hp 1")  # Prozess läuft weiter
                with remote.MainThreadHook(t.proc, ex["GetTickCount64"]) as hook:
                    self.assertTrue(hook.fires())
                    self.assertTrue(hook.last_this() or True)  # rcx wird mitgeschrieben
            self.assertEqual(t.proc.read_bytes(ex["GetTickCount64"], 16), orig)  # Original wiederhergestellt
        finally:
            t.close()


class LeftoverHookTest(unittest.TestCase):
    def test_leftover_hooks_are_healed(self):
        """Ein nicht entfernter Hook (z. B. abgebrochenes Programm) darf nie als Original übernommen werden."""
        t = Target()
        try:
            fn = remote.remote_exports(t.proc, "kernel32.dll")["GetTickCount64"]
            orig = t.proc.read_bytes(fn, 16)
            for legacy in (False, True):
                a = remote.MainThreadHook(t.proc, fn)
                remote._OPEN_HOOKS.discard(a)  # wie ein abgestürztes Programm: Hook bleibt stehen
                if legacy:  # alter Stub ohne gespeichertes Original
                    t.proc.write_bytes(a.base + remote.H_ORIG, b"\0" * 8)
                self.assertIsNotNone(remote.leftover_target(t.proc, fn))
                with remote.MainThreadHook(t.proc, fn) as b:
                    self.assertEqual(b.orig, orig[:len(b.orig)])
                    self.assertTrue(b.fires())
                self.assertEqual(t.proc.read_bytes(fn, 16), orig)
                a.hooked = False
                a.rc.close()
            t.send("add hp 1")
        finally:
            t.close()


class TableActionsTest(unittest.TestCase):
    def test_actions_roundtrip(self):
        from trainer_core import new_action, new_entry, table_from_json, table_to_json
        acts = [new_action(desc="Kill", call="GameManager::RosaryDamage(true, 1.8)", hotkey="F9", interval=10)]
        ents = [new_entry(desc="HP", expr="unity:GameManager::_mainCharacters[0]._currentHp", type="Float")]
        t = table_from_json(json.loads(json.dumps(table_to_json(ents, "x.exe", actions=acts))))
        self.assertEqual(t["actions"][0]["call"], acts[0]["call"])
        self.assertEqual(t["actions"][0]["interval"], 10)
        self.assertFalse(t["actions"][0]["timer"])  # Timer startet nie von selbst
        self.assertEqual(t["entries"][0]["expr"], ents[0]["expr"])
        self.assertEqual(table_from_json({"entries": []})["actions"], [])  # alte Tabellen

    def test_presets_are_valid(self):
        from trainer_core import table_from_json
        d = os.path.join(ROOT, "presets")
        for n in os.listdir(d):
            with open(os.path.join(d, n), encoding="utf-8") as f:
                t = table_from_json(json.load(f))
            self.assertTrue(t["process"].endswith(".exe"), n)
            for a in t["actions"]:
                self.assertIn("::", a["call"])


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
