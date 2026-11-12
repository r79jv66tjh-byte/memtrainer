"""Unity-Hilfe: Klassen und Felder (z. B. Player.gold) eines Unity-Spiels per Name finden.

Unterstützt IL2CPP (GameAssembly.dll) und Mono (mono-2.0-bdwgc.dll / mono.dll), nur 64-bit.
Die Laufzeit des Spiels wird über ihre eigenen Export-Funktionen befragt (siehe remote.py);
danach werden Objekte einer Klasse im Speicher gesucht und ihre Felder live gelesen.

Mit Anti-Cheat-Toolkit (ACTk) verschlüsselte Werte (ObscuredInt/Float/…) werden erkannt
und – wenn möglich – entschlüsselt angezeigt.
"""
import re
import struct
import time

import numpy as np

from remote import RemoteCaller, RemoteError, remote_exports

IL2CPP_MODULES = ("GameAssembly.dll",)
MONO_MODULES = ("mono-2.0-bdwgc.dll", "mono-2.0-sgen.dll", "mono.dll", "mono-2.0.dll")

FIELD_STATIC = 0x10
FIELD_LITERAL = 0x40

# Il2CppTypeEnum == MonoTypeEnum
T_NAMES = {1: "void", 2: "bool", 3: "char", 4: "sbyte", 5: "byte", 6: "short", 7: "ushort", 8: "int",
           9: "uint", 10: "long", 11: "ulong", 12: "float", 13: "double", 14: "string", 0xF: "ptr",
           0x11: "struct", 0x12: "class", 0x13: "T", 0x14: "array", 0x15: "generic", 0x18: "nint",
           0x19: "nuint", 0x1C: "object", 0x1D: "array[]", 0x1E: "T"}
T_FMT = {2: "<?", 3: "<H", 4: "<b", 5: "<B", 6: "<h", 7: "<H", 8: "<i", 9: "<I", 10: "<q", 11: "<Q",
         12: "<f", 13: "<d", 0x18: "<q", 0x19: "<Q"}
T_MEMTYPE = {2: "Byte", 4: "Byte", 5: "Byte", 3: "2 Bytes", 6: "2 Bytes", 7: "2 Bytes", 8: "4 Bytes",
             9: "4 Bytes", 10: "8 Bytes", 11: "8 Bytes", 0x18: "8 Bytes", 0x19: "8 Bytes",
             12: "Float", 13: "Double"}
NUMERIC = set(T_FMT)

SKIP_IMAGES = ("mscorlib", "System", "Mono.", "UnityEngine", "Unity.", "netstandard", "Newtonsoft",
               "Sirenix", "DOTween", "Rewired", "FMOD", "Steamworks", "Facepunch", "I18N", "TextMeshPro",
               "Purchasing", "Cinemachine", "spine-")

# Wörter, nach denen der Such-Assistent zuerst schaut
MONEY_WORDS = ("gold", "money", "coin", "cash", "currency", "gem", "credit", "soul", "essence",
               "shard", "token", "point", "xp", "exp", "scrap", "resource")


class UnityError(RuntimeError):
    pass


def detect(proc):
    """'il2cpp', 'mono' oder None."""
    names = {m[2].lower() for m in proc.modules}
    if any(m.lower() in names for m in IL2CPP_MODULES):
        return "il2cpp"
    if any(m.lower() in names for m in MONO_MODULES):
        return "mono"
    return None


class Field:
    __slots__ = ("ptr", "name", "offset", "tenum", "flags", "type_ptr", "cls", "type_name")

    def __init__(self, ptr, name, offset, tenum, flags, type_ptr, cls):
        self.ptr, self.name, self.offset, self.tenum = ptr, name, offset, tenum
        self.flags, self.type_ptr, self.cls = flags, type_ptr, cls
        self.type_name = None

    @property
    def static(self):
        return bool(self.flags & FIELD_STATIC)

    @property
    def mem_type(self):
        return T_MEMTYPE.get(self.tenum, "8 Bytes")

    def short_type(self):
        return self.type_name or T_NAMES.get(self.tenum, f"#{self.tenum:X}")


class Klass:
    __slots__ = ("ptr", "name", "ns", "image", "parent", "fields", "header")

    def __init__(self, ptr, name, ns, image, parent):
        self.ptr, self.name, self.ns, self.image, self.parent = ptr, name, ns, image, parent
        self.fields = []
        self.header = None  # Wert am Objektanfang (il2cpp: Klasse, mono: VTable)

    @property
    def full(self):
        return f"{self.ns}.{self.name}" if self.ns else self.name


class _Strings:
    """Liest viele C-Strings aus dem Zielprozess, seitenweise zwischengespeichert."""

    def __init__(self, proc):
        self.proc, self.pages = proc, {}

    def get(self, addr, maxlen=256):
        if not addr:
            return ""
        out = b""
        a = addr
        while len(out) < maxlen:
            page = a & ~0xFFF
            data = self.pages.get(page)
            if data is None:
                data = self.proc.read_bytes(page, 0x1000) or b""
                self.pages[page] = data
            chunk = data[a - page:]
            if not chunk:
                break
            z = chunk.find(b"\0")
            if z >= 0:
                out += chunk[:z]
                break
            out += chunk
            a = page + 0x1000
        return out.decode("utf-8", "replace")


class UnityRuntime:
    def __init__(self, proc):
        self.proc = proc
        self.kind = detect(proc)
        if not self.kind:
            raise UnityError("Kein Unity-Spiel erkannt (weder GameAssembly.dll noch mono*.dll geladen).")
        if proc.is32:
            raise UnityError("Unity-Hilfe gibt es nur für 64-bit Spiele.")
        mods = IL2CPP_MODULES if self.kind == "il2cpp" else MONO_MODULES
        self.module = next(m[2] for m in proc.modules if m[2].lower() in {x.lower() for x in mods})
        self.ex = remote_exports(proc, self.module)
        self.pre = "il2cpp_" if self.kind == "il2cpp" else "mono_"
        self.classes = []
        self.by_ptr = {}
        self.domain = 0
        self.images = []
        self.loaded_all = False

    # -- Hilfen ---------------------------------------------------------------
    def fn(self, name, required=True):
        a = self.ex.get(self.pre + name)
        if not a and required:
            raise UnityError(f"Funktion {self.pre}{name} fehlt im Spiel.")
        return a

    def _caller(self):
        rc = RemoteCaller(self.proc)
        if self.domain:
            rc.attach = (self.fn("thread_attach"), self.domain, self.fn("thread_detach"))
        return rc

    # -- Laden ------------------------------------------------------------------
    def load(self, all_assemblies=False, progress=lambda f, t="": None):
        """Klassen und Felder einlesen (einige Sekunden)."""
        t0 = time.time()
        rc = RemoteCaller(self.proc)
        strs = _Strings(self.proc)
        try:
            progress(0.02, "Laufzeit wird abgefragt…")
            if self.kind == "il2cpp":
                self.domain = rc.call(self.fn("domain_get"))
                rc.attach = (self.fn("thread_attach"), self.domain, self.fn("thread_detach"))
                slot = rc.alloc(16)
                arr = rc.call(self.fn("domain_get_assemblies"), self.domain, slot)
                n = struct.unpack("<Q", self.proc.read_bytes(slot, 8))[0]
                rc.free(slot)
                asms = list(struct.unpack(f"<{n}Q", self.proc.read_bytes(arr, n * 8) or b"")) if n else []
            else:
                self.domain = rc.call(self.fn("get_root_domain"))
                rc.attach = (self.fn("thread_attach"), self.domain, self.fn("thread_detach"))
                buf = rc.alloc(8 + 8 * 4096)
                rc.call(self.fn("assembly_foreach"), rc.cb, buf)
                n = struct.unpack("<Q", self.proc.read_bytes(buf, 8))[0]
                asms = list(struct.unpack(f"<{n}Q", self.proc.read_bytes(buf + 8, n * 8) or b"")) if n else []
                rc.free(buf)
            if not asms:
                raise UnityError("Keine Assemblies gefunden (Spiel noch im Ladebildschirm?).")
            imgs = rc.batch([(self.fn("assembly_get_image"), a) for a in asms])
            names = rc.batch([(self.fn("image_get_name"), i) for i in imgs])
            images = [(img, strs.get(nm)) for img, nm in zip(imgs, names) if img]
            self.images = [nm for _, nm in images]
            if not all_assemblies:
                images = [(i, nm) for i, nm in images if not nm.startswith(SKIP_IMAGES)]
            self.loaded_all = all_assemblies
            progress(0.08, f"{len(images)} Assemblies…")

            # Klassen
            if self.kind == "il2cpp":
                counts = rc.batch([(self.fn("image_get_class_count"), i) for i, _ in images])
                calls = [(self.fn("image_get_class"), img, k) for (img, _), c in zip(images, counts)
                         for k in range(c & 0xFFFFFFFF)]
                owners = [nm for (_, nm), c in zip(images, counts) for _ in range(c & 0xFFFFFFFF)]
            else:
                counts = rc.batch([(self.fn("image_get_table_rows"), i, 2) for i, _ in images])
                calls = [(self.fn("class_get"), img, 0x02000000 | (k + 1)) for (img, _), c in zip(images, counts)
                         for k in range(c & 0xFFFFFFFF)]
                owners = [nm for (_, nm), c in zip(images, counts) for _ in range(c & 0xFFFFFFFF)]
            kptrs = rc.batch(calls)
            pairs = [(k, o) for k, o in zip(kptrs, owners) if k]
            progress(0.25, f"{len(pairs)} Klassen…")
            ks = [k for k, _ in pairs]
            info = rc.batch([c for k in ks for c in ((self.fn("class_get_name"), k),
                                                     (self.fn("class_get_namespace"), k),
                                                     (self.fn("class_get_parent"), k),
                                                     (self.fn("class_num_fields"), k))])
            iters = rc.alloc(8 * max(len(ks), 1))
            first = rc.batch([(self.fn("class_get_fields"), k, iters + 8 * i) for i, k in enumerate(ks)])
            stride = self._field_stride(rc, ks, info, iters)
            rc.free(iters)
            progress(0.45, "Felder…")
            self.classes, self.by_ptr = [], {}
            fptrs, fowner = [], []
            for i, (k, img) in enumerate(pairs):
                c = Klass(k, strs.get(info[4 * i]), strs.get(info[4 * i + 1]), img, info[4 * i + 2])
                self.classes.append(c)
                self.by_ptr[k] = c
                nf = info[4 * i + 3] & 0xFFFFFFFF
                if first[i] and 0 < nf < 4096:
                    for j in range(nf):
                        fptrs.append(first[i] + j * stride)
                        fowner.append(c)
            fcalls = [c for f in fptrs for c in ((self.fn("field_get_name"), f), (self.fn("field_get_offset"), f),
                                                 (self.fn("field_get_type"), f), (self.fn("field_get_flags"), f))]
            fres = []
            step = 40000
            for s in range(0, len(fcalls), step):
                fres.extend(rc.batch(fcalls[s:s + step]))
                progress(0.45 + 0.4 * min(1, (s + step) / max(len(fcalls), 1)), "Felder…")
            types = [fres[4 * i + 2] for i in range(len(fptrs))]
            tenums = rc.batch([(self.fn("type_get_type"), t) for t in types])
            for i, fp in enumerate(fptrs):
                off = fres[4 * i + 1] & 0xFFFFFFFF
                off = off - (1 << 32) if off & 0x80000000 else off
                f = Field(fp, strs.get(fres[4 * i]), off, tenums[i] & 0xFF, fres[4 * i + 3] & 0xFFFF,
                          types[i], fowner[i])
                if not f.flags & FIELD_LITERAL:
                    fowner[i].fields.append(f)
            progress(1.0, f"{len(self.classes)} Klassen, {len(fptrs)} Felder in {time.time() - t0:.1f} s")
        finally:
            rc.close()
        return self

    def _field_stride(self, rc, ks, info, iters):
        """Abstand zweier FieldInfo-Strukturen (normalerweise 0x20) über zwei Iterator-Aufrufe bestimmen."""
        for i, k in enumerate(ks):
            if (info[4 * i + 3] & 0xFFFFFFFF) >= 2:
                slot = rc.alloc(8)
                a = rc.call(self.fn("class_get_fields"), k, slot)
                b = rc.call(self.fn("class_get_fields"), k, slot)
                rc.free(slot)
                if a and b and 0 < b - a <= 0x80:
                    return b - a
        return 0x20

    # -- Suche --------------------------------------------------------------------
    def search(self, text, numeric_only=False, include_ui=False, limit=2000):
        """Felder passend zum Suchtext, beste zuerst.

        Leerer Text = typische Geld-/Währungswörter. Mehrere Wörter: alle müssen in Klasse+Feld vorkommen.
        "Klasse.Feld" sucht gezielt. Feldnamen werden in Wörter zerlegt (camelCase, _), damit z. B. "exp"
        nicht "explosion" trifft.
        """
        text = text.strip()
        words = [w.lower() for w in text.replace(".", " ").split()] if text else []
        scored = []
        for c in self.classes:
            if "<" in c.name or (not include_ui and _is_ui(c)):
                continue
            ctoks = set(name_tokens(c.name))
            for f in c.fields:
                if numeric_only and f.tenum not in NUMERIC and f.tenum != 0x11:
                    continue
                ftoks = name_tokens(f.name)
                if words:
                    s = 0
                    for w in words:
                        if w in ftoks:
                            s += 3
                        elif any(t.startswith(w) for t in ftoks) and len(w) > 2:
                            s += 2
                        elif w in ctoks or (len(w) > 3 and w in c.full.lower()):
                            s += 1
                        elif len(w) > 3 and w in f.name.lower():
                            s += 1
                        else:
                            s = 0
                            break
                else:
                    s = 3 if any(t in MONEY_WORDS or t.rstrip("s") in MONEY_WORDS for t in ftoks) else 0
                if s:
                    if f.tenum in NUMERIC:
                        s += 1
                    if not f.static and any(k in c.name.lower() for k in ("player", "save", "data", "profile", "wallet", "inventory")):
                        s += 1
                    scored.append((-s, c.full, f.offset, f))
        scored.sort(key=lambda x: x[:3])
        return [f for *_, f in scored[:limit]]

    def find_class(self, name):
        name = name.lower()
        return [c for c in self.classes if c.name.lower() == name or c.full.lower() == name]

    def describe_types(self, fields):
        """Typnamen (z. B. ObscuredInt) für Struktur-/Klassenfelder nachladen."""
        todo = [f for f in fields if f.type_name is None and f.tenum not in NUMERIC]
        if not todo:
            return
        with self._caller() as rc:
            res = rc.batch([(self.fn("type_get_name"), f.type_ptr) for f in todo])
        strs = _Strings(self.proc)
        for f, p in zip(todo, res):
            f.type_name = strs.get(p) or T_NAMES.get(f.tenum, "?")

    def struct_fields(self, field):
        """Unterfelder eines Struct-Feldes (z. B. ObscuredInt.hiddenValue). Offsets relativ zum Struct."""
        with self._caller() as rc:
            k = rc.call(self.fn("class_from_type" if self.kind == "il2cpp" else "class_from_mono_type"),
                        field.type_ptr)
        c = self.by_ptr.get(k)
        if c is None and k:
            c = self._load_single(k)
        if c is None:
            return []
        return [f for f in c.fields if not f.static]

    def _load_single(self, k):
        with self._caller() as rc:
            strs = _Strings(self.proc)
            name, ns, parent, nf = rc.batch([(self.fn("class_get_name"), k), (self.fn("class_get_namespace"), k),
                                             (self.fn("class_get_parent"), k), (self.fn("class_num_fields"), k)])
            c = Klass(k, strs.get(name), strs.get(ns), "?", parent)
            slot = rc.alloc(8)
            fps = []
            for _ in range(min(nf & 0xFFFFFFFF, 256)):
                f = rc.call(self.fn("class_get_fields"), k, slot)
                if not f:
                    break
                fps.append(f)
            rc.free(slot)
            res = rc.batch([x for f in fps for x in ((self.fn("field_get_name"), f), (self.fn("field_get_offset"), f),
                                                     (self.fn("field_get_type"), f), (self.fn("field_get_flags"), f))])
            types = [res[4 * i + 2] for i in range(len(fps))]
            tenums = rc.batch([(self.fn("type_get_type"), t) for t in types]) if types else []
            for i, fp in enumerate(fps):
                off = res[4 * i + 1] & 0xFFFFFFFF
                c.fields.append(Field(fp, strs.get(res[4 * i]), off - (1 << 32) if off & 0x80000000 else off,
                                      tenums[i] & 0xFF, res[4 * i + 3] & 0xFFFF, types[i], c))
        self.by_ptr[k] = c
        return c

    # -- Objekte / Adressen ---------------------------------------------------------
    def subclasses(self, cls):
        """Die Klasse selbst und alle (geladenen) abgeleiteten Klassen."""
        out = []
        for c in self.classes:
            p, depth = c, 0
            while p is not None and depth < 32:
                if p is cls:
                    out.append(c)
                    break
                p = self.by_ptr.get(p.parent)
                depth += 1
        return out or [cls]

    def _headers(self, classes):
        if self.kind == "il2cpp":
            return {c.ptr: c for c in classes}
        todo = [c for c in classes if c.header is None]
        if todo:
            with self._caller() as rc:
                vts = rc.batch([(self.fn("class_vtable"), self.domain, c.ptr) for c in todo])
            for c, v in zip(todo, vts):
                c.header = v
        return {c.header: c for c in classes if c.header}

    def instances(self, cls, limit=200, progress=lambda f: None, cancel=None):
        """Adressen aller (plausiblen) Objekte der Klasse inkl. abgeleiteter, beste zuerst."""
        heads = self._headers(self.subclasses(cls))
        if not heads:
            return []
        keys = np.array(sorted(heads), dtype=np.uint64)
        regions = self.proc.regions(False)
        total = sum(s for _, s in regions) or 1
        done, cands = 0, []
        chunk = 16 << 20
        for base, size in regions:
            off = 0
            while off < size:
                if cancel is not None and cancel.is_set():
                    break
                n = min(chunk, size - off)
                arr = self.proc.read_array(base + off, n, np.uint64)
                if arr is not None:
                    hit = np.flatnonzero(np.isin(arr, keys))
                    start = base + off
                    cands.extend(start + int(h) * 8 for h in hit if (start + int(h) * 8) % 16 == 0)
                off += n
                done += n
                progress(done / total)
                if len(cands) > 200000:
                    break
        known = set(self.by_ptr) | {c.header for c in self.classes if c.header}
        scored = []
        for a in cands:
            head = self.proc.read_ptr(a)
            s = self._plausible(a, heads.get(head, cls), known)
            if s >= 0:
                scored.append((-s, a))
        scored.sort()
        return [a for _, a in scored[:limit]]

    def _plausible(self, obj, cls, known):
        """Punkte für ein mögliches Objekt; < 0 = sicher kein echtes Objekt."""
        data = self.proc.read_bytes(obj, 0x10)
        if not data:
            return -1
        monitor = struct.unpack_from("<Q", data, 8)[0]
        if monitor and not 0x10000 < monitor < 0x7FFFFFFFFFFF:
            return -1
        score = 0
        fields = []
        c, depth = cls, 0
        while c is not None and depth < 16:
            fields.extend(f for f in c.fields if not f.static)
            c = self.by_ptr.get(c.parent)
            depth += 1
        # Sichere Referenztypen (string, Klasse, Array, object); generische Felder können Structs sein
        refs = [f for f in fields if f.tenum in (0x12, 0x14, 0x15, 0x1C, 0x1D, 14) and f.offset % 8 == 0][:16]
        for f in refs:
            strict = f.tenum != 0x15
            p = self.proc.read_ptr(obj + f.offset)
            if p is None:
                return -1
            if not p:
                continue
            if not 0x10000 < p < 0x7FFFFFFFFFFF or p % 8:
                if strict:
                    return -1
                continue
            h = self.proc.read_ptr(p)
            if h in known:
                score += 2
            elif h and 0x10000 < h < 0x7FFFFFFFFFFF and h % 8 == 0 and self.proc.read_ptr(h) is not None:
                score += 1
            elif strict:
                return -1
        bools = [f for f in fields if f.tenum == 2][:24]
        if bools:
            vals = [self.proc.read_bytes(obj + f.offset, 1) for f in bools]
            bad = sum(1 for v in vals if v is None or v[0] > 1)
            if bad > len(bools) // 4:
                return -1
            score += 2 if not bad else 0
        if not monitor:
            score += 1
        for f in fields:
            if f.tenum in (12, 13):
                n = 4 if f.tenum == 12 else 8
                v = struct.unpack(T_FMT[f.tenum], self.proc.read_bytes(obj + f.offset, n) or b"\0" * n)[0]
                if v != v or abs(v) > 1e15:
                    score -= 1
        return score

    def static_base(self, cls):
        """Adresse der statischen Felder einer Klasse (0, wenn die Klasse noch nicht initialisiert ist)."""
        with self._caller() as rc:
            if self.kind == "il2cpp":
                return rc.call(self.fn("class_get_static_field_data"), cls.ptr)
            vt = rc.call(self.fn("class_vtable"), self.domain, cls.ptr)
            return rc.call(self.fn("vtable_get_static_field_data"), vt) if vt else 0

    def field_addr(self, field, obj=None, static_base=0):
        if field.static:
            return static_base + field.offset if static_base else None
        return obj + field.offset if obj else None

    # -- Werte -----------------------------------------------------------------------
    def read_field(self, addr, field, sub=None):
        """Wert als Text. Bei ACTk-Obscured-Typen wird entschlüsselt (sub = Unterfelder)."""
        if addr is None:
            return "–"
        if field.tenum in T_FMT:
            fmt = T_FMT[field.tenum]
            data = self.proc.read_bytes(addr, struct.calcsize(fmt))
            if data is None:
                return "??"
            v = struct.unpack(fmt, data)[0]
            return f"{v:.4f}".rstrip("0").rstrip(".") if isinstance(v, float) else str(v)
        if field.tenum == 0x11 and sub:
            dec = decode_obscured(self.proc, addr, field, sub)
            if dec is not None:
                return dec
        if field.tenum == 14:
            p = self.proc.read_ptr(addr)
            return repr(read_string(self.proc, p)) if p else "null"
        p = self.proc.read_ptr(addr)
        return "null" if not p else f"→ {p:X}"


_UI_HINTS = ("ui", "page", "popup", "button", "text", "vfx", "fx", "tween", "anim", "icon", "panel",
             "widget", "view", "menu", "tooltip", "label", "sfx", "shader", "renderer")


def _is_ui(cls):
    toks = set(name_tokens(cls.name))
    return bool(toks & set(_UI_HINTS)) or ".UI" in cls.full or cls.ns.endswith(".UI")


def name_tokens(name):
    """'<RunCoins>k__BackingField' -> ['run', 'coins']; '_maxHP' -> ['max', 'hp']."""
    name = name.replace("k__BackingField", "").strip("<>_")
    name = re.sub(r"[<>]", "", name)
    parts = re.findall(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|\d+", name)
    return [p.lower() for p in parts]


def read_string(proc, p, maxlen=64):
    """System.String (il2cpp und mono: Länge bei +0x10, UTF-16 ab +0x14)."""
    n = proc.read_value(p + 0x10, np.int32)
    if n is None or not 0 <= n < 100000:
        return "?"
    data = proc.read_bytes(p + 0x14, min(n, maxlen) * 2) or b""
    return data.decode("utf-16-le", "replace")


def decode_obscured(proc, addr, field, sub):
    """Anti-Cheat-Toolkit: ObscuredInt/Float/Long/Double… = hiddenValue XOR currentCryptoKey."""
    tn = (field.type_name or "").split(".")[-1]
    if not tn.startswith("Obscured"):
        return None
    by = {f.name: f for f in sub}
    hv, key = by.get("hiddenValue"), by.get("currentCryptoKey")
    if not hv or not key or hv.tenum not in T_FMT or key.tenum not in T_FMT:
        return None
    base = addr - 0x10  # Struct-Offsets enthalten den Objekt-Header
    fmt = "<q" if struct.calcsize(T_FMT[hv.tenum]) == 8 else "<i"
    raw_h = proc.read_bytes(base + hv.offset, struct.calcsize(fmt))
    raw_k = proc.read_bytes(base + key.offset, struct.calcsize(T_FMT[key.tenum]))
    if raw_h is None or raw_k is None:
        return "??"
    h = struct.unpack(fmt, raw_h)[0]
    k = struct.unpack(T_FMT[key.tenum], raw_k)[0]
    v = h ^ k
    if tn in ("ObscuredFloat",):
        v = struct.unpack("<f", struct.pack("<i", v & 0xFFFFFFFF if v >= 0 else v))[0]
        return f"{v:.4f}".rstrip("0").rstrip(".") + " 🔓"
    if tn in ("ObscuredDouble",):
        v = struct.unpack("<d", struct.pack("<q", v))[0]
        return f"{v:.4f}".rstrip("0").rstrip(".") + " 🔓"
    return f"{v} 🔓"


__all__ = ["UnityRuntime", "UnityError", "RemoteError", "detect", "MONEY_WORDS"]
