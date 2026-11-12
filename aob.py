"""Byte-Muster-Suche (AOB) und Textsuche im Speicher eines Prozesses."""
import re

CHUNK = 16 * 1024 * 1024


def parse_pattern(text):
    """'8B 45 ?? 89' oder '8B45??89' -> Liste aus int|None."""
    t = text.replace(",", " ").strip()
    if " " not in t:
        t = " ".join(t[i:i + 2] for i in range(0, len(t), 2))
    out = []
    for tok in t.split():
        if tok in ("?", "??", "**"):
            out.append(None)
        else:
            v = int(tok, 16)
            if not 0 <= v <= 255:
                raise ValueError(f"Ungültiges Byte: {tok}")
            out.append(v)
    if not out or all(b is None for b in out):
        raise ValueError("Muster braucht mindestens ein festes Byte.")
    return out


def pattern_to_str(pat):
    return " ".join("??" if b is None else f"{b:02X}" for b in pat)


def compile_pattern(pat):
    return re.compile(b"".join(b"." if b is None else re.escape(bytes([b])) for b in pat), re.DOTALL)


def search(proc, regex, length, regions, limit=1000, cancel=None, progress=None):
    """Sucht 'regex' (bytes) in den Regionen [(base, size), ...]. Liefert Adressen."""
    hits = []
    total = sum(s for _, s in regions) or 1
    done = 0
    for base, size in regions:
        off = 0
        while off < size:
            if cancel is not None and cancel.is_set():
                return hits
            n = min(CHUNK + length - 1, size - off)
            arr = proc.read_array(base + off, n, "uint8")
            if arr is not None:
                for m in regex.finditer(arr.tobytes()):
                    if m.start() < CHUNK:  # Rest wird im naechsten (ueberlappenden) Block gefunden
                        hits.append(base + off + m.start())
                        if len(hits) >= limit:
                            return hits
            off += CHUNK
            done += min(CHUNK, n)
            if progress:
                progress(min(done / total, 1.0))
    return hits


def module_regions(proc, module):
    rng = proc.module_range(module)
    if not rng:
        return []
    mb, ms = rng
    return [(b, s) for b, s, _ in proc.all_regions() if mb <= b < mb + ms]


def scan_aob(proc, pattern, module=None, limit=1000, cancel=None, progress=None):
    pat = parse_pattern(pattern) if isinstance(pattern, str) else pattern
    regions = module_regions(proc, module) if module else [(b, s) for b, s, _ in proc.all_regions()]
    return search(proc, compile_pattern(pat), len(pat), regions, limit, cancel, progress)


def scan_text(proc, text, utf16=False, ignore_case=True, limit=1000, cancel=None, progress=None):
    data = text.encode("utf-16-le" if utf16 else "utf-8")
    rx = re.compile(re.escape(data), re.IGNORECASE if ignore_case else 0)
    regions = proc.regions(include_mapped=False)
    return search(proc, rx, len(data), regions, limit, cancel, progress)


def make_signature(proc, addr, module, min_len=8, max_len=64):
    """Kuerzestes eindeutiges Byte-Muster ab 'addr' innerhalb des Moduls (fuer update-feste Patches)."""
    data = proc.read_bytes(addr, max_len)
    if not data:
        return None
    regions = module_regions(proc, module)
    for n in range(min_len, max_len + 1, 4):
        pat = list(data[:n])
        hits = search(proc, compile_pattern(pat), n, regions, limit=2)
        if len(hits) == 1:
            return pattern_to_str(pat)
    return None
