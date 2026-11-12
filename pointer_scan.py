"""Pointer-Scanner: findet stabile Zeigerketten (modul+offset -> ... -> Zielwert).

Ablauf: 1) Pointer-Map aufbauen (alle Werte im Speicher, die auf beschreibbaren Speicher zeigen)
        2) Rueckwaerts vom Ziel suchen: wer zeigt auf (Ziel - offset)? ... bis eine statische
           Adresse in einem Modul (z. B. spiel.exe) erreicht ist.
        3) Nach Spiel-Neustart: Wert neu suchen und Ketten per Rescan filtern.
"""
import numpy as np

from trainer_core import resolve_expr

CHUNK = 16 * 1024 * 1024


class PointerMap:
    def __init__(self, proc, progress=lambda f: None, cancel=None):
        self.proc = proc
        ps, dt = proc.ptr_size, proc.ptr_dtype
        regions = proc.regions(include_mapped=False)
        starts = np.array([b for b, _ in regions], dtype=np.uint64)
        ends = np.array([b + s for b, s in regions], dtype=np.uint64)
        lo_all, hi_all = (int(starts.min()), int(ends.max())) if len(regions) else (0, 0)
        total = sum(s for _, s in regions) or 1
        done = 0
        addr_parts, val_parts = [], []
        for base, size in regions:
            off = 0
            while off < size:
                if cancel is not None and cancel.is_set():
                    raise InterruptedError
                n = min(CHUNK, size - off)
                arr = proc.read_array(base + off, n, dt)
                off += n
                done += n
                progress(done / total * 0.9)
                if arr is None:
                    continue
                pos = np.flatnonzero((arr >= lo_all) & (arr < hi_all))
                if not pos.size:
                    continue
                v = arr[pos].astype(np.uint64)
                ri = np.searchsorted(starts, v, side="right") - 1
                ok = (ri >= 0) & (v < ends[np.maximum(ri, 0)])
                pos, v = pos[ok], v[ok]
                addr_parts.append(np.uint64(base + off - n) + pos.astype(np.uint64) * np.uint64(ps))
                val_parts.append(v)
        addrs = np.concatenate(addr_parts) if addr_parts else np.zeros(0, np.uint64)
        vals = np.concatenate(val_parts) if val_parts else np.zeros(0, np.uint64)
        order = np.argsort(vals, kind="stable")
        self.vals, self.addrs = vals[order], addrs[order]
        progress(1.0)
        mods = sorted(proc.modules)
        self.mod_starts = np.array([m[0] for m in mods], dtype=np.uint64)
        self.mod_ends = np.array([m[0] + m[1] for m in mods], dtype=np.uint64)

    def __len__(self):
        return int(self.vals.size)

    def is_static(self, a):
        i = np.searchsorted(self.mod_starts, a, side="right") - 1
        return (i >= 0) & (a < self.mod_ends[np.maximum(i, 0)])

    def scan(self, target, max_level=5, max_offset=0x1000, max_results=5000, max_nodes=300_000,
             progress=lambda f: None, cancel=None):
        """Liefert Liste von (basis_adresse, [offsets]) sortiert nach Kettenlaenge."""
        levels = [(np.array([target], np.uint64), None, None)]
        visited = np.array([target], np.uint64)
        found = []  # (level, addr, parent, off)
        for lvl in range(1, max_level + 1):
            if cancel is not None and cancel.is_set():
                break
            tgt = levels[-1][0]
            lo = np.searchsorted(self.vals, tgt - np.uint64(max_offset), side="left")
            hi = np.searchsorted(self.vals, tgt, side="right")
            cnt = (hi - lo).astype(np.int64)
            total = int(cnt.sum())
            if total == 0:
                break
            parent = np.repeat(np.arange(tgt.size), cnt)
            starts = np.repeat(lo - np.concatenate(([0], np.cumsum(cnt)[:-1])), cnt)
            pos = starts + np.arange(total)
            a = self.addrs[pos]
            off = tgt[parent] - self.vals[pos]
            st = self.is_static(a)
            for i in np.flatnonzero(st):
                found.append((lvl, int(a[i]), int(parent[i]), int(off[i])))
            keep = ~st
            a, parent, off = a[keep], parent[keep], off[keep]
            a, first = np.unique(a, return_index=True)
            parent, off = parent[first], off[first]
            fresh = ~np.isin(a, visited)
            a, parent, off = a[fresh], parent[fresh], off[fresh]
            if a.size > max_nodes:
                a, parent, off = a[:max_nodes], parent[:max_nodes], off[:max_nodes]
            visited = np.union1d(visited, a)
            levels.append((a, parent, off))
            progress(lvl / max_level)
            if len(found) >= max_results * 4:
                break

        chains = []
        for lvl, a, parent, off in found:
            offs = [off]
            p, L = parent, lvl - 1
            while L > 0:
                _, par, o = levels[L]
                offs.append(int(o[p]))
                p = int(par[p])
                L -= 1
            chains.append((a, offs))
        chains.sort(key=lambda c: (len(c[1]), sum(c[1])))
        return chains[:max_results]


def chain_to_expr(proc, base, offsets):
    s = proc.fmt_addr(base)
    for o in offsets:
        s = f"[{s}]+{o:X}"
    return s


def rescan(proc, exprs, new_target):
    """Behaelt nur Ketten, die (jetzt) auf new_target zeigen."""
    return [e for e in exprs if resolve_expr(proc, e) == new_target]


def find_refs(proc, target, max_offset=0x400, limit=500, progress=lambda f: None, cancel=None):
    """'Wer zeigt hierhin?': alle Zeiger im Speicher auf [target - max_offset, target].

    Liefert (fundort, offset, ist_statisch) – offset = target - Zeigerwert, also das Feld im
    Objekt, auf dessen Anfang gezeigt wird. Statische Fundorte (in einem Modul) zuerst.
    """
    ps, dt = proc.ptr_size, proc.ptr_dtype
    lo, hi = target - max_offset, target
    regions = proc.regions(include_mapped=False)
    total = sum(s for _, s in regions) or 1
    done, out = 0, []
    for base, size in regions:
        off = 0
        while off < size:
            if cancel is not None and cancel.is_set():
                return _sort_refs(out)
            n = min(CHUNK, size - off)
            arr = proc.read_array(base + off, n, dt)
            if arr is not None:
                for i in np.flatnonzero((arr >= lo) & (arr <= hi)):
                    a = base + off + int(i) * ps
                    out.append((a, target - int(arr[i]), proc.locate(a) is not None))
            off += n
            done += n
            progress(done / total)
            if len(out) >= limit * 4:
                return _sort_refs(out)[:limit]
    return _sort_refs(out)[:limit]


def _sort_refs(refs):
    return sorted(refs, key=lambda r: (not r[2], r[1], r[0]))
