"""Value scanning (first/next scan narrowing) and array-of-bytes signature scanning."""

from __future__ import annotations

import re
import struct
from array import array
from dataclasses import dataclass, field

from .process import VALUE_FORMATS, GameProcess

CHUNK = 32 * 1024 * 1024       # max bytes read per ReadProcessMemory call
BATCH_SPAN = 64 * 1024          # next-scan: candidates within this span share one read

COMPARE_MODES = ("eq", "ne", "gt", "lt", "changed", "unchanged", "increased", "decreased")


# ---------------------------------------------------------------------------
# Pure helpers (unit-tested without a live process)
# ---------------------------------------------------------------------------

def pack_value(vtype: str, value) -> bytes:
    fmt = VALUE_FORMATS[vtype]
    if vtype.startswith("f"):
        value = float(value)
    else:
        value = int(value, 0) if isinstance(value, str) else int(value)
    return struct.pack(fmt, value)


def find_value_offsets(data: bytes, needle: bytes, align: int = 1) -> list[int]:
    """Offsets of every occurrence of `needle` in `data`, optionally aligned."""
    out = []
    find = data.find
    i = find(needle)
    while i != -1:
        if i % align == 0:
            out.append(i)
            i = find(needle, i + align)
        else:
            i = find(needle, i + 1)
    return out


def compile_aob(pattern: str) -> re.Pattern[bytes]:
    """Compile '48 8B 05 ?? ?? ?? ??' style patterns ('?' or '??' are wildcards)."""
    parts = []
    for tok in pattern.split():
        if tok in ("?", "??"):
            parts.append(b".")
        else:
            parts.append(re.escape(bytes([int(tok, 16)])))
    if not parts:
        raise ValueError("empty AOB pattern")
    return re.compile(b"".join(parts), re.DOTALL)


def aob_offsets(data: bytes, pattern: str) -> list[int]:
    rx = compile_aob(pattern)
    out, pos = [], 0
    while (m := rx.search(data, pos)) is not None:
        out.append(m.start())
        pos = m.start() + 1
    return out


def compare(mode: str, prev, cur, arg=None) -> bool:
    if mode == "eq":
        return cur == arg
    if mode == "ne":
        return cur != arg
    if mode == "gt":
        return cur > arg
    if mode == "lt":
        return cur < arg
    if mode == "changed":
        return cur != prev
    if mode == "unchanged":
        return cur == prev
    if mode == "increased":
        return cur > prev
    if mode == "decreased":
        return cur < prev
    raise ValueError(f"unknown compare mode {mode!r}; expected one of {COMPARE_MODES}")


# ---------------------------------------------------------------------------
# Live scanning
# ---------------------------------------------------------------------------

@dataclass
class ScanSession:
    """Candidate addresses narrowed down across successive scans."""

    vtype: str
    addresses: array = field(default_factory=lambda: array("Q"))
    values: list = field(default_factory=list)

    def __len__(self) -> int:
        return len(self.addresses)


class Scanner:
    def __init__(self, proc: GameProcess):
        self.proc = proc

    def _read_chunks(self, writable_only: bool, overlap: int):
        for region in self.proc.regions(writable_only=writable_only):
            off = 0
            while off < region.size:
                size = min(CHUNK, region.size - off)
                base = region.base + off
                try:
                    data = self.proc.read(base, min(size + overlap, region.size - off))
                except OSError:
                    break
                yield base, data
                off += size

    def first_scan(self, vtype: str, value, *, writable_only: bool = True,
                   aligned: bool = True) -> ScanSession:
        needle = pack_value(vtype, value)
        size = len(needle)
        align = size if aligned else 1
        session = ScanSession(vtype)
        decoded = struct.unpack(VALUE_FORMATS[vtype], needle)[0]
        # overlap of size-1 catches values straddling a chunk boundary; it can
        # never contain a whole value starting past the boundary, so no dupes.
        for base, data in self._read_chunks(writable_only, overlap=size - 1):
            for off in find_value_offsets(data, needle, align):
                session.addresses.append(base + off)
                session.values.append(decoded)
        return session

    def next_scan(self, session: ScanSession, mode: str, value=None) -> ScanSession:
        fmt = VALUE_FORMATS[session.vtype]
        width = struct.calcsize(fmt)
        arg = struct.unpack(fmt, pack_value(session.vtype, value))[0] if value is not None else None
        out = ScanSession(session.vtype)
        addrs, prevs = session.addresses, session.values
        i, n = 0, len(addrs)
        while i < n:
            j = i
            start = addrs[i]
            while j + 1 < n and addrs[j + 1] + width - start <= BATCH_SPAN:
                j += 1
            try:
                blob = self.proc.read(start, addrs[j] + width - start)
            except OSError:
                i = j + 1
                continue
            for k in range(i, j + 1):
                rel = addrs[k] - start
                if rel + width > len(blob):
                    continue
                cur = struct.unpack_from(fmt, blob, rel)[0]
                if compare(mode, prevs[k], cur, arg):
                    out.addresses.append(addrs[k])
                    out.values.append(cur)
            i = j + 1
        return out

    def aob_scan(self, module_name: str, pattern: str) -> list[int]:
        mod = self.proc.module(module_name)
        hits = []
        rx = compile_aob(pattern)
        for region in self.proc.regions():
            if region.base + region.size <= mod.base or region.base >= mod.base + mod.size:
                continue
            try:
                data = self.proc.read(region.base, region.size)
            except OSError:
                continue
            pos = 0
            while (m := rx.search(data, pos)) is not None:
                hits.append(region.base + m.start())
                pos = m.start() + 1
        return hits

    def resolve_rip(self, instr_addr: int, disp_offset: int, instr_len: int) -> int:
        """Resolve a RIP-relative operand, e.g. `mov rax,[rip+disp32]` (disp at +3, len 7)."""
        disp = self.proc.read_value(instr_addr + disp_offset, "i32")
        return instr_addr + instr_len + disp
