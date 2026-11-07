"""Address table: named game values (currency, inventory, stats) and how to locate them.

Each entry resolves to an address in one of three ways, tried in order:
  1. "aob":     signature in `module`; optional "rip" = [disp_offset, instr_len]
                to follow a RIP-relative operand to a static pointer.
  2. "base":    static offset from the start of `module`.
  3. "address": absolute address (only valid for the current game session).
The result of 1 or 2 is then walked through "offsets" like a Cheat Engine
pointer chain: for each offset, addr = read_ptr(addr) + offset.
"""

from __future__ import annotations

import json
import threading
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .process import GameProcess


@dataclass
class Entry:
    name: str
    category: str = "misc"
    type: str = "i32"
    module: str | None = None
    aob: str | None = None
    rip: list[int] | None = None
    base: str | None = None
    offsets: list[str] = field(default_factory=list)
    address: str | None = None
    notes: str = ""

    @property
    def located(self) -> bool:
        return bool(self.aob or self.base or self.address)


@dataclass
class Table:
    process: str
    entries: list[Entry]
    path: Path | None = None

    @classmethod
    def load(cls, path: str | Path) -> "Table":
        path = Path(path)
        raw = json.loads(path.read_text(encoding="utf-8"))
        return cls(raw["process"], [Entry(**e) for e in raw.get("entries", [])], path)

    def save(self, path: str | Path | None = None) -> None:
        path = Path(path or self.path)
        data = {"process": self.process, "entries": [_compact(asdict(e)) for e in self.entries]}
        path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")

    def get(self, name: str) -> Entry:
        for e in self.entries:
            if e.name.lower() == name.lower():
                return e
        raise KeyError(name)


def _compact(d: dict) -> dict:
    return {k: v for k, v in d.items() if v not in (None, "", [])}


def _int(v: str | int) -> int:
    return v if isinstance(v, int) else int(v, 0)


def resolve(proc: GameProcess, entry: Entry, scanner=None) -> int:
    if entry.aob:
        from .scanner import Scanner
        scanner = scanner or Scanner(proc)
        hits = scanner.aob_scan(entry.module, entry.aob)
        if len(hits) != 1:
            raise LookupError(f"{entry.name}: AOB matched {len(hits)} times (need exactly 1)")
        addr = hits[0]
        if entry.rip:
            addr = scanner.resolve_rip(addr, *entry.rip)
    elif entry.base:
        addr = proc.module(entry.module).base + _int(entry.base) if entry.module else _int(entry.base)
    elif entry.address:
        addr = _int(entry.address)
    else:
        raise LookupError(f"{entry.name}: not located yet (no aob/base/address)")
    for off in entry.offsets:
        addr = proc.read_ptr(addr) + _int(off)
    return addr


class Freezer:
    """Background thread that keeps re-writing values (e.g. lock health or shards)."""

    def __init__(self, proc: GameProcess, interval: float = 0.1):
        self.proc = proc
        self.interval = interval
        self._frozen: dict[str, tuple[int, str, object]] = {}
        self._lock = threading.Lock()
        self._thread: threading.Thread | None = None
        self._stop = threading.Event()

    def freeze(self, name: str, address: int, vtype: str, value) -> None:
        with self._lock:
            self._frozen[name] = (address, vtype, value)
        if not self._thread or not self._thread.is_alive():
            self._stop.clear()
            self._thread = threading.Thread(target=self._run, daemon=True)
            self._thread.start()

    def unfreeze(self, name: str) -> None:
        with self._lock:
            self._frozen.pop(name, None)

    def items(self):
        with self._lock:
            return dict(self._frozen)

    def stop(self) -> None:
        self._stop.set()

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            for name, (addr, vtype, value) in self.items().items():
                try:
                    self.proc.write_value(addr, vtype, value)
                except OSError:
                    self.unfreeze(name)
