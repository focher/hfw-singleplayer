"""Command line + interactive shell.

    hfw-trainer status                 is the game running, what's loaded
    hfw-trainer show [--table PATH]    read every located table entry
    hfw-trainer set NAME VALUE         write one table entry
    hfw-trainer shell                  interactive scan / edit / freeze session
"""

from __future__ import annotations

import argparse
import cmd
import shlex
from pathlib import Path

from . import GAME_EXE
from .process import GameProcess, find_pid
from .scanner import Scanner, ScanSession
from .table import Freezer, Table, resolve

DEFAULT_TABLE = Path(__file__).resolve().parents[2] / "tables" / "hfw.json"


def _parse_value(vtype: str, text: str):
    return float(text) if vtype.startswith("f") else int(text, 0)


def _read_entry(proc, entry):
    try:
        addr = resolve(proc, entry)
        return addr, proc.read_value(addr, entry.type)
    except (LookupError, OSError) as exc:
        return None, f"<{exc}>"


def cmd_status(args) -> int:
    pid = find_pid(args.exe)
    if pid is None:
        print(f"{args.exe} is not running")
        return 1
    with GameProcess(pid, write=False) as proc:
        mod = proc.module(args.exe)
        print(f"pid {pid}  {mod.name} base=0x{mod.base:X} size=0x{mod.size:X}")
    return 0


def cmd_show(args) -> int:
    table = Table.load(args.table)
    with GameProcess.attach(table.process, write=False) as proc:
        for e in table.entries:
            if not e.located:
                print(f"  {e.category:14} {e.name:24} (not located)")
                continue
            addr, val = _read_entry(proc, e)
            where = f"0x{addr:X}" if addr else "-"
            print(f"  {e.category:14} {e.name:24} {val!s:>14}  @ {where}")
    return 0


def cmd_set(args) -> int:
    table = Table.load(args.table)
    entry = table.get(args.name)
    with GameProcess.attach(table.process) as proc:
        addr = resolve(proc, entry)
        proc.write_value(addr, entry.type, _parse_value(entry.type, args.value))
        print(f"{entry.name} = {proc.read_value(addr, entry.type)}")
    return 0


class Shell(cmd.Cmd):
    intro = "HFW trainer shell. 'help' lists commands. Typical flow: scan i32 1234 -> " \
            "(change value in game) -> next eq 1250 -> list -> bind 0 \"Metal Shards\""
    prompt = "hfw> "

    def __init__(self, table: Table):
        super().__init__()
        self.table = table
        self.proc = GameProcess.attach(table.process)
        self.scanner = Scanner(self.proc)
        self.freezer = Freezer(self.proc)
        self.session: ScanSession | None = None

    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except (ValueError, KeyError, LookupError, OSError) as exc:
            print(f"error: {exc}")

    def emptyline(self):
        pass

    # -- scanning ---------------------------------------------------------

    def do_scan(self, arg):
        """scan TYPE VALUE  first scan for an exact value. TYPE: u8 i8 u16 i16 u32 i32 u64 i64 f32 f64"""
        vtype, value = shlex.split(arg)
        print("scanning...")
        self.session = self.scanner.first_scan(vtype, value)
        print(f"{len(self.session)} candidates")

    def do_next(self, arg):
        """next MODE [VALUE]  narrow candidates. MODE: eq ne gt lt changed unchanged increased decreased"""
        if not self.session:
            print("run 'scan' first")
            return
        parts = shlex.split(arg)
        self.session = self.scanner.next_scan(self.session, parts[0], parts[1] if len(parts) > 1 else None)
        print(f"{len(self.session)} candidates")

    def do_list(self, arg):
        """list [N]  show up to N candidates (default 20) with live values"""
        if not self.session:
            return
        n = int(arg or 20)
        for i, addr in enumerate(self.session.addresses[:n]):
            try:
                cur = self.proc.read_value(addr, self.session.vtype)
            except OSError:
                cur = "?"
            print(f"  [{i}] 0x{addr:X}  {cur}")

    def do_poke(self, arg):
        """poke INDEX VALUE  write a value to a candidate (to confirm it is the right one)"""
        idx, value = shlex.split(arg)
        addr = self.session.addresses[int(idx)]
        self.proc.write_value(addr, self.session.vtype, _parse_value(self.session.vtype, value))

    def do_bind(self, arg):
        """bind INDEX NAME  store a candidate's address on a table entry (this session only)"""
        idx, name = shlex.split(arg)
        entry = self.table.get(name)
        entry.address = f"0x{self.session.addresses[int(idx)]:X}"
        entry.type = self.session.vtype
        print(f"{entry.name} -> {entry.address} ({entry.type}); 'save' to persist")

    def do_aob(self, arg):
        """aob "PATTERN" [MODULE]  signature scan in a module (default: game exe)"""
        parts = shlex.split(arg)
        mod = parts[1] if len(parts) > 1 else self.table.process
        for hit in self.scanner.aob_scan(mod, parts[0])[:50]:
            print(f"  0x{hit:X}")

    # -- table ------------------------------------------------------------

    def do_show(self, arg):
        """show  read all located table entries"""
        frozen = self.freezer.items()
        for e in self.table.entries:
            if not e.located:
                continue
            addr, val = _read_entry(self.proc, e)
            mark = " [frozen]" if e.name in frozen else ""
            print(f"  {e.name:24} {val!s:>14}{mark}")

    def do_set(self, arg):
        """set NAME VALUE  write a table entry"""
        name, value = shlex.split(arg)
        e = self.table.get(name)
        self.proc.write_value(resolve(self.proc, e), e.type, _parse_value(e.type, value))

    def do_freeze(self, arg):
        """freeze NAME [VALUE]  keep a table entry pinned (at VALUE or its current value)"""
        parts = shlex.split(arg)
        e = self.table.get(parts[0])
        addr = resolve(self.proc, e)
        value = _parse_value(e.type, parts[1]) if len(parts) > 1 else self.proc.read_value(addr, e.type)
        self.freezer.freeze(e.name, addr, e.type, value)
        print(f"{e.name} frozen at {value}")

    def do_unfreeze(self, arg):
        """unfreeze NAME"""
        self.freezer.unfreeze(self.table.get(arg.strip()).name)

    def do_save(self, arg):
        """save [PATH]  write the table (including bound addresses) to disk"""
        self.table.save(arg.strip() or None)
        print("saved")

    def do_quit(self, arg):
        """quit"""
        self.freezer.stop()
        self.proc.close()
        return True

    do_exit = do_quit
    do_EOF = do_quit


def cmd_shell(args) -> int:
    Shell(Table.load(args.table)).cmdloop()
    return 0


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="hfw-trainer", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("status")
    s.add_argument("--exe", default=GAME_EXE)
    s.set_defaults(func=cmd_status)

    for name, func in (("show", cmd_show), ("shell", cmd_shell)):
        s = sub.add_parser(name)
        s.add_argument("--table", default=DEFAULT_TABLE)
        s.set_defaults(func=func)

    s = sub.add_parser("set")
    s.add_argument("name")
    s.add_argument("value")
    s.add_argument("--table", default=DEFAULT_TABLE)
    s.set_defaults(func=cmd_set)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except ProcessLookupError as exc:
        print(exc)
        return 1
    except PermissionError as exc:
        print(f"{exc}\nTry running the terminal as Administrator.")
        return 1
