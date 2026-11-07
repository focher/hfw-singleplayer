"""Command line + interactive shell.

    hfw-trainer status                 is the game running, what's loaded
    hfw-trainer show [--table PATH]    read every located table entry
    hfw-trainer set NAME VALUE         write one table entry
    hfw-trainer inventory [FILTER]     list the player's inventory (found via game RTTI)
    hfw-trainer components             list the player entity's components
    hfw-trainer dump COMPONENT [FILT]  show every named field of a player component
    hfw-trainer shell                  interactive scan / edit / freeze session
"""

from __future__ import annotations

import argparse
import cmd
import shlex
from pathlib import Path

from . import GAME_EXE
from .decima import Decima
from .process import GameProcess, find_pid
from .scanner import Scanner, ScanSession
from .table import Entry, Freezer, Table, resolve

DEFAULT_TABLE = Path(__file__).resolve().parents[2] / "tables" / "hfw.json"


def _parse_value(vtype: str, text: str):
    return float(text) if vtype.startswith("f") else int(text, 0)


class _Progress:
    """Prints a dot every few hundred memory regions during the one-time heap scan."""

    def __init__(self):
        self.n = 0

    def __call__(self, _region):
        self.n += 1
        if self.n % 200 == 0:
            print(".", end="", flush=True)


_progress = _Progress()


def _locate(proc, dec, entry) -> tuple[int, str]:
    """(address, value type) for a table entry."""
    if entry.component and entry.field:
        addr, f = dec.component_field_address(entry.component, entry.field, _progress)
        return addr, f.vtype or entry.type
    return resolve(proc, entry, decima=dec), entry.type


def _read_entry(proc, dec, entry):
    try:
        addr, vtype = _locate(proc, dec, entry)
        return addr, proc.read_value(addr, vtype)
    except (LookupError, OSError) as exc:
        return None, f"<{exc}>"


def print_inventory(dec: Decima, needle: str = "") -> None:
    items = dec.player_inventory(_progress)
    print()
    shown = 0
    for it in sorted(items, key=lambda i: (i.name or i.resource_type or "").lower()):
        label = it.name or it.resource_type or "?"
        if needle and needle.lower() not in label.lower() and needle.upper() != it.resource_uuid:
            continue
        shown += 1
        print(f"  {it.amount:>8}  {label:40} {it.resource_uuid or '-'}  @0x{it.amount_address:X}")
    print(f"{shown} of {len(items)} items")


def print_components(dec: Decima) -> None:
    player, entity = dec.player_entity(_progress)
    print(f"\nplayer 0x{player:X} ({dec.class_name(player)})  "
          f"entity 0x{entity:X} ({dec.class_name(entity)})")
    for addr, name in dec.components(entity):
        print(f"  0x{addr:X}  {name}")


def print_dump(dec: Decima, component: str, needle: str = "") -> None:
    _, entity = dec.player_entity(_progress)
    comp = entity if component.lower() == "entity" else dec.component(entity, component)
    if not comp:
        raise LookupError(f"player has no {component} component (see 'components')")
    print(f"\n{dec.class_name(comp)} @ 0x{comp:X}")
    for f in dec.fields(dec.rtti_of(comp)):
        if needle and needle.lower() not in f.name.lower():
            continue
        try:
            val = dec.read_field(comp, f)
        except OSError:
            val = "?"
        print(f"  +0x{f.offset:04X}  {f.type_name:24} {f.name:36} {'' if val is None else val}")


# ---------------------------------------------------------------------------
# One-shot commands
# ---------------------------------------------------------------------------

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
        dec = Decima(proc, table.process)
        for e in table.entries:
            if not e.located:
                print(f"  {e.category:14} {e.name:24} (not located)")
                continue
            addr, val = _read_entry(proc, dec, e)
            where = f"0x{addr:X}" if addr else "-"
            print(f"  {e.category:14} {e.name:24} {val!s:>14}  @ {where}")
    return 0


def cmd_set(args) -> int:
    table = Table.load(args.table)
    entry = table.get(args.name)
    with GameProcess.attach(table.process) as proc:
        addr, vtype = _locate(proc, Decima(proc, table.process), entry)
        proc.write_value(addr, vtype, _parse_value(vtype, args.value))
        print(f"{entry.name} = {proc.read_value(addr, vtype)}")
    return 0


def _with_decima(fn):
    def run(args) -> int:
        with GameProcess.attach(GAME_EXE, write=False) as proc:
            fn(Decima(proc, GAME_EXE), args)
        return 0
    return run


cmd_inventory = _with_decima(lambda dec, a: print_inventory(dec, a.filter))
cmd_components = _with_decima(lambda dec, a: print_components(dec))
cmd_dump = _with_decima(lambda dec, a: print_dump(dec, a.component, a.filter))


# ---------------------------------------------------------------------------
# Interactive shell
# ---------------------------------------------------------------------------

class Shell(cmd.Cmd):
    intro = ("HFW trainer shell. 'help' lists commands.\n"
             "  RTTI route:  components -> inventory -> item \"shard\" 99999 -> track \"shard\" \"Metal Shards\" -> save\n"
             "  Scan route:  scan i32 1234 -> (change it in game) -> next eq 1250 -> list -> bind 0 \"Metal Shards\"")
    prompt = "hfw> "

    def __init__(self, table: Table):
        super().__init__()
        self.table = table
        self.proc = GameProcess.attach(table.process)
        self.scanner = Scanner(self.proc)
        self.dec = Decima(self.proc, table.process)
        self.freezer = Freezer(self.proc)
        self.session: ScanSession | None = None

    def onecmd(self, line):
        try:
            return super().onecmd(line)
        except (ValueError, KeyError, LookupError, OSError, IndexError) as exc:
            print(f"error: {exc}")

    def emptyline(self):
        pass

    # -- RTTI navigation ----------------------------------------------------

    def do_components(self, arg):
        """components  list the player entity's components (first call scans the heap)"""
        print_components(self.dec)

    def do_dump(self, arg):
        """dump COMPONENT [FILTER]  named fields + live values of a player component ('entity' = the entity)"""
        parts = shlex.split(arg)
        print_dump(self.dec, parts[0], parts[1] if len(parts) > 1 else "")

    def do_inventory(self, arg):
        """inventory [FILTER]  list inventory items: amount, name, resource UUID"""
        print_inventory(self.dec, arg.strip())

    def do_item(self, arg):
        """item KEY [AMOUNT]  read or set an inventory item's amount (KEY = UUID or part of its name)"""
        parts = shlex.split(arg)
        it = self.dec.find_item(parts[0], _progress)
        if len(parts) > 1:
            self.proc.write_value(it.amount_address, "u32", int(parts[1], 0))
        print(f"{it.name or it.resource_uuid}: {self.proc.read_value(it.amount_address, 'u32')}")

    def do_track(self, arg):
        """track KEY [NAME]  save an inventory item to the table by UUID (works across game restarts)"""
        parts = shlex.split(arg)
        it = self.dec.find_item(parts[0], _progress)
        name = parts[1] if len(parts) > 1 else (it.name or it.resource_uuid)
        try:
            entry = self.table.get(name)
        except KeyError:
            entry = Entry(name=name, category="inventory")
            self.table.entries.append(entry)
        entry.item, entry.type, entry.address = it.resource_uuid, "i32", None
        print(f"{name} -> item {it.resource_uuid}; 'save' to persist")

    def do_field(self, arg):
        """field COMPONENT FIELD [NAME]  save a component field (e.g. a health value) to the table"""
        parts = shlex.split(arg)
        _, f = self.dec.component_field_address(parts[0], parts[1], _progress)
        name = parts[2] if len(parts) > 2 else f"{parts[0]}.{parts[1]}"
        try:
            entry = self.table.get(name)
        except KeyError:
            entry = Entry(name=name, category="stats")
            self.table.entries.append(entry)
        entry.component, entry.field, entry.address = parts[0], parts[1], None
        entry.type = f.vtype or entry.type
        print(f"{name} -> {parts[0]}.{parts[1]} ({f.type_name}); 'save' to persist")

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
        """list [N]  show up to N candidates (default 20) with live values and owning object class"""
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
        """bind INDEX NAME  store a candidate's address on a table entry (this game session only)"""
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
            _addr, val = _read_entry(self.proc, self.dec, e)
            mark = " [frozen]" if e.name in frozen else ""
            print(f"  {e.name:24} {val!s:>14}{mark}")

    def do_set(self, arg):
        """set NAME VALUE  write a table entry"""
        name, value = shlex.split(arg)
        e = self.table.get(name)
        addr, vtype = _locate(self.proc, self.dec, e)
        self.proc.write_value(addr, vtype, _parse_value(vtype, value))

    def do_freeze(self, arg):
        """freeze NAME [VALUE]  keep a table entry pinned (at VALUE or its current value)"""
        parts = shlex.split(arg)
        e = self.table.get(parts[0])
        addr, vtype = _locate(self.proc, self.dec, e)
        value = _parse_value(vtype, parts[1]) if len(parts) > 1 else self.proc.read_value(addr, vtype)
        self.freezer.freeze(e.name, addr, vtype, value)
        print(f"{e.name} frozen at {value}")

    def do_unfreeze(self, arg):
        """unfreeze NAME"""
        self.freezer.unfreeze(self.table.get(arg.strip()).name)

    def do_save(self, arg):
        """save [PATH]  write the table to disk"""
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

    s = sub.add_parser("inventory")
    s.add_argument("filter", nargs="?", default="")
    s.set_defaults(func=cmd_inventory)

    s = sub.add_parser("components")
    s.set_defaults(func=cmd_components)

    s = sub.add_parser("dump")
    s.add_argument("component")
    s.add_argument("filter", nargs="?", default="")
    s.set_defaults(func=cmd_dump)

    args = p.parse_args(argv)
    try:
        return args.func(args)
    except (ProcessLookupError, LookupError) as exc:
        print(exc)
        return 1
    except PermissionError as exc:
        print(f"{exc}\nTry running the terminal as Administrator.")
        return 1
