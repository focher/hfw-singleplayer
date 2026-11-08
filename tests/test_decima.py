"""Offline tests for decima.py against a synthetic process that mimics the game's
memory shapes: RTTI records, `lea rax,[rip+X]; ret` GetRTTI stubs, vtables, and a
Player -> Entity -> components -> Inventory -> InventoryItem graph."""

import struct
import uuid

import pytest

from hfw_trainer.decima import KIND_POINTER, Decima, format_uuid
from hfw_trainer.process import Module, Region
from hfw_trainer.table import Entry, resolve

MOD, HEAP = 0x1_4000_0000, 0x2000_0000


class FakeProc:
    def __init__(self):
        self.mod = bytearray(0x10000)
        self.heap = bytearray(0x10000)

    def _seg(self, addr):
        if MOD <= addr < MOD + len(self.mod):
            return self.mod, addr - MOD
        if HEAP <= addr < HEAP + len(self.heap):
            return self.heap, addr - HEAP
        raise OSError(f"unmapped 0x{addr:X}")

    def read(self, addr, size):
        buf, off = self._seg(addr)
        if off + size > len(buf):
            size = len(buf) - off
        return bytes(buf[off:off + size])

    def write(self, addr, data):
        buf, off = self._seg(addr)
        buf[off:off + len(data)] = data

    def read_value(self, addr, vtype):
        fmt = {"u32": "<I", "i32": "<i", "f32": "<f", "u64": "<Q"}[vtype]
        return struct.unpack(fmt, self.read(addr, struct.calcsize(fmt)))[0]

    def write_value(self, addr, vtype, value):
        fmt = {"u32": "<I", "i32": "<i", "f32": "<f"}[vtype]
        self.write(addr, struct.pack(fmt, value))

    def read_ptr(self, addr):
        return self.read_value(addr, "u64")

    def module(self, name):
        return Module(name, MOD, len(self.mod), name)

    def regions(self, writable_only=False, private_only=False):
        if not writable_only:
            yield Region(MOD, len(self.mod), 0x02, 0x1000000)
        yield Region(HEAP, len(self.heap), 0x04, 0x20000)

    # helpers
    def put(self, addr, fmt, *vals):
        self.write(addr, struct.pack(fmt, *vals))


class Builder:
    def __init__(self, p: FakeProc):
        self.p = p
        self.str_at, self.rtti_at, self.attr_at, self.code_at, self.vt_at = 0x100, 0x1000, 0x3000, 0x5000, 0x6000

    def string(self, s):
        addr = MOD + self.str_at
        self.p.write(addr, s.encode() + b"\0")
        self.str_at += len(s) + 8
        return addr

    def atom(self, name):
        r = MOD + self.rtti_at
        self.rtti_at += 0x100
        self.p.put(r + 4, "<B", 0)
        self.p.put(r + 0x10, "<Q", self.string(name))
        return r

    def compound(self, name, attrs=(), bases=()):
        """attrs: (name, type_rtti|None, offset, is_property)"""
        r = MOD + self.rtti_at
        self.rtti_at += 0x100
        self.p.put(r + 4, "<BBBB", 4, 0, len(bases), len(attrs))
        self.p.put(r + 0x40, "<Q", self.string(name))
        if bases:
            b = MOD + self.attr_at
            self.attr_at += 0x10 * len(bases)
            for i, (btype, boff) in enumerate(bases):
                self.p.put(b + i * 0x10, "<QI", btype, boff)
            self.p.put(r + 0x58, "<Q", b)
        if attrs:
            a = MOD + self.attr_at
            self.attr_at += 0x38 * len(attrs)
            for i, (aname, atype, aoff, prop) in enumerate(attrs):
                self.p.put(a + i * 0x38, "<QHHxxxxQQQ", atype or 0, aoff, 0,
                           self.string(aname), 0x1234 if prop else 0, 0)
            self.p.put(r + 0x60, "<Q", a)
        return r

    def vtable(self, rtti, thunk=False):
        fn = MOD + self.code_at
        self.code_at += 0x10
        if thunk:  # vtable slot -> jmp -> lea/ret
            real = MOD + self.code_at
            self.code_at += 0x10
            self.p.write(fn, b"\xE9" + struct.pack("<i", real - (fn + 5)))
            fn_real = real
        else:
            fn_real = fn
        self.p.write(fn_real, b"\x48\x8D\x05" + struct.pack("<i", rtti - (fn_real + 7)) + b"\xC3")
        vt = MOD + self.vt_at
        self.vt_at += 0x40
        self.p.put(vt, "<Q", fn)
        return vt


SHARD_UUID = "6C7D3B2A-1F0E-4D5C-9B8A-7F6E5D4C3B2A"
WIRE_UUID = "11111111-2222-3333-4444-555555555555"
RIDGE_UUID = "BA128806-D3DA-6E4B-B768-A46D751850D5"


@pytest.fixture
def game():
    p = FakeProc()
    b = Builder(p)
    t_float, t_u32, t_bool, t_str = b.atom("float"), b.atom("uint32"), b.atom("bool"), b.atom("String")
    c_comp = b.compound("EntityComponent", [("IsInitialized", t_bool, 0x38, False)])
    c_destr = b.compound("Destructibility", [
        ("Health", None, 0, False),                    # category header
        ("Health", t_float, 0x80, False),
        ("MaxHealth", t_float, 0x84, False),
        ("HealthPercent", t_float, 0x0, True),         # property, must be skipped
    ], bases=[(c_comp, 0)])
    c_item = b.compound("InventoryItem", [("Amount", t_u32, 0x50, False)])
    c_res = b.compound("CommodityResource", [("Name", t_str, 0x20, False)])
    vt_player = b.vtable(b.compound("PlayerGame"))
    vt_entity = b.vtable(b.compound("HumanoidEntity"))
    vt_inv = b.vtable(b.compound("Inventory"))
    vt_destr = b.vtable(c_destr, thunk=True)
    vt_item, vt_res = b.vtable(c_item), b.vtable(c_res)
    b.string("NotPlayerGame")  # suffix decoy

    H = HEAP
    player, entity, comps, inv, hm, destr = H + 0x100, H + 0x400, H + 0x800, H + 0x900, H + 0x1000, H + 0x5000
    p.put(player, "<Q", vt_player)
    p.put(player + 0x48, "<Q", entity)
    p.put(entity, "<Q", vt_entity)
    p.put(entity + 0xA0, "<iiQ", 2, 4, comps)
    p.put(comps, "<QQ", inv, destr)
    p.put(inv, "<Q", vt_inv)
    p.put(inv + 0x60, "<Qii", hm, 2, 4)
    p.put(destr, "<Q", vt_destr)
    p.put(destr + 0x80, "<ff", 87.5, 120.0)

    def item(slot, at, uid, name, amount):
        proxy, loc, res, chars = at + 0x100, at + 0x200, at + 0x300, at + 0x410
        p.put(hm + slot * 0x20, "<16sQi", uuid.uuid4().bytes, at, 0x55)
        p.put(at, "<Q", vt_item)
        p.put(at + 0x48, "<Q", proxy)
        p.put(at + 0x50, "<I", amount)
        p.put(proxy, "<Q", loc)
        p.write(loc + 0x10, uuid.UUID(uid).bytes_le)
        p.put(loc + 0x20, "<Q", res)
        p.put(res, "<Q", vt_res)
        p.put(res + 0x20, "<Q", chars)
        p.put(chars - 8, "<I", len(name))
        p.write(chars, name.encode())

    item(0, H + 0x2000, SHARD_UUID, "Metal Shards", 1520)
    item(2, H + 0x2800, WIRE_UUID, "Wire", 12)

    # Item whose name comes from InventoryItemResource.ItemName -> LocalizedTextResource
    t_ref = MOD + b.rtti_at
    b.rtti_at += 0x100
    p.put(t_ref + 4, "<B", KIND_POINTER)
    p.put(t_ref + 0x18, "<Q", b.string("Ref_LocalizedTextResource"))
    vt_iir = b.vtable(b.compound("InventoryItemResource", [("ItemName", t_ref, 0x48, False)]))
    vt_ltr = b.vtable(b.compound("LocalizedTextResource"))
    at = H + 0x3000
    proxy, loc, res, ltr, chars = at + 0x100, at + 0x200, at + 0x300, at + 0x400, at + 0x500
    p.put(hm + 3 * 0x20, "<16sQi", uuid.uuid4().bytes, at, 0x77)
    p.put(at, "<Q", vt_item)
    p.put(at + 0x48, "<Q", proxy)
    p.put(at + 0x50, "<I", 100)
    p.put(proxy, "<Q", loc)
    p.write(loc + 0x10, uuid.UUID(RIDGE_UUID).bytes_le)
    p.put(loc + 0x20, "<Q", res)
    p.put(res, "<Q", vt_iir)
    p.put(res + 0x48, "<Q", ltr)
    p.put(ltr, "<Q", vt_ltr)
    p.put(ltr + 0x20, "<QH", chars, len("Ridge-Wood"))
    p.write(chars, b"Ridge-Wood")
    p.put(inv + 0x60, "<Qii", hm, 3, 4)

    # Static Array<Player*> {u32 n, u32 cap, Player** data} in module .data
    p.put(H + 0x80, "<Q", player)
    p.put(MOD + 0x9000, "<IIQ", 1, 3, H + 0x80)
    return p


def test_rtti_and_fields(game):
    d = Decima(game, "HorizonForbiddenWest.exe")
    assert len(d.find_rtti("PlayerGame")) == 1          # decoy suffix ignored
    destr = HEAP + 0x5000
    assert d.class_name(destr) == "Destructibility"     # through jmp thunk
    names = [(f.name, f.offset) for f in d.fields(d.rtti_of(destr))]
    assert names == [("IsInitialized", 0x38), ("Health", 0x80), ("MaxHealth", 0x84)]
    f = d.field(d.rtti_of(destr), "Health")
    assert f.vtype == "f32" and f.category == "Health"
    assert d.read_field(destr, f) == 87.5


def test_player_inventory(game):
    d = Decima(game, "HorizonForbiddenWest.exe")
    player, entity = d.player_entity()
    assert (player, entity) == (HEAP + 0x100, HEAP + 0x400)
    assert [n for _, n in d.components(entity)] == ["Inventory", "Destructibility"]
    items = {i.name: i for i in d.player_inventory()}
    assert items["Metal Shards"].amount == 1520
    assert items["Metal Shards"].resource_uuid == SHARD_UUID
    assert items["Wire"].amount == 12
    assert d.find_item("shard").name == "Metal Shards"
    assert d.find_item(SHARD_UUID.lower()).name == "Metal Shards"


def test_table_entries_resolve_by_uuid_and_field(game):
    d = Decima(game, "HorizonForbiddenWest.exe")
    shards = Entry(name="Metal Shards", item=SHARD_UUID)
    addr = resolve(game, shards, decima=d)
    game.write_value(addr, "i32", 99999)
    assert d.find_item(SHARD_UUID).amount == 99999
    health_addr, f = d.component_field_address("Destructibility", "Health")
    assert game.read_value(health_addr, "f32") == 87.5


def test_entity_offset_fallback(game):
    """If a patch moves Player.m_Entity, the validator searches nearby offsets."""
    game.put(HEAP + 0x100 + 0x48, "<Q", 0)
    game.put(HEAP + 0x100 + 0x58, "<Q", HEAP + 0x400)
    d = Decima(game, "HorizonForbiddenWest.exe")
    assert d.player_entity()[1] == HEAP + 0x400


def test_player_found_through_static_array(game):
    d = Decima(game, "HorizonForbiddenWest.exe")
    assert d.player_objects_from_globals() == [HEAP + 0x100]


def test_localized_item_name(game):
    d = Decima(game, "HorizonForbiddenWest.exe")
    ridge = d.find_item("ridge")
    assert ridge.name == "Ridge-Wood" and ridge.amount == 100
    assert ridge.resource_uuid == RIDGE_UUID


def test_raw_component_offset(game):
    d = Decima(game, "HorizonForbiddenWest.exe")
    entry = Entry(name="Max Health", type="f32", component="Destructibility", field="0x84")
    assert game.read_value(resolve(game, entry, decima=d), "f32") == 120.0


def test_format_uuid_roundtrip():
    u = uuid.uuid4()
    assert format_uuid(u.bytes_le) == str(u).upper()
