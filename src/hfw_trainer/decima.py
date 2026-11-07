"""Navigate Horizon Forbidden West's live object graph through Decima engine RTTI.

Why this exists: absolute addresses change every launch (ASLR + fresh heap), but
the *shape* of the data does not. Every engine object starts with a vtable whose
first entry is `GetRTTI()`, compiled as `lea rax,[rip+RTTI]; ret`. The RTTI
record carries the class name and a table of named fields with byte offsets.
So from any object we can learn what it is and where its fields live, and from
a class name we can find every live instance. Nothing here depends on a
hard-coded address, so it survives game restarts and (mostly) patches.

Object path to the player's data (layouts from Nukem9's hfw-gameplay-tweaks,
targeting game v1.5.80.0; each offset is validated and re-searched if wrong):

    PlayerGame/Player            +0x48 -> Entity*
    Entity                       +0xA0 -> Array<EntityComponent*> {i32 len, i32 max, T* data}
    Inventory (component)        +0x60 -> HashMap<GGUUID, InventoryItem*> {Assoc* data, i32 num, i32 cap}
        Assoc (0x20 bytes)       +0x00 GGUUID key, +0x10 InventoryItem*, +0x18 i32 hash (0 = empty)
    InventoryItem                +0x48 StreamingRef<EntityResource> -> proxy -> locator{+0x10 GGUUID, +0x20 obj}
                                 +0x50 u32 amount      (metal shards are an item; value is 32-bit)
    Destructibility (component)  player health and invulnerability flags

RTTI record layouts (RTTICompound, kind 4):
    +0x04 u8 kind  +0x06 u8 base_count  +0x07 u8 attr_count
    +0x40 char* name  +0x58 Base* bases {RTTI* type, u32 offset}  +0x60 Attr* attrs (0x38 each)
    Attr: +0x00 RTTI* type (null = category header)  +0x08 u16 offset  +0x0A u16 flags
          +0x10 char* name  +0x18 getter  +0x20 setter (property: offset not meaningful)
"""

from __future__ import annotations

import re
import struct
import uuid
from dataclasses import dataclass

KIND_ATOM, KIND_POINTER, KIND_CONTAINER, KIND_ENUM, KIND_COMPOUND = 0, 1, 2, 3, 4

# Atom type names -> struct formats for reading field values
ATOM_FORMATS = {
    "bool": "<?", "int8": "<b", "uint8": "<B", "int16": "<h", "uint16": "<H",
    "int": "<i", "int32": "<i", "uint": "<I", "uint32": "<I",
    "int64": "<q", "uint64": "<Q", "float": "<f", "double": "<d",
    "ucs4": "<I", "wchar": "<H", "tchar": "<B",
}
ATOM_VTYPES = {
    "bool": "u8", "int8": "i8", "uint8": "u8", "int16": "i16", "uint16": "u16",
    "int": "i32", "int32": "i32", "uint": "u32", "uint32": "u32",
    "int64": "i64", "uint64": "u64", "float": "f32", "double": "f64",
}

# Layout hints (game v1.5.80.0). Each is validated before use.
PLAYER_ENTITY_OFF = 0x48
ENTITY_COMPONENTS_OFF = 0xA0
INVENTORY_ITEMS_OFF = 0x60
ITEM_RESOURCE_OFF = 0x48
ITEM_AMOUNT_OFF = 0x50
COMPONENT_ENTITY_OFF = 0x48

GETRTTI_RE = re.compile(rb"\x48\x8D\x05(.{4})\xC3", re.DOTALL)
USER_MAX = 0x7FFF_FFFF_FFFF


@dataclass(frozen=True)
class Field:
    name: str
    offset: int
    type_name: str
    kind: int
    category: str = ""
    type_rtti: int = 0

    @property
    def vtype(self) -> str | None:
        return ATOM_VTYPES.get(self.type_name) if self.kind in (KIND_ATOM, KIND_ENUM) else None


@dataclass(frozen=True)
class Item:
    address: int          # InventoryItem object
    amount_address: int
    amount: int
    resource_uuid: str | None
    resource_type: str | None
    name: str | None


def format_uuid(raw: bytes) -> str:
    return str(uuid.UUID(bytes_le=bytes(raw))).upper()


def parse_uuid(text: str) -> bytes:
    return uuid.UUID(text).bytes_le


def _canonical(p: int) -> bool:
    return 0x10000 <= p <= USER_MAX


class Decima:
    """RTTI-aware view of a GameProcess (or anything with read/regions/module)."""

    def __init__(self, proc, module_name: str):
        self.proc = proc
        self.module_name = module_name
        self._mod = proc.module(module_name)
        self._image: bytes | None = None
        self._getrtti_index: dict[int, list[int]] | None = None
        self._vt_rtti: dict[int, int | None] = {}
        self._names: dict[int, str] = {}
        self._fields: dict[int, list[Field]] = {}
        self._player: tuple[int, int] | None = None

    # -- low level ---------------------------------------------------------

    def ptr(self, addr: int) -> int:
        try:
            return struct.unpack("<Q", self.proc.read(addr, 8))[0]
        except (OSError, struct.error):
            return 0

    def u8(self, addr: int) -> int:
        return self.proc.read(addr, 1)[0]

    def cstr(self, addr: int, limit: int = 256) -> str:
        raw = self.proc.read(addr, limit)
        return raw.split(b"\0", 1)[0].decode("utf-8", "replace")

    def read_string(self, addr: int) -> str | None:
        """Decima `String`: pointer to chars, u32 length stored 8 bytes before the chars."""
        data = self.ptr(addr)
        if not _canonical(data):
            return None
        try:
            length = struct.unpack("<I", self.proc.read(data - 8, 4))[0]
            if length > 4096:
                return None
            return self.proc.read(data, length).decode("utf-8", "replace")
        except OSError:
            return None

    @property
    def image(self) -> bytes:
        """The main module mapped as it is in memory (index = RVA)."""
        if self._image is None:
            m = self._mod
            buf = bytearray(m.size)
            for region in self.proc.regions():
                lo, hi = max(region.base, m.base), min(region.base + region.size, m.base + m.size)
                if lo >= hi:
                    continue
                try:
                    buf[lo - m.base: hi - m.base] = self.proc.read(lo, hi - lo)
                except OSError:
                    pass
            self._image = bytes(buf)
        return self._image

    def _image_find_all(self, needle: bytes, align: int = 1) -> list[int]:
        img, out, i = self.image, [], self.image.find(needle)
        while i != -1:
            if i % align == 0:
                out.append(self._mod.base + i)
            i = img.find(needle, i + 1)
        return out

    # -- RTTI --------------------------------------------------------------

    def rtti_of(self, obj: int) -> int | None:
        vt = self.ptr(obj)
        if not _canonical(vt):
            return None
        if vt in self._vt_rtti:
            return self._vt_rtti[vt]
        rtti = None
        fn = self.ptr(vt)
        try:
            for _ in range(2):  # follow one `jmp rel32` thunk if present
                code = self.proc.read(fn, 8)
                if code[0] == 0xE9:
                    fn = fn + 5 + struct.unpack_from("<i", code, 1)[0]
                    continue
                if code[:3] == b"\x48\x8D\x05" and code[7] == 0xC3:
                    rtti = fn + 7 + struct.unpack_from("<i", code, 3)[0]
                break
        except (OSError, IndexError):
            pass
        self._vt_rtti[vt] = rtti
        return rtti

    def kind(self, rtti: int) -> int:
        return self.u8(rtti + 4)

    def type_name(self, rtti: int) -> str:
        if rtti in self._names:
            return self._names[rtti]
        try:
            k = self.kind(rtti)
            off = {KIND_COMPOUND: 0x40, KIND_ATOM: 0x10, KIND_ENUM: 0x10}.get(k, 0x18)
            name = self.cstr(self.ptr(rtti + off))
        except OSError:
            name = "?"
        self._names[rtti] = name
        return name

    def class_name(self, obj: int) -> str | None:
        rtti = self.rtti_of(obj)
        return self.type_name(rtti) if rtti else None

    def fields(self, rtti: int) -> list[Field]:
        """All data members of a compound type, including inherited ones, with absolute offsets."""
        if rtti in self._fields:
            return self._fields[rtti]
        out: list[Field] = []
        self._collect_fields(rtti, 0, out, depth=0)
        out.sort(key=lambda f: f.offset)
        self._fields[rtti] = out
        return out

    def _collect_fields(self, rtti: int, base: int, out: list[Field], depth: int) -> None:
        if depth > 16 or self.kind(rtti) != KIND_COMPOUND:
            return
        hdr = self.proc.read(rtti, 0x68)
        n_bases, n_attrs = hdr[6], hdr[7]
        bases_p, attrs_p = struct.unpack_from("<QQ", hdr, 0x58)
        if n_bases and _canonical(bases_p):
            raw = self.proc.read(bases_p, n_bases * 0x10)
            for i in range(n_bases):
                btype, boff = struct.unpack_from("<QI", raw, i * 0x10)
                if _canonical(btype):
                    self._collect_fields(btype, base + boff, out, depth + 1)
        if n_attrs and _canonical(attrs_p):
            raw = self.proc.read(attrs_p, n_attrs * 0x38)
            category = ""
            for i in range(n_attrs):
                atype, aoff, _flags, aname, getter, setter = struct.unpack_from("<QHHxxxxQQQ", raw, i * 0x38)
                name = self.cstr(aname) if _canonical(aname) else "?"
                if not atype:
                    category = name
                    continue
                if getter or setter:     # property accessor; offset not a real storage slot
                    continue
                out.append(Field(name, base + aoff, self.type_name(atype), self.kind(atype),
                                 category, atype))

    def field(self, rtti: int, name: str) -> Field | None:
        for f in self.fields(rtti):
            if f.name == name:
                return f
        return None

    def read_field(self, obj: int, f: Field):
        if f.type_name in ATOM_FORMATS:
            fmt = ATOM_FORMATS[f.type_name]
            return struct.unpack(fmt, self.proc.read(obj + f.offset, struct.calcsize(fmt)))[0]
        if f.type_name == "String":
            return self.read_string(obj + f.offset)
        if f.kind == KIND_ENUM:
            size = self.u8(f.type_rtti + 6)
            fmt = {1: "<B", 2: "<H", 4: "<i"}.get(size)
            return struct.unpack(fmt, self.proc.read(obj + f.offset, size))[0] if fmt else None
        if f.kind == KIND_POINTER:
            return f"-> 0x{self.ptr(obj + f.offset):X}"
        return None

    # -- finding classes and live instances --------------------------------

    def find_rtti(self, name: str) -> list[int]:
        """RTTICompound records whose type name is exactly `name`."""
        hits = []
        for s in self._image_find_all(name.encode() + b"\0"):
            rva = s - self._mod.base
            if rva and self.image[rva - 1] != 0:
                continue                     # suffix of a longer string
            for ref in self._image_find_all(struct.pack("<Q", s), align=8):
                cand = ref - 0x40
                rv = cand - self._mod.base
                if 0 <= rv + 4 < len(self.image) and self.image[rv + 4] == KIND_COMPOUND:
                    hits.append(cand)
        return hits

    def getrtti_functions(self, rtti: int) -> list[int]:
        if self._getrtti_index is None:
            idx: dict[int, list[int]] = {}
            base = self._mod.base
            for m in GETRTTI_RE.finditer(self.image):
                fn = base + m.start()
                target = fn + 7 + struct.unpack("<i", m.group(1))[0]
                idx.setdefault(target, []).append(fn)
            self._getrtti_index = idx
        return self._getrtti_index.get(rtti, [])

    def vtables_of(self, class_name: str) -> list[int]:
        out = []
        for rtti in self.find_rtti(class_name):
            for fn in self.getrtti_functions(rtti):
                out.extend(self._image_find_all(struct.pack("<Q", fn), align=8))
        return sorted(set(out))

    def instances(self, class_name: str, limit: int = 10_000, progress=None) -> list[int]:
        """Heap objects whose vtable belongs to `class_name` (exact class, not subclasses)."""
        vtables = self.vtables_of(class_name)
        if not vtables:
            return []
        needles = [struct.pack("<Q", v) for v in vtables]
        out: list[int] = []
        chunk = 32 * 1024 * 1024
        for region in self.proc.regions(writable_only=True):
            if self._mod.base <= region.base < self._mod.base + self._mod.size:
                continue
            for off in range(0, region.size, chunk):
                base = region.base + off
                try:
                    data = self.proc.read(base, min(chunk, region.size - off))
                except OSError:
                    break
                for needle in needles:
                    i = data.find(needle)
                    while i != -1:
                        if i % 8 == 0:
                            out.append(base + i)
                            if len(out) >= limit:
                                return out
                        i = data.find(needle, i + 1)
            if progress:
                progress(region)
        return out

    # -- player / components / inventory -----------------------------------

    def component_array(self, entity: int) -> tuple[int, int] | None:
        """(data_ptr, count) for an Entity's component list; validates the hint, else searches."""
        for off in [ENTITY_COMPONENTS_OFF] + list(range(0x60, 0x200, 8)):
            try:
                n, cap, data = struct.unpack("<iiQ", self.proc.read(entity + off, 16))
            except OSError:
                return None
            if not (0 < n <= cap <= 1024 and _canonical(data)):
                continue
            try:
                ptrs = struct.unpack(f"<{n}Q", self.proc.read(data, n * 8))
            except OSError:
                continue
            if all(_canonical(p) and self.rtti_of(p) for p in ptrs[: min(n, 8)]):
                return data, n
        return None

    def components(self, entity: int) -> list[tuple[int, str]]:
        arr = self.component_array(entity)
        if not arr:
            return []
        data, n = arr
        ptrs = struct.unpack(f"<{n}Q", self.proc.read(data, n * 8))
        return [(p, self.class_name(p) or "?") for p in ptrs]

    def component(self, entity: int, class_name: str) -> int | None:
        for addr, name in self.components(entity):
            if name == class_name:
                return addr
        return None

    def player_entity(self, progress=None) -> tuple[int, int]:
        """(player, entity) for the local player. Scans the heap once, then cached."""
        if self._player and self.component_array(self._player[1]):
            return self._player
        candidates = []
        for cls in ("PlayerGame", "Player"):
            for obj in self.instances(cls, limit=64, progress=progress):
                entity = self._player_entity_ptr(obj)
                if entity:
                    candidates.append((obj, entity))
            if candidates:
                break
        if not candidates:
            raise LookupError("could not find the player object (is a save loaded?)")
        # Prefer the player whose entity actually carries an Inventory component
        candidates.sort(key=lambda pe: self.component(pe[1], "Inventory") is None)
        self._player = candidates[0]
        return self._player

    def _player_entity_ptr(self, player: int) -> int | None:
        for off in [PLAYER_ENTITY_OFF] + list(range(0x20, 0x100, 8)):
            ent = self.ptr(player + off)
            if _canonical(ent) and self.component_array(ent):
                return ent
        return None

    def _hashmap(self, inv: int) -> tuple[int, int, int] | None:
        for off in [INVENTORY_ITEMS_OFF] + list(range(0x50, 0x120, 8)):
            try:
                data, num, cap = struct.unpack("<Qii", self.proc.read(inv + off, 16))
            except OSError:
                return None
            if _canonical(data) and 0 < num <= cap <= 1 << 16:
                return data, num, cap
        return None

    def inventory_items(self, inv: int) -> list[Item]:
        hm = self._hashmap(inv)
        if not hm:
            return []
        data, _num, cap = hm
        raw = self.proc.read(data, cap * 0x20)
        items = []
        amount_off = None
        for i in range(cap):
            _key, value, h = struct.unpack_from("<16sQi", raw, i * 0x20)
            if h == 0 or not _canonical(value):
                continue
            if amount_off is None:
                rtti = self.rtti_of(value)
                f = self.field(rtti, "Amount") if rtti else None
                amount_off = f.offset if f else ITEM_AMOUNT_OFF
            items.append(self._item(value, amount_off))
        return items

    def _item(self, item: int, amount_off: int) -> Item:
        amount = struct.unpack("<I", self.proc.read(item + amount_off, 4))[0]
        res_uuid = res_type = name = None
        proxy = self.ptr(item + ITEM_RESOURCE_OFF)
        locator = self.ptr(proxy) if _canonical(proxy) else 0
        if _canonical(locator):
            try:
                res_uuid = format_uuid(self.proc.read(locator + 0x10, 16))
            except OSError:
                pass
            res = self.ptr(locator + 0x20)
            rtti = self.rtti_of(res) if _canonical(res) else None
            if rtti:
                res_type = self.type_name(rtti)
                f = self.field(rtti, "Name")
                if f and f.type_name == "String":
                    name = self.read_string(res + f.offset)
        return Item(item, item + amount_off, amount, res_uuid, res_type, name)

    def player_inventory(self, progress=None) -> list[Item]:
        _, entity = self.player_entity(progress)
        inv = self.component(entity, "Inventory")
        if not inv:
            raise LookupError("player entity has no Inventory component")
        return self.inventory_items(inv)

    def find_item(self, key: str, progress=None) -> Item:
        """Match by resource UUID (stable across runs) or case-insensitive name substring."""
        items = self.player_inventory(progress)
        k = key.upper().strip("{}")
        exact = [i for i in items if i.resource_uuid == k]
        if exact:
            return exact[0]
        named = [i for i in items if i.name and key.lower() in i.name.lower()]
        if len(named) == 1:
            return named[0]
        if not named:
            raise LookupError(f"no inventory item matches {key!r}")
        raise LookupError(f"{key!r} is ambiguous: " + ", ".join(i.name for i in named[:10]))

    def component_field_address(self, component_name: str, field_name: str,
                                progress=None) -> tuple[int, Field]:
        _, entity = self.player_entity(progress)
        comp = self.component(entity, component_name)
        if not comp:
            raise LookupError(f"player has no {component_name} component")
        f = self.field(self.rtti_of(comp), field_name)
        if not f:
            raise LookupError(f"{component_name} has no field {field_name!r}")
        return comp + f.offset, f
