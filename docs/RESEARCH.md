# How Horizon Forbidden West stores player values

Research notes behind `src/hfw_trainer/decima.py`. Collected 2026-11-07.

## Sources

- **[Nukem9/hfw-gameplay-tweaks](https://github.com/Nukem9/hfw-gameplay-tweaks)**: open-source C++ mod
  (inventory editor, god mode, item spawner) for game **v1.5.80.0**. Its headers
  (`source/HRZ2/Core/*.h`) document engine class layouts with compile-time offset asserts.
  This is the primary source for every offset below.
- [ShadelessFox/decima](https://github.com/ShadelessFox/decima): Decima asset tooling (HFW supported).
  Useful later for mapping resource UUIDs to names offline.
- Marcus101RR's Cheat Engine table ([GamePressure mirror](https://www.gamepressure.com/download/horizon-forbidden-west-complete-edition-cheat-table-ct-for-cheat/z714cf9)):
  covers health, focus, stamina and oxygen. Its pointers aren't published outside the .CT file.
- [Steam thread on a shard overflow](https://steamcommunity.com/app/2420110/discussions/0/4292566649770339762):
  a shard total pushed past the limit displayed as about −2,147,4xx,xxx. So shards are a **signed 32-bit** count.

## Why addresses change and what doesn't

| Layer | Changes between game launches? | Changes between game patches? |
|---|---|---|
| Absolute heap address of any value | **yes** (fresh allocations + ASLR) | yes |
| Module base (`HorizonForbiddenWest.exe`) | yes (ASLR) | — |
| Code/data RVAs, AOB signatures | no | RVAs yes; signatures usually not |
| Class layouts (field offsets) | no | occasionally |
| RTTI class + field **names** | no | rarely |
| Item resource **GGUUIDs** | no | no (asset identity) |

So the durable way to find a value is to navigate by RTTI names and item UUIDs. That's what
`decima.py` does. Raw scan addresses (`address` in the table) only live for one session.

## RTTI: from an object to its class and fields

Every engine object's vtable slot 0 is `GetRTTI()`, compiled as
`48 8D 05 <disp32> C3` (`lea rax,[rip+RTTI]; ret`). The RTTI record:

```
RTTI           +0x04 u8 kind (0 atom, 1 pointer, 2 container, 3 enum, 4 compound)
RTTICompound   +0x06 u8 base_count   +0x07 u8 attr_count
               +0x40 char* type_name
               +0x58 Base* bases     {RTTI* type; u32 offset}         (0x10 each)
               +0x60 Attr* attrs     (0x38 each)
Attr           +0x00 RTTI* type (null = category header)  +0x08 u16 offset  +0x0A u16 flags
               +0x10 char* name  +0x18 getter  +0x20 setter (non-null = property, no storage)
RTTIAtom/Enum  +0x10 char* type_name
Container/Ptr  +0x18 char* full_type_name
```

To find the live instances of a class *by name*, without any hard-coded address:
1. find `"<Name>\0"` in the module image,
2. find the 8-byte pointer to it at RTTI+0x40 (with kind == 4 at RTTI+4),
3. find the `lea rax,[rip+RTTI]; ret` stub that targets it,
4. find vtables whose slot 0 points to that stub,
5. scan writable heap memory for objects whose first 8 bytes equal the vtable.

## Player data path (v1.5.80.0 layouts; each offset is checked and searched if wrong)

```
PlayerGame / Player     +0x48  Entity*
Entity                  +0xA0  Array<EntityComponent*>  {i32 len; i32 max; T* data}
                        +0xD0  Destructibility*  (health, m_Invulnerable @+0x70, m_DieAtZeroHealth @+0x71)
EntityComponent         +0x48  Entity* owner
Inventory (component)   +0x60  HashMap<GGUUID, InventoryItem*> {Assoc* data; i32 num; i32 cap}
  Assoc (0x20)          +0x00 GGUUID key  +0x10 InventoryItem*  +0x18 i32 hash (0 = empty slot)
InventoryItem           +0x48  StreamingRef<EntityResource> -> proxy -> locator
                                 locator: +0x10 GGUUID resource id, +0x20 resource object
                        +0x50  u32 amount
                        +0x58  Entity* owner
Decima String           char* data; u32 length at data-8
```

Metal Shards appear to be an `InventoryItem` like any other resource (as in Horizon Zero Dawn). The
32-bit overflow report fits the `u32 amount` at +0x50. Stack limits come from the item's resource, so
the game may clamp or reject values above its maximum. Values near 2^31 overflow.

The mod also adds items through `Inventory::AddItem` (a game function call). An external tool can only
change amounts of items **already in the inventory**. Getting one of a new resource first (pick one up
or buy one) is enough.

## Save files (persistence across runs)

`%USERPROFILE%\[OneDrive\]Documents\Horizon Forbidden West Complete Edition\<SteamID64>\`
holds `autosaveN.dat`, `quicksaveN.dat`, `courtesysaveN.dat` and `profile.dat`. Layout observed
on build 1.0.38.0:

```
0x000  "GGDS"  u32 version=1  u32 data_hash (0x0644F4A9, same in every save)  u32 state_size  u32 thumb_size
0x014  description, NUL-padded: "To The Brink - Level 3 - 02:02:41"  (quest - level - play time)
0x194  state blob (state_size): starts "HRZ2-PCR 38/9660601 ..." build tag; mostly compressed
....   PNG thumbnail (thumb_size)
```

The state blob is compressed (entropy around 7.9), so a save editor isn't practical yet. Values change on load:
the game reads the save into **newly allocated** objects every launch. To keep an edit, change the live value,
then save in-game. The UUID/RTTI path finds the same values again after the next load.

## Version caveat

The local install is **v1.0.38.0**. Nukem9's offsets target **v1.5.80.0**. The RTTI walk doesn't depend on
offsets, and the fixed offsets have validators and fallback searches. If something still fails on 1.0.38,
`dump entity` / `dump <component>` shows the real layout.
