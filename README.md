# hfw-trainer

A Windows 11 tool that attaches to the running PC version of **Horizon Forbidden West**
(`HorizonForbiddenWest.exe`) to find and edit currency, inventory/resources and
character stats in memory, so you can skip resource grinding in the single-player game.

Pure Python (stdlib `ctypes` only), no third-party runtime dependencies.

## Setup

```bash
python -m pip install -e .[dev]
```

Run your terminal **as Administrator** if attaching fails with "Access is denied".

## Usage

```bash
hfw-trainer status
```

```bash
hfw-trainer shell
```

### Recommended: navigate by game RTTI (survives restarts)

The game carries runtime type info for every object, so the tool finds the player,
their components and their inventory **by class name**, with no fixed addresses
(details in [docs/RESEARCH.md](docs/RESEARCH.md)). With a save loaded:

```
hfw> components                         # player entity's components (first call scans the heap, ~10-30 s)
hfw> inventory shard                    # amount, name, resource UUID of matching items
hfw> item "Metal Shards" 99999          # set an item's amount (name substring or UUID)
hfw> track "Metal Shards"               # store the item's UUID in the table
hfw> dump Destructibility health        # named fields + live values of a component
hfw> field Destructibility Health       # store a component field in the table
hfw> freeze Health                      # keep it pinned
hfw> save
```

You can only change amounts of items you already hold (pick up or buy one first).
Save in-game afterwards so the change ends up in your save file.

### Fallback: classic value scan (this session only)


```
hfw> scan i32 1520          # your current shard count
hfw> next eq 1490           # after spending 30 shards in game
hfw> list                   # a handful of candidates left
hfw> poke 0 99999           # check the in-game counter changes
hfw> bind 0 "Metal Shards"  # attach the address to the table entry
hfw> freeze "Metal Shards"  # or: set "Metal Shards" 99999
hfw> save
```

Other commands: `next changed|unchanged|increased|decreased|gt|lt|ne`, `aob "48 8B 05 ?? ?? ?? ??"`,
`show`, `unfreeze NAME`, `quit`. Outside the shell: `hfw-trainer show`, `set NAME VALUE`, `inventory [FILTER]`,
`components`, `dump COMPONENT [FILTER]`.

## Address table — `tables/hfw.json`

Each entry has a `name`, `category`, value `type` (`i32`, `f32`, …) and one way to locate it:

| field     | meaning                                                            | survives restart |
|-----------|--------------------------------------------------------------------|------------------|
| `item`    | inventory item by resource UUID (or name substring); value = amount | yes (UUIDs are permanent) |
| `component` + `field` | named field on a player component, e.g. `Destructibility` / `Health` | yes |
| `aob`     | byte signature in `module`; `rip: [disp_offset, instr_len]` to follow a RIP-relative operand | yes |
| `base`    | static offset from `module` base                                   | until game patch |
| `address` | absolute address bound from a scan                                 | no               |

`offsets` then walks a pointer chain (`addr = *addr + off` per step). Absolute addresses
change every launch; promote them to an `aob` + `offsets` chain for a durable table.

## Layout

- `src/hfw_trainer/process.py` — Win32 attach, modules, memory regions, typed read/write
- `src/hfw_trainer/decima.py` — Decima RTTI reader: class/field names, instance search, player inventory
- `src/hfw_trainer/scanner.py` — first/next value scans, AOB signature scans
- `src/hfw_trainer/table.py` — address table, pointer-chain resolution, value freezer
- `src/hfw_trainer/cli.py` — CLI and interactive shell

## Roadmap

- Unknown-initial-value scans (snapshot + changed/unchanged) and float tolerance scans
- Pointer-scan helper to turn bound addresses into stable chains
- Verify RTTI layouts on game build 1.0.38.0 (offsets come from v1.5.80.0)
- Offline UUID → display-name map (via ShadelessFox/decima) for nicer item names

## Notes

Single-player use only. Back up your save before writing values.
