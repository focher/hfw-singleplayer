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

Finding a value (example: Metal Shards) inside the shell:

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
`show`, `unfreeze NAME`, `quit`. Outside the shell: `hfw-trainer show` and `hfw-trainer set NAME VALUE`.

## Address table — `tables/hfw.json`

Each entry has a `name`, `category`, value `type` (`i32`, `f32`, …) and one way to locate it:

| field     | meaning                                                            | survives restart |
|-----------|--------------------------------------------------------------------|------------------|
| `aob`     | byte signature in `module`; `rip: [disp_offset, instr_len]` to follow a RIP-relative operand | yes |
| `base`    | static offset from `module` base                                   | until game patch |
| `address` | absolute address bound from a scan                                 | no               |

`offsets` then walks a pointer chain (`addr = *addr + off` per step). Absolute addresses
change every launch; promote them to an `aob` + `offsets` chain for a durable table.

## Layout

- `src/hfw_trainer/process.py` — Win32 attach, modules, memory regions, typed read/write
- `src/hfw_trainer/scanner.py` — first/next value scans, AOB signature scans
- `src/hfw_trainer/table.py` — address table, pointer-chain resolution, value freezer
- `src/hfw_trainer/cli.py` — CLI and interactive shell

## Roadmap

- Unknown-initial-value scans (snapshot + changed/unchanged) and float tolerance scans
- Pointer-scan helper to turn bound addresses into stable chains
- Inventory struct mapping (item ID → count) for bulk resource edits

## Notes

Single-player use only. Back up your save before writing values.
