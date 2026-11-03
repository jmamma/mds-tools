# mds-tools

Tools for building and certifying USR Machines for the Machinedrum,
following the [MDS specification](https://github.com/jmamma/MDS).

## Tools

This repository contains:

- `mds_pack.py` builds an MDS file from a JSON definition and assembled
  CLD, LOD or raw binary input, with optional certification.
- `mds-certifier` checks execution and measures MKI/MKII cycle costs,
  and MKI's with the program in SRAM.
- `mds_to_syx.py` converts an MDS file to MIDI SysEx for a selected USR slot.

## Build

```sh
git clone --recurse-submodules https://github.com/jmamma/mds-tools.git
cd mds-tools
cmake -S . -B build
cmake --build build -j
```

## Usage

Package an assembled program, certify it and convert it to SysEx:

```sh
python3 tools/mds_pack.py machine.json machine.lod --certify -o machine.mds
python3 tools/mds_to_syx.py machine.mds --slot 1 -o machine.syx
```

`--certify` runs the built certifier and stamps the measured cycle costs.
Omitting it produces an uncertified file and a warning. Add `--report FILE`
to save the certification report, or `--certifier PATH` to select an executable.

For raw binary input, use `--symbols FILE` to provide a JSON map of labels
to program-word offsets. Run either Python script with `--help` for options.

Check an existing MDS SysEx file without changing it:

```sh
build/mds-certifier machine.syx
```

For fast feedback while authoring, run `build/mds-certifier --quick machine.mds`.
This checks a short development schedule and cannot certify or stamp a machine.
Use the default full check for release measurements.

[Standalone certifier usage](certifier/README.md).
The MDS repository contains the specification and example machines.

## Requirements

- Python tools: Python 3.10+; standard library only.
- Certifier build: C++17, CMake 3.18+ and `patch`.
- Source assembly: Motorola/Freescale's [asm56300](https://www.nxp.com/docs/en/reference-manual/DSPASMRM.pdf),
  or a compatible DSP56300 assembler.
- CLD conversion: Motorola/Freescale's `cldlod`. LOD and raw binary input do not require it.
- Windows assembler or converter on macOS/Linux: [Wine](https://www.winehq.org/).
