# mds-certifier

Certifies USR Machines against the MDS specification and measures their cycle costs for MKI and MKII.

From the repository root:

```sh
build/mds-certifier machine.syx
build/mds-certifier --stamp certified.mds --json report.json machine.mds
```

SysEx checks include packet integrity and declared cycle costs. MKII-only
stamps need remeasurement with `--stamp`; its output is an `.mds` file.

Stamps include MKII, MKI DRAM and MKI SRAM cycle counts.

[Build instructions](../README.md). Run without arguments to list options.

## Fast development checks

```sh
build/mds-certifier --quick machine.mds
build/mds-certifier --quick --json development.json machine.mds
```

`--quick` gives authors bounded execution feedback. It runs the distinct
default, minimum and maximum parameter vectors for four blocks each: assignment
and initial trigger at block 0, retrigger at block 2, and a following render at
block 3. It checks one DRAM and one SRAM program placement, all sixteen tracks,
and both initial register/memory patterns. Applicable tempo, repeat-trigger and
non-UW/MKI UW/MKII UW sample-service profiles still run. Memory permissions,
register preservation, control-flow restrictions, complete output writes and
comparison between initialization patterns use the same checks as certification.

A zero exit status means those development checks passed. Output is labelled
`DEVELOPMENT ONLY`; an optional JSON report always has `"certified": false`,
`"scope": "development_only"`, and a `development_checks_passed` boolean.
Reported cycles are observations from this short schedule, not release maxima.
SysEx packet integrity is checked, but release cycle declarations are not verified.
`--quick --stamp` and `--quick --loops` are rejected before writing any output.

Quick checks omit additional parameter combinations, placement offsets and long
running state (including the full RAM-service lifetime). They cannot establish
release safety or cycle budgets. Run the default full check before publication;
its schedule, report format and stamping behavior are unchanged. Quick mode
ignores the `MDS_CERTIFIER_BLOCKS` and `MDS_CERTIFIER_PLACEMENTS` diagnostic
schedule overrides so its execution schedule stays bounded.

## Files and runtime

The standalone executable writes only the requested `--stamp` output and
optional `--json` report. It does not retain instruction traces or memory
dumps. Working state is kept in process memory and released after the run.
The packer's temporary input, stamped output and report are cleaned up by
its temporary-directory context. There is no automatic on-disk certification
cache in the standalone CLI. Build-system caches are separate.

Full measurements can take minutes for a complex machine. A normal check
runs one machine serially; the firmware release builder can certify several
machines concurrently and reuse unchanged certificates. `--loops` is a fast
DO-loop inspection only; it neither certifies a machine nor writes stamps.
