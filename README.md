<p align="center">
  <a href="https://github.com/brunonlinespace/brunonlinespace/blob/main/linspectacles/coredumps-inspector.png">
    <img
      src="https://raw.githubusercontent.com/brunonlinespace/brunonlinespace/main/linspectacles/coredumps-inspector.png"
      alt="Coredumps Inspector screenshot"
      width="900"
    >
  </a>
</p>

# Coredumps Inspector

**Expose. Explore. Explain.**

Coredumps Inspector is a read-only inspector for coredump records visible through `systemd-coredump` / `coredumpctl`.

Current release: **0.0.9**

Repository: <https://github.com/linspectacles/coredumps-inspector>

## What Coredumps Inspector is

Coredumps Inspector answers a focused question: **what coredump records are visible to the current user, and what metadata does systemd report for each record?**

Coredumps Inspector is inspired in part by the crash-diagnostics role of **Microsoft Sysinternals ProcDump**, but its scope is intentionally different: LinSpectacles does **not create dumps** here; it only inspects coredump records already managed by `systemd-coredump`.

It keeps acquisition and interpretation close to the Linux interfaces actually used by the applet. When a source is unavailable, restricted, or does not report a field, the README does not imply that the applet can manufacture the missing information.

## Highlights

- Machine-readable inventory from `coredumpctl --no-pager --json=short --reverse list`.
- Normalized presentation fields include time, PID, UID, GID, signal, core-file state, executable and size where reported.
- Compatibility handling recognizes corresponding `COREDUMP_*` journal-field names when encountered.
- Metadata Details retains the normalized inventory fields plus every key/value returned in the record's JSON object.
- Records are not assumed to belong to the current boot.

## Data sources and acquisition

- `coredumpctl --no-pager --json=short --reverse list`.
- Journal visibility as granted to the current user through `coredumpctl`.

The applet uses those sources according to the acquisition paths implemented in this release. Optional tools or privileged helpers only affect the views/actions that explicitly use them; they are not treated as silent substitutes for unrelated sources.

## Interface

Coredumps Inspector follows the LinSpectacles inventory + **Metadata Details** pattern where applicable: an acquired inventory remains separate from the details for the selected record, and search/filter controls operate on the data the applet has actually collected.

The applet's **Options** surface provides the presentation/source/about controls implemented by this release, together with export controls where present in the source. Applet-specific actions remain explicit rather than being folded into background collection.

## Read-only and scope boundaries

The applet does not retrieve or modify the core image, delete coredumps, invoke a debugger, create dumps or change `systemd-coredump` configuration. Visibility is limited to records the current user is allowed to see.

## Running from source

The supplied source is directly runnable on Linux. The Python-side requirements are:

- Python 3.
- PyQt6 for the graphical interface.

Create a local virtual environment if you do not already have the required Python packages in the environment you want to use:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install PyQt6
python3 linspectacles_coredumps_inspector/standalone.py
```

Linux commands, procfs/sysfs interfaces, system services, or optional helpers mentioned in **Data sources and acquisition** are applet-specific runtime inputs. A missing optional source is handled by the applet's existing availability/error path; it is not replaced here with an invented dependency or capability.

No RPM installation instructions are included in this README.

## Source layout and LinSpectacles integration

The applet source is contained in:

```text
linspectacles_coredumps_inspector/
├── __init__.py
├── standalone.py
├── LICENSE
├── applet.json
├── README.md
└── coredumps_inspector/
    ├── __init__.py
    ├── applet.py
    ├── _support.py
    └── icon.png
```

`applet.json` supplies the LinSpectacles applet identity and entrypoint metadata. `standalone.py` launches the applet directly, while the package's applet factory provides the host-loadable LinSpectacles integration used by the source.

## Configuration

Presentation and inspection preferences are persisted only through the settings mechanisms already implemented by the applet. Persisted UI state does not grant the applet permission to modify the inspected Linux subsystem.

## Scope

Coredumps Inspector is intentionally specialist. Related Linux information that belongs to another LinSpectacles subsystem remains outside this applet rather than being inferred or duplicated here.

## License

GNU General Public License v3.0 or later. See [`LICENSE`](LICENSE).

## Links

- LinSpectacles organisation: <https://github.com/linspectacles/>
- Repository: <https://github.com/linspectacles/coredumps-inspector>
- Issues: <https://github.com/linspectacles/coredumps-inspector/issues>

<p align="center">
  <a href="https://github.com/linspectacles/coredumps-inspector">
    <img
      src="coredumps_inspector/icon.png"
      alt="Coredumps Inspector"
      width="256"
    >
  </a>
</p>
