
# dynint

`dynint` provides a two-mode toolkit for Linux ELF binaries:

- `dynmap` — a static analyzer that enumerates functions, basic blocks, PLT callsites, and dynamic dependencies without executing the binary.
- `dyntrace` — a dynamic tracer built on Frida that focuses on third-party library entrypoints and the corresponding application callsites.

The modules share utilities for address rebasing and map handling so you can correlate runtime events with the static view of the binary.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install .[analysis]
```

Key dependencies:

- [`pyelftools`](https://github.com/eliben/pyelftools) for ELF and DWARF parsing.
- [`capstone`](http://www.capstone-engine.org/) (via the `analysis` extra) for disassembly and basic-block recovery.
- [`frida`](https://frida.re/) for runtime instrumentation (`dyntrace`).

> **Note:** `dyntrace` currently uses the Frida backend. Slots are reserved for BCC and Dyninst backends in the CLI, but they are not implemented yet.

## Static analysis (`dynmap`)

Generate a complete static map for an ELF binary:

```bash
# minimal output (functions + callsites + DT_NEEDED)
dynint map ./bin/app -o map.json

# include DWARF file:line info and callsite bytes
dynint map ./bin/app -o map.json --with-dwarf --bytes
```

The resulting `map.json` contains:

- `binary`: PIE flag, static image base, entry point, and absolute path.
- `functions`: per-function records with symbol binding, size, and basic blocks (successor graph derived from Capstone).
- `callsites`: every call instruction discovered via disassembly. PLT calls include the resolved symbol and PLT thunk address.
- `libraries`: `DT_NEEDED` entries plus any version requirements discovered in `.gnu.version_r`.
- `symbol_versions`: version-qualified export names such as `recvfrom@@GLIBC_2.2.5`, which is useful when resolving symbols with `dlvsym` at runtime.

### Basic-block coverage

`dynmap` disassembles all executable sections and builds a conservative control-flow graph. If Capstone is not available or the architecture is unsupported, it gracefully falls back to symbol-level mapping (one block per function) after warning.

### Flags

- `--only-extern-calls`: limit callsite emission to PLT calls (useful for library boundary reviews).
- `--with-dwarf`: enrich callsites with `file:line` information when DWARF debug info is present.
- `--bytes`: include the raw opcode bytes for each callsite (helpful for forensic triage).

## Dynamic tracing (`dyntrace`)

Attach to a running PID or spawn a new process under instrumentation:

```bash
# Attach to an existing PID, tracing libc recv/send callsites
dynint trace --pid 4321 --map map.json --lib libc.so.6 --fn recvfrom --fn send

# Spawn a process and trace every PLT call into libssl
dynint trace --spawn ./bin/app --map map.json --lib libssl.so --sample 1/10
```

### How it works

1. The tracer loads `map.json` and selects target functions:
   - User-specified `--fn` values are respected (`lib:fn` is supported for explicit scoping).
   - Otherwise, every PLT call in the map contributes a symbol to hook.
2. `/proc/<pid>/maps` is parsed to compute runtime base addresses (handles PIE/ASLR).
3. Frida installs hooks:
   - Exported functions in the selected libraries (`Module.findExportByName`).
   - Optional PLT callsites (static addresses are re-based to runtime).
4. Runtime events are streamed as JSONL to stdout or `--output`. Each record includes timestamp, pid/tid, function/library, arguments (stringified pointers), return value, and latency. When possible, callsite metadata (`function`, `file`, `line`) is attached by correlating the return address back through `map.json`.
5. Sampling (`--sample 1/100`) is applied in Python to avoid hot-path logging overhead. `--since` and `--duration` offer temporal controls.

### Output example

```json
{"ts": 1715091021.612, "kind": "function", "function": "recvfrom", "library": "libc.so.6", "args": ["0x7ffc1b4b0bf0", "0x200", "0", "0x0", "0x0", "0x0"], "ret": "128", "duration": 0.00041, "tid": 43901, "pid": 4321, "callsite": {"callsite": "0x4011d5", "function": "net_loop", "file": "src/net.c", "line": 118, "target": "recvfrom"}}
```

### Permissions

Frida can attach without root when the target process is owned by the current user. For system libraries (e.g., glibc) this is usually sufficient. For BCC/eBPF-style tracing or to inspect other users' processes, root access would be required—those backends are planned but not yet implemented.

## Shared utilities (`addrutils`)

The `addrutils` module offers:

- `/proc/<pid>/maps` parsing into typed entries (`start`, `end`, permissions, pathname...).
- Address rebasing helpers for PIE-aware translation between static and runtime addresses.
- Convenience lookup for locating the mapping that hosts a specific soname.

These helpers are reused by both the static and dynamic components to stay consistent about address arithmetic.

## Roadmap / Next steps

The CLI is structured to accept future backends:

1. **Dyninst backend** — reusing map metadata for instrumentation without Frida.
2. **BCC/eBPF backend** — high-throughput uprobes/uretprobes for hot libraries (OpenSSL, zlib, etc.).
3. Extended filtering: `--from-func`, `--lib-regex`, sliding-window sampling.
4. Metrics & observability: Prometheus exporter for event rates, queue depth, drops.
5. Additional forensic modes: `--sample-payload` to dump N bytes from pointer arguments.
