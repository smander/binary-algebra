# Behavior Algebra Disassembler

A Dyninst-backed Python module that disassembles binaries, exports control-flow metadata, and optionally emits behavior algebra expressions.

## Features

- Native [Dyninst](https://github.com/dyninst/dyninst) disassembly for accurate instruction streams and control-flow insight
- Optional behavior algebra generation that follows the original project semantics
- CFG export as structured JSON (basic blocks, instructions, edges, metadata)
- Command-line interface and lightweight Python API built around a single stateful class
- Optional `objdump` fallback for environments where Dyninst bindings are not available

## Requirements

- Python 3.8+
- Dyninst with Python bindings available on the system path
- (Optional) GNU binutils `objdump` if you enable the fallback mode

Ensure the `dyninst`, `ParseAPI`, and `InstructionAPI` Python modules from the Dyninst distribution are importable before using the package.

## Installation

```bash
# Clone the repository
git clone https://github.com/smander/binary-algebra
cd binary-algebra

# Install the package in editable mode
pip install -e .
```

If Dyninst is installed in a non-standard location, update `PYTHONPATH`/`LD_LIBRARY_PATH` accordingly so the Python bindings and shared libraries are discoverable.

## Command-Line Usage

```bash
# Generate behavior algebra (default)
behavior-algebra /path/to/binary

# Export CFG JSON instead of behavior algebra
behavior-algebra /path/to/binary --format json --output cfg.json

# Produce both artifacts at once
behavior-algebra /path/to/binary --format both --output behavior.txt --cfg-output cfg.json

# Disable algebra generation explicitly
behavior-algebra /path/to/binary --no-behavior-algebra --format json

# Highlight specific addresses in the CFG export
behavior-algebra /path/to/binary --format json --highlight "401000,401050"

# Allow objdump fallback if Dyninst bindings are missing
behavior-algebra /path/to/binary --allow-objdump-fallback
```

### CLI Options

- `--format {txt,json,both}`: Select the main artifact (`txt` for behavior algebra, `json` for CFG). `both` produces both outputs.
- `--output PATH`: Destination for the main artifact (behavior algebra when `txt`, CFG JSON when `json`).
- `--cfg-output PATH`: Optional explicit path for CFG JSON when producing both artifacts or when `--format txt`.
- `--no-behavior-algebra`: Disable algebra generation even if the format includes it.
- `--highlight ADDRS`: Comma-separated list of hex addresses highlighted in the CFG JSON.
- `--export-dir DIR`: Directory for default artifact locations when explicit paths are not given.
- `--allow-objdump-fallback`: Use `objdump -d` if Dyninst bindings are not importable.

## Python API Usage

```python
from behavior_algebra import DyninstDisassembler

analyzer = DyninstDisassembler(
    "/path/to/binary",
    behavior_algebra=True,
    cfg_json=True,
    highlight_addrs={0x401000},
    fallback_to_objdump=False,
)

# Trigger disassembly and collect artifacts
results = analyzer.run()
print(results)

# Access cached data directly
print(analyzer.disassembly_text)
print(analyzer.behavior_algebra)
print(analyzer.cfg)
```

Helper shims remain for compatibility:

```python
from behavior_algebra import disassemble_binary, generate_behavior_algebra

instructions = disassemble_binary("/path/to/binary")
algebra = generate_behavior_algebra("/path/to/binary")
```

## Behavior Algebra Format

The generator preserves the original textual representation:

- `B(addr)` indicates control flow rooted at `addr`
- Sequential instructions: `instr1(addr1).instr2(addr2).B(next_addr)`
- Conditional jumps: `jcc(addr).B(dest) + !jcc(addr).B(fallthrough)`
- Calls: `B(addr) = B(dest); B(return_addr)`
- Dynamic transfers are recorded via `B(DYNAMIC)` with comments summarising observed sites

Example output:

```
B(401000) = mov(401000).sub(401003).B(401006),
B(401006) = jz(401006).B(401050) + !jz(401006).B(401008),
B(401008) = add(401008).cmp(40100b).B(40100e),

# Dynamic (indirect) control flows:
B(DYNAMIC) = nop(DYNAMIC),
```

## Control Flow Graph JSON Format

`DyninstDisassembler` synthesises a compact CFG from the recovered instructions. The JSON document includes:

- `nodes`: Basic blocks with addresses, instruction payloads, highlighting, and control-flow flags
- `edges`: Relations between blocks labelled as `sequential`, `conditional_jump`, `unconditional_jump`, or `call`
- `metadata`: Node/edge counts and the list of highlighted addresses

Example structure:

```json
{
  "nodes": [
    {
      "address": "0x401000",
      "instructions": [
        {
          "address": "0x401000",
          "mnemonic": "mov",
          "operands": "rax, 0x1",
          "bytes": "48c7c001000000",
          "is_highlighted": false,
          "is_control_flow": false
        }
      ],
      "is_highlighted": false
    }
  ],
  "edges": [
    {
      "source": "0x401000",
      "target": "0x401006",
      "type": "sequential"
    }
  ],
  "metadata": {
    "total_nodes": 1,
    "total_edges": 1,
    "highlighted_addresses": []
  }
}
```

## Virtual Environment Setup

When working in a restricted environment (macOS, sandboxed CI, etc.), install Dyninst inside a virtual environment and update relevant paths:

```bash
python3 -m venv venv
source venv/bin/activate

# Install or build Dyninst so that ParseAPI/InstructionAPI are importable
pip install --no-deps dyninst  # if wheels are available, otherwise build from source
export PYTHONPATH="/path/to/dyninst/python:$PYTHONPATH"
```

## Fallback Mode

Enabling the `--allow-objdump-fallback` flag (or setting `fallback_to_objdump=True` in Python) lets the tool continue operating with GNU objdump when Dyninst bindings are missing. Expect reduced fidelity in the CFG because indirect control transfers cannot be resolved without Dyninst's analyses.

# CLI Command Reference

## Complete Test Commands for Behavior Algebra Disassembler

### Basic Usage Commands

```bash
# 1. Default behavior algebra generation
python3 disassembler.py data/demo_binary --allow-objdump-fallback

# 2. JSON CFG export only
python3 disassembler.py data/demo_binary --format json --allow-objdump-fallback

# 3. Both formats simultaneously  
python3 disassembler.py data/demo_binary --format both --allow-objdump-fallback

# 4. Custom output paths
python3 disassembler.py data/tiny_minimal --format both \
    --output custom_algebra.txt --cfg-output custom_cfg.json --allow-objdump-fallback

# 5. Export to specific directory
mkdir -p exports && python3 disassembler.py data/demo_binary \
    --format both --export-dir exports --allow-objdump-fallback
```

### Advanced Options

```bash
# 6. Disable behavior algebra generation
python3 disassembler.py data/demo_binary --no-behavior-algebra \
    --format json --allow-objdump-fallback

# 7. Highlight specific addresses in CFG
python3 disassembler.py data/demo_binary --format json \
    --highlight "1000,1010,1020" --output highlighted.json --allow-objdump-fallback

# 8. Short format flags
python3 disassembler.py data/demo_binary -f both -o output.txt --allow-objdump-fallback
```

### Error Handling Tests

```bash
# 9. Test with non-existent binary (should fail gracefully)
python3 disassembler.py /nonexistent/binary --allow-objdump-fallback

# 10. Test without fallback (should fail when Dyninst unavailable)
python3 disassembler.py data/demo_binary

# 11. Get help
python3 disassembler.py --help
```

### Validation Commands

```bash
# 12. Verify behavior algebra format
python3 disassembler.py data/demo_binary --allow-objdump-fallback
grep "B([0-9a-f]*) =" data/demo_binary_behavior_algebra.txt

# 13. Verify JSON structure
python3 disassembler.py data/demo_binary --format json --allow-objdump-fallback
python3 -c "import json; data=json.load(open('data/demo_binary_cfg.json')); print('Valid JSON with', len(data['nodes']), 'nodes')"

# 14. Verify highlighting works
python3 disassembler.py data/demo_binary --format json --highlight "1000,1010" \
    --output highlighted.json --allow-objdump-fallback
python3 -c "import json; data=json.load(open('highlighted.json')); print('Highlighted:', data['metadata']['highlighted_addresses'])"
```

### Performance Tests

```bash
# 15. Time large binary processing
time python3 disassembler.py data/caseSym --format txt --allow-objdump-fallback

# 16. Test multiple binaries in sequence
for binary in data/*; do 
    if [ -f "$binary" ]; then
        echo "Processing $binary..."
        python3 disassembler.py "$binary" --format txt --allow-objdump-fallback
    fi
done
```

### Python API Test Commands

```bash
# 17. Test class-based API
python3 -c "
import sys; sys.path.insert(0, '.')
from disassembler import DyninstDisassembler
d = DyninstDisassembler('data/demo_binary', fallback_to_objdump=True)
print('Instructions:', len(d.instructions))
print('Algebra length:', len(d.behavior_algebra))
"

# 18. Test export methods
python3 -c "
import sys; sys.path.insert(0, '.')  
from disassembler import DyninstDisassembler
d = DyninstDisassembler('data/demo_binary', behavior_algebra=True, cfg_json=True, fallback_to_objdump=True)
results = d.run(behavior_algebra_path='api_test.txt', cfg_path='api_test.json')
print('Exported:', list(results.keys()))
"
```

### Comprehensive Test

```bash
# 19. Run complete test suite
./test_cli.sh
```

## Expected Outputs

### Behavior Algebra Format
```
B(1000) = subq(1000).movq(1004).testq(100b).je(100e).B(1010),
B(1010) = callq(1010).B(1012),
B(1012) = addq(1012).retq(1016).B(1020),
...
# Dynamic (indirect) control flows:
B(DYNAMIC) = nop(DYNAMIC),
```

### CFG JSON Structure
```json
{
  "nodes": [
    {
      "address": "0x1000", 
      "instructions": [...],
      "is_highlighted": false
    }
  ],
  "edges": [
    {
      "source": "0x1000",
      "target": "0x1010", 
      "type": "sequential"
    }
  ],
  "metadata": {
    "total_nodes": 42,
    "total_edges": 61,
    "highlighted_addresses": []
  }
}
```

## Exit Codes

- `0`: Success
- `1`: Error (missing binary, Dyninst unavailable without fallback, invalid arguments)

## Notes

- Always use `--allow-objdump-fallback` unless testing Dyninst-specific behavior
- Generated files use binary name + suffix by default (e.g., `demo_binary_behavior_algebra.txt`)
- Highlighting accepts hex addresses with or without `0x` prefix
- CFG export includes detailed instruction metadata and control flow analysis