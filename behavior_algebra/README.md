# Behavior Algebra Disassembler

A Python package for disassembling binary files and generating behavior algebra expressions that represent program control flow.

## Features

- Disassemble binary files using either:
  - The powerful [angr](https://github.com/angr/angr) framework (for advanced analysis)
  - Direct objdump integration (for faster, simpler analysis)
- Generate behavior algebra expressions from disassembled instructions
- Export control flow graphs (CFG) in JSON format for further analysis
- Google Colab integration for easy web-based analysis

## Installation

```bash
# Clone the repository
git clone https://github.com/smander/binary-algebra
cd binary-algebra

# Install the package
pip install -e .
```

## Command-Line Usage

```bash
# Generate behavior algebra (basic usage with angr)
behavior-algebra /path/to/binary

# Use objdump instead of angr
behavior-algebra /path/to/binary --objdump

# Specify output file
behavior-algebra /path/to/binary --output /path/to/output.txt

# Export CFG in JSON format
behavior-algebra /path/to/binary --format cfg-json --output /path/to/cfg.json

# Highlight specific addresses in CFG
behavior-algebra /path/to/binary --format cfg-json --highlight "401000,401050"
```

## Python API Usage

```python
from behavior_algebra import disassemble_binary, generate_behavior_algebra

# Just disassemble a binary with angr (default)
assembly = disassemble_binary("/path/to/binary")
print(assembly)

# Use objdump instead of angr
assembly = disassemble_binary("/path/to/binary", use_objdump=True)

# Generate behavior algebra and save to file
generate_behavior_algebra(assembly, "output.txt")

# Or use the all-in-one process function
from behavior_algebra.disassembler import process_binary
process_binary("/path/to/binary", "output.txt")

# Export control flow graph as JSON
from behavior_algebra.disassembler import export_cfg_json, get_angr_cfg
cfg_analysis = get_angr_cfg("/path/to/binary")
export_cfg_json(cfg_analysis, "cfg.json")
```

## Google Colab Integration

You can use this tool directly in Google Colab without any local installation:

1. Open the [Binary Algebra Colab Notebook](https://colab.research.google.com/github/smander/binary-algebra/blob/main/Binary_Algebra.ipynb)
2. Upload your binary file or use the provided sample
3. Run the analysis and export the results

## Behavior Algebra Format

The tool generates behavioral expressions in the following format:

- `B(addr)` - Represents the behavior starting at address `addr`
- Sequential instructions: `instr1(addr1).instr2(addr2).B(next_addr)`
- Conditional jumps: `jcc(addr).B(dest) + !jcc(addr).B(fallthrough)`
- Function calls: `B(addr) = B(dest); B(return_addr)`

Example output:
```
B(401000) = mov(401000).sub(401003).B(401006),
B(401006) = jz(401006).B(401050) + !jz(401006).B(401008),
B(401008) = add(401008).cmp(40100b).B(40100e),
```

## Control Flow Graph JSON Format

The CFG JSON export provides a structured representation of the program's control flow:

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
        },
        {
          "address": "0x401007",
          "mnemonic": "cmp",
          "operands": "rax, 0x10",
          "bytes": "483d10000000",
          "is_highlighted": false,
          "is_control_flow": false
        }
      ],
      "is_highlighted": false
    },
    {
      "address": "0x40100d",
      "instructions": [
        {
          "address": "0x40100d",
          "mnemonic": "je",
          "operands": "0x401020",
          "bytes": "7411",
          "is_highlighted": false,
          "is_control_flow": true
        }
      ],
      "is_highlighted": false
    }
  ],
  "edges": [
    {
      "source": "0x401000",
      "target": "0x40100d",
      "type": "sequential"
    },
    {
      "source": "0x40100d",
      "target": "0x401020",
      "type": "conditional_jump"
    },
    {
      "source": "0x40100d",
      "target": "0x40100f",
      "type": "sequential"
    }
  ],
  "metadata": {
    "total_nodes": 10,
    "total_edges": 12,
    "highlighted_addresses": ["0x401020"]
  }
}
```

### JSON Format Details

The JSON CFG format contains three main sections:

1. **nodes**: Array of basic blocks in the control flow graph
   - `address`: Hexadecimal address of the first instruction in the block
   - `instructions`: Array of instructions in the block
     - `address`: Hexadecimal instruction address
     - `mnemonic`: Instruction mnemonic (e.g., "mov", "call", "jmp")
     - `operands`: Instruction operands as a string
     - `bytes`: Hexadecimal representation of the instruction bytes
     - `is_highlighted`: Boolean indicating if this instruction is highlighted
     - `is_control_flow`: Boolean indicating if this is a control flow instruction
   - `is_highlighted`: Boolean indicating if any instruction in the block is highlighted

2. **edges**: Array of control flow transitions between blocks
   - `source`: Hexadecimal address of the source block
   - `target`: Hexadecimal address of the target block
   - `type`: Type of edge (one of "sequential", "conditional_jump", "unconditional_jump", or "call")

3. **metadata**: Additional information about the CFG
   - `total_nodes`: Total number of nodes in the graph
   - `total_edges`: Total number of edges in the graph
   - `highlighted_addresses`: Array of highlighted addresses (in hexadecimal)
```

## Virtual Environment Setup

When using macOS or other protected environments, it's recommended to use a virtual environment:

```bash
# Create a virtual environment
python3 -m venv venv

# Activate the virtual environment
source venv/bin/activate

# Install dependencies
pip install angr

# Now you can run the disassembler
python behavior_algebra/disassembler.py /path/to/binary
```

## Requirements

- Python 3.6+
- angr (automatically installed as a dependency for CFG generation)
- binutils (for objdump functionality when angr is not available)

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.