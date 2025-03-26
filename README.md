# Behavior Algebra Disassembler

A Python package for disassembling binary files and generating behavior algebra expressions that represent program control flow.

## Features

- Disassemble binary files using the powerful [angr](https://github.com/angr/angr) framework
- Generate behavior algebra expressions from disassembled instructions
- Analyze control flow patterns and instruction sequences
- Command-line interface and programmatic API

## Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/behavior_algebra.git
cd behavior_algebra

# Install the package
pip install -e .
```

## Command-Line Usage

```bash
# Basic usage
behavior-algebra /path/to/binary

# Specify output file
behavior-algebra /path/to/binary --output /path/to/output.txt
```

## Python API Usage

```python
from behavior_algebra import disassemble_binary, generate_behavior_algebra

# Just disassemble a binary
assembly = disassemble_binary("/path/to/binary")
print(assembly)

# Generate behavior algebra and save to file
generate_behavior_algebra(assembly, "output.txt")

# Or use the all-in-one process function
from behavior_algebra.disassembler import process_binary
process_binary("/path/to/binary", "output.txt")
```

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

## Requirements

- Python 3.6+
- angr (automatically installed as a dependency)

## Advanced Usage

### Custom Analysis Flow

```python
from behavior_algebra.disassembler import parse_instructions

# Use your own disassembly method
my_assembly = "401000: mov eax, ebx\n401002: add eax, 1"

# Parse into structured format
instructions = parse_instructions(my_assembly)

# Process further as needed
for instr in instructions:
    print(f"Address: {instr['address']}, Mnemonic: {instr['mnemonic']}")
```

## License

MIT

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.