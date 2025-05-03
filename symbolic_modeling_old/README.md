# Symbolic Binary Behavior Analysis

A hybrid symbolic modeling system for analyzing binary behavior through bit-level and abstract execution.

## Overview

This project implements a symbolic execution engine that can model the behavior of x86-64 assembly instructions. The system supports both:

1. **Bit-level modeling** - For precise bit-by-bit operations
2. **Abstract modeling** - For higher-level reasoning about program state

The core functionality allows you to:
- Parse and model assembly instruction traces
- Apply and check symbolic constraints
- Create and explore branching execution paths
- Analyze memory access patterns

## Files

- **modeling.py**: Core implementation of the symbolic modeling engine
- **behavior_algebra_20250326_194917.txt**: Sample instruction trace in behavior algebra format
- **template.txt**: Example symbolic constraints to apply during execution

## Architecture

The system is built around several key components:

### SymbolicValue

Represents a value that may be either concrete or symbolic.

```python
class SymbolicValue:
    def __init__(self, value=None, symbolic=True, size=1, name=None):
        self.value = value      # Concrete value, if available
        self.symbolic = symbolic  # True if value is symbolic
        self.size = size        # Size in bytes
        self.name = name        # Symbolic variable name
```

### SymbolicEnvironment

Models the execution environment including:
- Register file (both bit-level and abstract)
- Flags
- Memory
- Execution constraints

The environment supports both bit-level operations (for precise modeling) and abstract operations (for reasoning at a higher level).

### Behavior Algebra Parser

Processes a behavior algebra expression like:
```
B(401000) = sub(401000).mov(401004).test(40100b).B(40100e)
```

Converting it into a sequence of instructions that can be executed by the symbolic engine.

## Usage

### Basic Usage

```python
from modeling import SymbolicEnvironment, SymMod, parse_behavior_file

# Read behavior trace
with open('behavior_algebra_20250326_194917.txt', 'r') as f:
    behavior_content = f.read()

# Parse into instruction trace
instruction_trace = parse_behavior_file(behavior_content)

# Define a template with constraints
template = """
a1.X1;a2.X2
a1: Mem(i) != 0
a2: FLAGS[0] == 0
"""

# Run symbolic modeling
result_env = SymMod(instruction_trace, template)

# Examine the final state
if result_env:
    result_env.print_state()
```

### Defining Templates and Constraints

Templates identify points in the execution where constraints should be applied:

```
a1.X1;a2.X2      # Points in execution
a1: Mem(i) != 0  # Memory constraint
a2: FLAGS[0] == 0 # Flag constraint
```

Where:
- `a1`, `a2` are labels referencing execution points
- `X1`, `X2` are placeholder variables
- Constraints are expressed as conditions on memory or flags

## Examples

### Example 1: Checking Memory Access Patterns

```python
# Template that checks if memory at index i is non-zero
# and if the carry flag is zero after operation a2
template = """
a1.X1;a2.X2
a1: Mem(i) != 0
a2: FLAGS[0] == 0
"""

result = SymMod(trace, template)
```

### Example 2: Manual Bit-Level Operations

```python
# Create environment
env = SymbolicEnvironment()

# Set register values
env.set_register('RAX', 0x1234)
env.set_register('RBX', 0x5678)

# Perform bit-level add
env.sym_add_reg_reg('RAX', 'RBX')

# Check flags
cf = env.get_flag('CF')
print(f"Carry flag: {cf}")
```