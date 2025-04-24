# Behavior Algebra Slicing Algorithm

This repository contains an implementation of a behavior algebra slicing algorithm that identifies slices in behavior equations based on specified instruction patterns.

## Overview

The algorithm analyzes behavior equations in the format of control flow algebra and extracts slices that match specified patterns of instructions (like "mov.X1;ret.X2"). This tool is useful for:

- Understanding control flow patterns in binary code
- Isolating specific behaviors in large codebases
- Analyzing instruction sequences across multiple functions

## Algorithm Description

The algorithm follows these main steps:

1. **Instruction Identification**: Finds all behaviors containing each instruction in the pattern
2. **Control Flow Analysis**: Builds a graph representing control flow between behaviors
3. **Path Finding**: Discovers paths through the control flow where instructions appear in the specified sequence
4. **Slice Construction**: Creates a slice containing behaviors that form these paths

## Usage

```bash
python slicer.py <behavior_algebra_file> <pattern>
```

Example:
```bash
python slice_builder.py behavior_algebra_20250326_194917.txt "mov.X1;ret.X2"
```

### Pattern Format

Patterns specify instruction sequences using the following format:
- Instructions separated by "." or ";"
- Optional placeholder variables (X1, X2, etc.)

Examples:
- `mov.X1;ret.X2` - Find paths where mov instructions lead to ret instructions
- `push.X1;call.X2;pop.X3` - Find sequences of push, call, and pop instructions

## Implementation Details

The implementation includes:

- Non-recursive control flow tracing (avoids stack overflow for large files)
- Proper normalization of behavior references
- Breadth-first search with depth limiting for efficient path finding
- Sampling strategy to handle large behavior sets

## File Format

The behavior algebra file should contain equations in the following format:

```
B(401000) = sub(401000).mov(401004).test(40100b).B(40100e)
B(40100e) = je(40100e).B(0x401012) + !je(40100e).B(401010)
...
```

Each equation specifies a behavior (left side) and its definition (right side), which can include:
- Instructions like mov(addr), ret(addr)
- References to other behaviors: B(addr)
- Control flow operators: ".", ";", "+"

## Output

The algorithm produces:
1. A list of behaviors with each instruction type
2. Paths found through the control flow
3. A slice containing relevant behaviors
4. A text file with the complete slice

## Performance Considerations

For large behavior algebra files:
- The algorithm samples behaviors rather than exhaustively checking all combinations
- A depth limit prevents excessive searching
- Visited tracking prevents cycles in the control flow graph

## Requirements

- Python 3.6 or higher
- No external dependencies