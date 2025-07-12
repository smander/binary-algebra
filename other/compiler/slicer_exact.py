#!/usr/bin/env python3
import re
import sys
import os
from datetime import datetime
from collections import deque, defaultdict


def load_equations(file_path):
    """Load behavior equations from a file."""
    equations = {}
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            parts = line.split('=', 1)
            if len(parts) != 2:
                continue

            left = parts[0].strip()
            right = parts[1].strip()

            # Remove trailing comma if present
            if right.endswith(','):
                right = right[:-1]

            equations[left] = right

    print(f"Loaded {len(equations)} behavior equations")
    return equations


def parse_template(template):
    """Parse a template pattern into a sequence of instructions and wildcards."""
    # Custom parser to handle the pattern correctly
    parts = []
    current = ""

    for char in template:
        if char in ['.', ';']:
            if current:
                parts.append(current)
                current = ""
            parts.append(char)
        else:
            current += char

    if current:
        parts.append(current)

    sequence = []
    current_instr = None

    for i, part in enumerate(parts):
        if not part:
            continue

        if part[0].isalpha() and not part.startswith('X'):
            # This is an instruction
            if current_instr:
                sequence.append(current_instr)
            current_instr = {"type": part, "wildcard": False}
        elif part.startswith('X'):
            # This is a wildcard
            if current_instr:
                current_instr["wildcard"] = True
        elif part in ['.', ';'] and current_instr and i + 1 < len(parts) and parts[i + 1].startswith('X'):
            # This handles the case where we have a separator followed by a wildcard
            pass

    # Add the last instruction if it exists
    if current_instr:
        sequence.append(current_instr)

    print(f"Parsed template: {template}")
    print(f"Sequence: {[(s['type'], 'wildcard' if s['wildcard'] else 'exact') for s in sequence]}")

    return sequence


def parse_behavior_instructions(behavior_rhs):
    """Parse all instructions from a behavior RHS in order."""
    instructions = []
    
    # Split by '.' to get individual instruction calls
    parts = behavior_rhs.split('.')
    
    for part in parts:
        part = part.strip()
        if not part:
            continue
            
        # Match instruction patterns like "lea(100000d71)" or "B(0x100001948)"
        if part.startswith('B('):
            # This is a behavior call - treat as 'call' for pattern matching
            instructions.append({
                'type': 'call',
                'full': part,
                'address': part
            })
        else:
            # Regular instruction pattern
            match = re.match(r'([a-zA-Z0-9_]+)\(([^)]+)\)', part)
            if match:
                instr_type = match.group(1)
                addr = match.group(2)
                instructions.append({
                    'type': instr_type,
                    'full': part,
                    'address': addr
                })
    
    return instructions


def check_exact_sequence_match(behavior_rhs, template_sequence):
    """Check if behavior contains the exact consecutive sequence from template, with wildcard support."""
    # Parse all instructions in order
    instructions = parse_behavior_instructions(behavior_rhs)
    instruction_types = [instr['type'] for instr in instructions]
    
    print(f"  Checking sequence: {' -> '.join(instruction_types)}")
    template_display = []
    for item in template_sequence:
        if item.get('wildcard', False):
            template_display.append(f"{item['type']}.X")
        else:
            template_display.append(item['type'])
    print(f"  Looking for: {' -> '.join(template_display)}")
    
    # Look for matches with wildcard support
    for i in range(len(instruction_types)):
        match_result = try_match_from_position(instructions, i, template_sequence)
        if match_result[0]:  # Found a match
            matched_instructions, end_pos = match_result[1], match_result[2]
            print(f"  ✓ Found match at positions {i}-{end_pos}")
            for k, instr in enumerate(matched_instructions):
                print(f"    {k + 1}. {instr['type']}: {instr['full']}")
            return True, matched_instructions
    
    print(f"  ✗ No match found")
    return False, []


def try_match_from_position(instructions, start_pos, template_sequence):
    """Try to match template starting from a specific position in instructions."""
    matched_instructions = []
    current_pos = start_pos
    
    for template_idx, template_item in enumerate(template_sequence):
        template_type = template_item['type']
        has_wildcard = template_item.get('wildcard', False)
        
        # Check if we've run out of instructions
        if current_pos >= len(instructions):
            return False, None, None
        
        # Check if current instruction matches the template type
        if instructions[current_pos]['type'] == template_type:
            matched_instructions.append(instructions[current_pos])
            current_pos += 1
            
            # If this template item has a wildcard, skip any number of following instructions
            # until we find the next template item (or reach the end)
            if has_wildcard and template_idx < len(template_sequence) - 1:
                next_template_type = template_sequence[template_idx + 1]['type']
                
                # Skip instructions until we find the next template type
                wildcard_instructions = []
                while current_pos < len(instructions) and instructions[current_pos]['type'] != next_template_type:
                    wildcard_instructions.append(instructions[current_pos])
                    current_pos += 1
                
                # Add the wildcard instructions to our match
                matched_instructions.extend(wildcard_instructions)
                
                # Check if we found the next template type
                if current_pos >= len(instructions):
                    return False, None, None
        else:
            # No match at this position
            return False, None, None
    
    # Successfully matched all template items
    return True, matched_instructions, current_pos - 1


def find_exact_intra_behavior_patterns(equations, template_sequence):
    """Find all behaviors that contain the exact consecutive pattern within themselves."""
    instruction_types = [item["type"] for item in template_sequence]
    matching_behaviors = []
    
    print(f"Searching for EXACT consecutive intra-behavior patterns...")
    print(f"Looking for exact pattern: {' -> '.join(instruction_types)}")
    print(f"Total behaviors to check: {len(equations)}")
    
    for behavior, rhs in equations.items():
        print(f"\nChecking {behavior}:")
        has_pattern, matches = check_exact_sequence_match(rhs, template_sequence)
        if has_pattern:
            matching_behaviors.append((behavior, matches))
            print(f"✓ Found exact consecutive pattern in {behavior}")
    
    return matching_behaviors


def parse_objdump(file_path):
    """Parse an objdump output file to create a mapping of addresses to assembly instructions."""
    asm_map = {}

    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Match patterns like "100000d20: push rbp" 
            match = re.match(r'([0-9a-f]+):\s*(.*)', line)
            if match:
                addr_str = match.group(1)
                instruction = match.group(2).strip()

                try:
                    # Try as hex
                    addr = int(addr_str, 16)
                    asm_map[addr] = instruction
                except ValueError:
                    print(f"Warning: Could not parse address: {addr_str}")

    print(f"Loaded {len(asm_map)} assembly instructions from objdump")
    return asm_map


def convert_behavior_to_asm(behavior_rhs, asm_map):
    """Convert behavior RHS to assembly instructions using the address mapping."""
    if not asm_map:
        return []
    
    asm_instructions = []
    instructions = parse_behavior_instructions(behavior_rhs)
    
    for instr in instructions:
        try:
            if instr['type'] == 'call':
                # Handle call instructions - they may be B(0x...) format
                if instr['address'].startswith('0x'):
                    addr = int(instr['address'], 16)
                else:
                    addr = int(instr['address'], 16)
                    
                if addr in asm_map:
                    asm_instructions.append((addr, instr['type'], asm_map[addr]))
            else:
                # Regular instruction
                addr = int(instr['address'], 16)
                if addr in asm_map:
                    asm_instructions.append((addr, instr['type'], asm_map[addr]))
        except (ValueError, KeyError):
            continue
    
    return asm_instructions


def create_export_files(slice_equations, path_traces, template, asm_map, template_sequence):
    """Create export directory structure with organized output files."""
    
    # Create timestamp for unique directory names
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Create export directory structure
    base_dir = f"export_{template.replace('.', '_').replace(';', '_')}_{timestamp}"
    os.makedirs(base_dir, exist_ok=True)
    
    # Check if we have assembly data
    has_asm = asm_map is not None and len(asm_map) > 0
    
    # 1. Save path flows to a dedicated file
    path_flows_file = os.path.join(base_dir, "path_flows.txt")
    with open(path_flows_file, 'w') as f:
        f.write(f"# Path Flows for Template: {template}\n")
        f.write(f"# Export created: {datetime.now().isoformat()}\n")
        f.write(f"# Template type: EXACT CONSECUTIVE with wildcards\n\n")
        for i, trace in enumerate(path_traces):
            f.write(f"Path {i + 1}:\n{trace}\n\n")
    
    print(f"Path flows saved to {path_flows_file}")
    
    # 2. Save all behaviors to a separate file
    all_behaviors_file = os.path.join(base_dir, "all_behaviors.txt")
    with open(all_behaviors_file, 'w') as f:
        f.write(f"# All Behaviors for Template: {template}\n")
        f.write(f"# Export created: {datetime.now().isoformat()}\n")
        f.write(f"# Template type: EXACT CONSECUTIVE with wildcards\n\n")
        
        for behavior, rhs in slice_equations.items():
            f.write(f"{behavior} = {rhs}\n")
            
            # Add assembly if available
            if has_asm:
                asm_instructions = convert_behavior_to_asm(rhs, asm_map)
                if asm_instructions:
                    f.write("  # Assembly:\n")
                    for addr, instr_type, asm in asm_instructions:
                        addr_hex = f"0x{addr:x}" if isinstance(addr, int) else addr
                        f.write(f"  #   {addr_hex}: {asm}\n")
                f.write("\n")
    
    print(f"All behaviors saved to {all_behaviors_file}")
    
    # 3. Create subdirectory for each path trace with detailed analysis
    traces_dir = os.path.join(base_dir, "traces")
    os.makedirs(traces_dir, exist_ok=True)
    
    for i, path_trace in enumerate(path_traces):
        # Create directory for this trace
        trace_dir = os.path.join(traces_dir, f"trace_{i + 1}")
        os.makedirs(trace_dir, exist_ok=True)
        
        # Get behaviors in this path
        behaviors = path_trace.split(" -> ")
        
        # Create a file with the full trace behaviors
        trace_file = os.path.join(trace_dir, "trace_behaviors.txt")
        with open(trace_file, 'w') as f:
            f.write(f"# Full Trace {i + 1} Behaviors\n")
            f.write(f"# Template: {template}\n")
            f.write(f"# Path: {path_trace}\n\n")
            
            for behavior in behaviors:
                if behavior in slice_equations:
                    f.write(f"{behavior} = {slice_equations[behavior]}\n")
                    
                    # Add assembly if available
                    if has_asm:
                        asm_instructions = convert_behavior_to_asm(slice_equations[behavior], asm_map)
                        if asm_instructions:
                            f.write("  # Assembly:\n")
                            for addr, instr_type, asm in asm_instructions:
                                addr_hex = f"0x{addr:x}" if isinstance(addr, int) else addr
                                f.write(f"  #   {addr_hex}: {asm}\n")
                        f.write("\n")
        
        # Create a pattern analysis file
        pattern_file = os.path.join(trace_dir, "pattern_analysis.txt")
        with open(pattern_file, 'w') as f:
            f.write(f"# Pattern Analysis for Trace {i + 1}\n")
            f.write(f"# Template: {template}\n")
            f.write(f"# Type: EXACT CONSECUTIVE with wildcards\n\n")
            
            # Analyze the pattern in each behavior
            for behavior in behaviors:
                if behavior in slice_equations:
                    f.write(f"Behavior: {behavior}\n")
                    rhs = slice_equations[behavior]
                    instructions = parse_behavior_instructions(rhs)
                    
                    f.write(f"Instruction sequence: {' -> '.join([instr['type'] for instr in instructions])}\n")
                    
                    # Try to find the template pattern
                    template_types = [item['type'] for item in template_sequence]
                    f.write(f"Looking for pattern: {' -> '.join(template_types)}\n")
                    
                    # Check if this behavior contains the pattern
                    has_pattern, matches = check_exact_sequence_match(rhs, template_sequence)
                    if has_pattern:
                        f.write("✓ PATTERN FOUND:\n")
                        for j, match in enumerate(matches):
                            f.write(f"  {j + 1}. {match['type']}: {match['full']}")
                            if has_asm:
                                try:
                                    addr = int(match['address'], 16)
                                    if addr in asm_map:
                                        f.write(f" -> {asm_map[addr]}")
                                except:
                                    pass
                            f.write("\n")
                    else:
                        f.write("✗ Pattern not found in this behavior\n")
                    f.write("\n")
    
    print(f"Trace analysis saved to {traces_dir}/")
    print(f"Export completed in directory: {base_dir}")


def build_slice(equations_file, template, objdump_file=None):
    """Build a behavior slice based on a template pattern."""
    equations = load_equations(equations_file)

    # Load assembly mapping if objdump file is provided
    asm_map = None
    if objdump_file:
        asm_map = parse_objdump(objdump_file)
        print(f"Loaded assembly mapping with {len(asm_map)} instructions")

    # Parse the template into a sequence of instructions and wildcards
    template_sequence = parse_template(template)

    # Find exact consecutive patterns within single behaviors
    exact_patterns = find_exact_intra_behavior_patterns(equations, template_sequence)
    
    if exact_patterns:
        print(f"\n=== FOUND EXACT CONSECUTIVE PATTERNS ===")
        print(f"Found {len(exact_patterns)} behaviors containing the exact consecutive pattern:")
        
        all_paths = []
        for behavior, matches in exact_patterns:
            # Create a single-behavior path
            path = [behavior]
            all_paths.append(path)
            print(f"\n  Exact pattern in {behavior}:")
            for match in matches:
                print(f"    {match['type']}: {match['full']}")
                
                # If we have assembly mapping, show the assembly too
                if asm_map:
                    try:
                        addr_int = int(match['address'], 16)
                        if addr_int in asm_map:
                            print(f"      Assembly: {addr_int:x}: {asm_map[addr_int]}")
                    except ValueError:
                        pass
        
        valid_paths = all_paths
        
    else:
        print(f"\nNo exact consecutive patterns found within single behaviors")
        valid_paths = []

    print(f"\nFound {len(valid_paths)} behaviors with exact consecutive patterns")

    # Create path traces for output
    path_traces = []
    slice_behaviors = set()
    
    for path in valid_paths:
        path_trace = " -> ".join(path)
        path_traces.append(path_trace)
        print(f"Valid path: {path_trace}")
        
        for behavior in path:
            slice_behaviors.add(behavior)

    # Create slice equations
    slice_equations = {}
    for behavior in slice_behaviors:
        if behavior in equations:
            slice_equations[behavior] = equations[behavior]

    print(f"Built a slice with {len(slice_equations)} behaviors from {len(valid_paths)} paths")
    
    return slice_equations, path_traces, equations, asm_map, template_sequence


def main():
    if len(sys.argv) < 3:
        print("Usage: python slicer_exact.py <equations_file> <template> [<objdump_file>]")
        print("Example: python slicer_exact.py behavior_algebra.txt \"lea;movzx;sub;movsxd;call\"")
        print("Example with objdump: python slicer_exact.py behavior_algebra.txt \"lea;movzx;sub;movsxd\" objdump.txt")
        return

    equations_file = sys.argv[1]
    template = sys.argv[2]

    # Check if objdump file is provided
    objdump_file = None
    if len(sys.argv) > 3:
        objdump_file = sys.argv[3]
        print(f"Using objdump file: {objdump_file}")

    # Build the slice
    slice_equations, path_traces, equations, asm_map, template_sequence = build_slice(equations_file, template, objdump_file)

    # Show results and create output files
    if path_traces:
        print(f"\n=== RESULTS ===")
        print(f"Found {len(path_traces)} matching traces:")
        for i, trace in enumerate(path_traces):
            print(f"  Trace {i+1}: {trace}")
            
        print(f"\nBehavior details:")
        for behavior, rhs in slice_equations.items():
            print(f"{behavior} = {rhs}")
            
        # Create export files
        create_export_files(slice_equations, path_traces, template, asm_map, template_sequence)
    else:
        print("No exact consecutive patterns found.")


if __name__ == "__main__":
    main()