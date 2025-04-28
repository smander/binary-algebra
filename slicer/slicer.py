#!/usr/bin/env python3
import re
import sys
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


def has_instruction(behavior_rhs, instruction):
    """Check if a behavior right-hand side contains a specific instruction."""
    pattern = fr'{instruction}\([^)]+\)'
    return re.search(pattern, behavior_rhs) is not None


def get_behaviors_with_instructions(equations, instructions):
    """Find all behaviors that contain specific instructions."""
    result = {}

    for instr in instructions:
        behaviors = []
        for behavior, rhs in equations.items():
            if has_instruction(rhs, instr):
                behaviors.append(behavior)
        result[instr] = behaviors

    print(f"Found behaviors with instructions:")
    for instr, behaviors in result.items():
        print(f"  - {instr}: {len(behaviors)} behaviors")

    return result


def get_behavior_refs(rhs):
    """Extract behavior references from a right-hand side expression."""
    refs = []
    pattern = r'B\(([^)]+)\)'

    for match in re.finditer(pattern, rhs):
        refs.append(match.group(0))

    return refs


def parse_branches(rhs):
    """Extract branch conditions and target behaviors from a right-hand side expression."""
    branches = []

    # Look for patterns like: je(addr). B(target1) + !je(addr).B(target2)
    branch_pattern = r'([a-z]+)\(([^)]+)\)\.\s*B\(([^)]+)\)\s*\+\s*!([a-z]+)\(([^)]+)\)\.B\(([^)]+)\)'

    for match in re.finditer(branch_pattern, rhs):
        cond_type = match.group(1)  # je, jmp, etc.
        cond_addr = match.group(2)  # address of the condition
        true_target = f"B({match.group(3)})"
        false_target = f"B({match.group(6)})"

        branches.append({
            "condition": f"{cond_type}({cond_addr})",
            "true_branch": true_target,
            "false_branch": false_target
        })

    return branches


def build_control_flow_graph(equations):
    """Build a control flow graph from behavior equations with branch information."""
    graph = {}
    branch_info = {}

    for behavior, rhs in equations.items():
        # Extract direct behavior references
        refs = get_behavior_refs(rhs)

        # Extract branch information
        branches = parse_branches(rhs)

        if branches:
            branch_info[behavior] = branches

            # For the graph, include both branch targets
            for branch in branches:
                if branch["true_branch"] not in refs:
                    refs.append(branch["true_branch"])
                if branch["false_branch"] not in refs:
                    refs.append(branch["false_branch"])

        graph[behavior] = refs

    print(f"Built control flow graph with {len(graph)} nodes and {len(branch_info)} branch points")
    return graph, branch_info


def normalize_behavior_ref(ref):
    """Normalize a behavior reference to a standard form."""
    # Handle B(addr) format
    if ref.startswith('B(') and ref.endswith(')'):
        # Extract just the behavior name inside B()
        content = ref[2:-1].strip()

        # Handle special cases like B(rax), B(qword ptr [rip + 0x2fe4])
        if content.startswith('0x') or content.startswith('r') or content.startswith('qword'):
            return ref

        # Handle B(some_addr); B(next_addr) format
        if ';' in content:
            parts = content.split(';')
            return f"B({parts[0].strip()})"

        return ref

    return ref


def find_paths_between_instructions(template_sequence, behaviors_by_instr, graph, max_depth=15):
    """Find all paths matching the template sequence through the control flow graph."""
    all_paths = []
    visited_paths = set()
    processed_states = set()  # To avoid reprocessing states

    # Get start behaviors (those with the first instruction type)
    start_instr = template_sequence[0]["type"]
    start_behaviors = behaviors_by_instr.get(start_instr, [])

    print(f"Starting search from behaviors with '{start_instr}': {len(start_behaviors)} behaviors")

    # Get end instruction type
    end_instr = template_sequence[-1]["type"]
    end_behaviors = behaviors_by_instr.get(end_instr, [])

    print(f"Looking for paths ending with '{end_instr}': {len(end_behaviors)} potential end behaviors")

    # Iterate through each potential starting behavior
    for start in start_behaviors:
        print(f"Exploring paths from starting point: {start}")

        # BFS to find paths
        # Each queue entry is (current_behavior, path_so_far, template_index, completed_template)
        queue = deque([(start, [start], 0, False)])

        while queue:
            current, path, template_idx, completed = queue.popleft()

            # Create a state key to avoid reprocessing
            state_key = (current, template_idx, completed)
            if state_key in processed_states:
                continue
            processed_states.add(state_key)

            # Skip if we've exceeded the maximum depth
            if len(path) > max_depth:
                continue

            # If we've already completed the template, don't process any further
            if completed:
                path_key = tuple(path)
                if path_key not in visited_paths:
                    print(f"Found complete path: {' -> '.join(path)}")
                    all_paths.append(path)
                    visited_paths.add(path_key)
                continue

            # Check if the current behavior is an end behavior and we're on the final instruction
            if template_idx == len(template_sequence) - 1 and current in end_behaviors:
                # We've found a complete path
                path_key = tuple(path)
                if path_key not in visited_paths:
                    print(f"Found complete path: {' -> '.join(path)}")
                    all_paths.append(path)
                    visited_paths.add(path_key)
                continue

            # Get the next instruction type to look for
            next_template_idx = min(template_idx + 1, len(template_sequence) - 1)
            next_instr = template_sequence[next_template_idx]["type"]
            has_wildcard = template_sequence[template_idx]["wildcard"]  # Wildcard applies to current instruction

            # Get behaviors that contain the next instruction
            next_behaviors = set(behaviors_by_instr.get(next_instr, []))

            # Get neighbors in the control flow graph
            for neighbor_ref in graph.get(current, []):
                # Normalize the reference
                neighbor = normalize_behavior_ref(neighbor_ref)

                # Skip invalid neighbors
                if neighbor not in graph:
                    continue

                # Avoid cycles in the path
                if neighbor in path:
                    continue

                new_path = path + [neighbor]

                if neighbor in next_behaviors:
                    # Found a direct match to next instruction
                    if next_template_idx == len(template_sequence) - 1:
                        # This is the last instruction in the template
                        queue.append((neighbor, new_path, next_template_idx, True))
                    else:
                        queue.append((neighbor, new_path, next_template_idx, False))
                elif has_wildcard:
                    # If there's a wildcard, we can continue traversing through other nodes
                    queue.append((neighbor, new_path, template_idx, False))

    # Process the paths to create the final result
    unique_paths = []
    for path in all_paths:
        # Check if this path is a subset of another path
        is_subset = False
        for other_path in all_paths:
            if path != other_path and len(path) < len(other_path):
                # Check if path is a proper subset of other_path (all elements in same order)
                if is_subpath(path, other_path):
                    is_subset = True
                    break

        if not is_subset:
            unique_paths.append(path)

    print(f"Found {len(unique_paths)} unique paths matching the template")
    return unique_paths


def is_subpath(path1, path2):
    """Check if path1 is a subpath of path2 (elements appear in the same order)"""
    i, j = 0, 0
    while i < len(path1) and j < len(path2):
        if path1[i] == path2[j]:
            i += 1
        j += 1
    return i == len(path1)


def find_instruction_locations(path, equations, instructions):
    """
    Find the location of each instruction type in a path.
    Returns a dict mapping instruction types to [(behavior_index, addr, position),...] lists.
    """
    instruction_locations = {instr: [] for instr in instructions}

    # Go through each behavior in the path
    for path_idx, behavior in enumerate(path):
        if behavior not in equations:
            continue

        rhs = equations[behavior]

        # Check for each instruction type
        for instr_type in instructions:
            # Find all occurrences of this instruction type
            pattern = fr'{instr_type}\(([^)]+)\)'
            for match in re.finditer(pattern, rhs):
                addr = match.group(1)  # Extract the address
                position = match.start()  # Position within the string

                # Add this location to the list for this instruction type
                instruction_locations[instr_type].append((path_idx, addr, position))

    return instruction_locations


def verify_path_matches_template(path, equations, template_sequence):
    """
    Verify that a path matches the template sequence by checking if
    instructions appear in the correct order.
    """
    # Extract instruction types from template
    instruction_types = [item["type"] for item in template_sequence]

    # Find all occurrences of each instruction in the path
    all_instructions = {}
    for instr_type in instruction_types:
        all_instructions[instr_type] = []

    for path_idx, behavior in enumerate(path):
        if behavior not in equations:
            continue

        rhs = equations[behavior]

        # Find all occurrences of each instruction type
        for instr_type in instruction_types:
            pattern = fr'{instr_type}\(([^)]+)\)'
            for match in re.finditer(pattern, rhs):
                addr = match.group(1)
                pos = match.start()
                all_instructions[instr_type].append((path_idx, addr, pos, behavior))

    # Check if all instruction types are found
    for instr_type in instruction_types:
        if not all_instructions[instr_type]:
            print(f"Path missing instruction: {instr_type}")
            return False, path

    # Find earliest occurrence of each instruction
    earliest = {}
    for instr_type in instruction_types:
        # Sort by path index, then by position within behavior
        sorted_occurrences = sorted(all_instructions[instr_type], key=lambda x: (x[0], x[2]))
        earliest[instr_type] = sorted_occurrences[0]

    # Find the ending position for the last instruction
    last_instr = instruction_types[-1]
    last_instr_pos = earliest[last_instr]
    last_behavior_idx = last_instr_pos[0]

    # Truncate the path at the last instruction's behavior
    truncated_path = path[:last_behavior_idx + 1]

    # Log information for debugging
    print(f"Valid path candidate: {' -> '.join(truncated_path)}")
    for instr_type in instruction_types:
        path_idx, addr, pos, behavior = earliest[instr_type]
        print(f"  {instr_type} found in {behavior} at position {pos}, address {addr}")

    # Check if instructions appear in the correct order
    for i in range(len(instruction_types) - 1):
        curr_instr = instruction_types[i]
        next_instr = instruction_types[i + 1]

        curr_loc = earliest[curr_instr]
        next_loc = earliest[next_instr]

        # Get path indices
        curr_path_idx = curr_loc[0]
        next_path_idx = next_loc[0]

        # If in different behaviors, check that the next instruction appears later in the path
        if curr_path_idx > next_path_idx:
            print(
                f"Instructions out of order: {curr_instr} at behavior {curr_loc[3]} comes after {next_instr} at behavior {next_loc[3]}")
            return False, path

        # If in same behavior, check position within the behavior string
        if curr_path_idx == next_path_idx and curr_loc[2] > next_loc[2]:
            print(
                f"Instructions out of order within behavior {curr_loc[3]}: {curr_instr} at position {curr_loc[2]} comes after {next_instr} at position {next_loc[2]}")
            return False, path

    # All checks passed - use the truncated path
    print(f"Path verification successful: {' -> '.join(truncated_path)}")
    return True, truncated_path


def extract_instruction(behavior_rhs, instr_type):
    """Extract a specific instruction from a behavior right-hand side."""
    pattern = fr'{instr_type}\([^)]+\)'
    matches = re.findall(pattern, behavior_rhs)
    return matches if matches else []


def clean_unreachable_paths(behavior_rhs):
    """
    Identify and clean unreachable paths in a behavior equation.
    Looks for patterns like: je(addr). B(target1) + !je(addr).B(target2)
    Removes branches to registers, hex addresses, or memory references.
    Also filters out dynamic behaviors like B(0x456100); and B(rax);
    """
    # Define all registers to filter out
    registers = [
        'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp', 'r8', 'r9', 'r10',
        'r11', 'r12', 'r13', 'r14', 'r15', 'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi',
        'ebp', 'esp', 'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d',
        'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp', 'al', 'bl', 'cl', 'dl',
        'ah', 'bh', 'ch', 'dh'
    ]

    # Filter out dynamic behavior references with hex addresses: B(0x456100);
    dynamic_behavior_pattern = r'B\(0x[0-9a-fA-F]+\);\.?'
    behavior_rhs = re.sub(dynamic_behavior_pattern, '', behavior_rhs)

    # Filter out dynamic behavior references with registers: B(rax);
    for reg in registers:
        reg_pattern = fr'B\({reg}\);\.?'
        behavior_rhs = re.sub(reg_pattern, '', behavior_rhs)

    # Filter out dynamic behavior references with memory pointers: B(qword ptr [rax]);
    pointer_pattern = r'B\((qword|dword|word|byte)\s+ptr\s+\[[^\]]+\]\);\.?'
    behavior_rhs = re.sub(pointer_pattern, '', behavior_rhs)

    # Fix double dots that might result from the above substitution
    behavior_rhs = behavior_rhs.replace('..', '.')

    # Look for branch patterns (conditional jumps)
    branch_pattern = r'([a-z]+)\(([^)]+)\)\.\s*B\(([^)]+)\)\s*\+\s*!([a-z]+)\(([^)]+)\)\.B\(([^)]+)\)'

    matches = list(re.finditer(branch_pattern, behavior_rhs))
    if not matches:
        # No branches to clean, keep as is
        return behavior_rhs

    new_rhs = behavior_rhs
    for match in matches:
        cond_type = match.group(1)  # je, jmp, etc.
        cond_addr = match.group(2)  # Address
        true_target = match.group(3)  # Target if condition is true
        false_target = match.group(6)  # Target if condition is false

        full_branch = match.group(0)

        # Check if this is a jump instruction
        is_jump = cond_type.startswith('j')

        # Check for dynamic references or hex addresses in true branch
        true_is_dynamic = any(reg in true_target for reg in registers)
        true_is_dynamic = true_is_dynamic or 'qword ptr' in true_target
        true_is_dynamic = true_is_dynamic or 'byte ptr' in true_target
        true_is_dynamic = true_is_dynamic or 'word ptr' in true_target
        true_is_dynamic = true_is_dynamic or 'dword ptr' in true_target
        true_is_hex = true_target.startswith('0x')

        # If true branch is dynamic or hex address, remove it and keep only false branch
        if is_jump and (true_is_dynamic or true_is_hex):
            new_branch = f"{cond_type}({cond_addr}).B({false_target})"
            new_rhs = new_rhs.replace(full_branch, new_branch)

        # Check the false branch too
        false_is_dynamic = any(reg in false_target for reg in registers)
        false_is_dynamic = false_is_dynamic or 'qword ptr' in false_target
        false_is_dynamic = false_is_dynamic or 'byte ptr' in false_target
        false_is_dynamic = false_is_dynamic or 'word ptr' in false_target
        false_is_dynamic = false_is_dynamic or 'dword ptr' in false_target
        false_is_hex = false_target.startswith('0x')

        # If false branch is dynamic or hex address, remove it and keep only true branch
        if is_jump and (false_is_dynamic or false_is_hex):
            new_branch = f"{cond_type}({cond_addr}).B({true_target})"
            new_rhs = new_rhs.replace(full_branch, new_branch)

    return new_rhs

def create_filtered_behaviors(path, equations, template_sequence):
    """
    Create filtered version of behaviors in a path by:
    1. Removing unreachable branch paths
    2. Truncating at the first template end instruction
    3. Finding appropriate start/end points based on template instructions

    Returns a dict of filtered behavior equations.
    """
    # Extract the instruction types from the template
    first_instr_type = template_sequence[0]["type"]
    end_instr_type = template_sequence[-1]["type"]

    # Process each behavior in the path
    filtered_equations = {}
    behaviors = path.split(" -> ")

    # Find the first behavior that contains the first template instruction
    start_index = -1
    for i, behavior in enumerate(behaviors):
        if behavior in equations and has_instruction(equations[behavior], first_instr_type):
            start_index = i
            break

    if start_index == -1:
        print(f"Warning: No behavior in path contains {first_instr_type}")
        return {}

    # Find the last behavior that contains the end template instruction
    end_index = -1
    for i, behavior in enumerate(behaviors):
        if behavior in equations and has_instruction(equations[behavior], end_instr_type):
            end_index = i

    if end_index == -1:
        print(f"Warning: No behavior in path contains {end_instr_type}")
        return {}

    # If end comes before start, something is wrong
    if end_index < start_index:
        print(f"Warning: End instruction {end_instr_type} found before start instruction {first_instr_type}")
        return {}

    # Process only the behaviors between start and end (inclusive)
    for i in range(start_index, end_index + 1):
        behavior = behaviors[i]
        if behavior not in equations:
            continue

        rhs = equations[behavior]

        # Clean unreachable paths
        cleaned_rhs = clean_unreachable_paths(rhs)

        # If this is the first behavior with first instruction, remove everything before it
        if i == start_index:
            # Find the position of the first instruction
            pattern = fr'{first_instr_type}\(([^)]+)\)'
            match = re.search(pattern, cleaned_rhs)
            if match:
                start_pos = match.start()
                # Find the last dot before this instruction
                last_dot = cleaned_rhs[:start_pos].rfind('.')
                if last_dot != -1:
                    # Start from the first instruction (removing everything before it)
                    cleaned_rhs = cleaned_rhs[last_dot + 1:]

        # If this is the last behavior with end instruction, truncate after it
        if i == end_index:
            cleaned_rhs = truncate_behavior(cleaned_rhs, end_instr_type, 'after')

        filtered_equations[behavior] = cleaned_rhs

    # Debug information
    if filtered_equations:
        print(f"Found valid path from {behaviors[start_index]} to {behaviors[end_index]}")
        print(f"Path contains {len(filtered_equations)} behaviors with {first_instr_type} and {end_instr_type}")

    return filtered_equations


def truncate_behavior(rhs, instr_type, truncate_point="before"):
    """
    Simplified function to truncate a behavior RHS at a specific instruction.

    Args:
        rhs: The right-hand side of the behavior equation
        instr_type: The instruction type to find (e.g., 'mov', 'test', 'nop')
        truncate_point: Where to truncate -
                       "before": keep instructions before the target instruction
                       "after": keep instructions up to and including the target instruction

    Returns:
        The truncated RHS based on the specified truncate_point
    """
    # Create pattern to match the instruction
    pattern = fr'{instr_type}\(([^)]+)\)'

    match = re.search(pattern, rhs)
    if not match:
        return rhs  # No match found, return original

    # Find the positions to truncate
    start_pos = match.start()  # Start of the instruction
    end_pos = match.end()  # End of the instruction

    if truncate_point == "before":
        # Keep everything before the instruction
        # Find the last dot before the instruction
        last_dot = rhs[:start_pos].rfind('.')
        if last_dot != -1:
            return rhs[:last_dot + 1]
        else:
            return ""  # No previous instruction, return empty

    elif truncate_point == "after":
        # Keep everything up to and including the instruction
        # Find the next dot after the instruction
        next_dot = rhs[end_pos:].find('.')
        if next_dot != -1:
            return rhs[:end_pos + next_dot]
        else:
            return rhs  # No next instruction, return until end

    return rhs  # Default case, return original


def save_slice(slice_equations, path_traces, template, equations, behaviors_by_instr, asm_map=None):
    """Save the slice and path traces to organized directory structure."""
    import os
    from datetime import datetime

    # Create timestamp for unique directory naming
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

    # Create export directory structure
    base_dir = f"export_{template.replace('.', '_').replace(';', '_')}_{timestamp}"
    os.makedirs(base_dir, exist_ok=True)

    # Parse the template to understand what we're looking for
    template_sequence = parse_template(template)
    first_instr = template_sequence[0]["type"]
    last_instr = template_sequence[-1]["type"]

    # Check if we have assembly data
    has_asm = asm_map is not None and len(asm_map) > 0

    # 1. Save path flows to a dedicated file
    path_flows_file = os.path.join(base_dir, "path_flows.txt")
    with open(path_flows_file, 'w') as f:
        f.write(f"# Path Flows for Template: {template}\n")
        for i, trace in enumerate(path_traces):
            f.write(f"Path {i + 1}:\n{trace}\n\n")

    print(f"Path flows saved to {path_flows_file}")

    # 2. Save all behaviors to a separate file
    all_behaviors_file = os.path.join(base_dir, "all_behaviors.txt")
    with open(all_behaviors_file, 'w') as f:
        f.write(f"# All Behaviors for Template: {template}\n")
        for behavior, rhs in slice_equations.items():
            f.write(f"{behavior} = {rhs}\n")

            # Add assembly if available
            if has_asm:
                # Convert behavior to assembly
                asm_instructions = convert_behavior_to_asm(rhs, asm_map)
                if asm_instructions:
                    f.write("  # Assembly:\n")
                    for addr, instr_type, asm in asm_instructions:
                        addr_hex = f"0x{addr:x}" if isinstance(addr, int) else addr
                        f.write(f"  #   {addr_hex}: {asm}\n")
                f.write("\n")

    print(f"All behaviors saved to {all_behaviors_file}")

    # 3. Create subdirectory for each path trace with cleaned behaviors
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
            for behavior in behaviors:
                if behavior in equations:
                    f.write(f"{behavior} = {equations[behavior]}\n")

                    # Add assembly if available
                    if has_asm:
                        asm_instructions = convert_behavior_to_asm(equations[behavior], asm_map)
                        if asm_instructions:
                            f.write("  # Assembly:\n")
                            for addr, instr_type, asm in asm_instructions:
                                addr_hex = f"0x{addr:x}" if isinstance(addr, int) else addr
                                f.write(f"  #   {addr_hex}: {asm}\n")
                        f.write("\n")

        # Create a cleaned trace file with just the relevant instructions
        cleaned_trace_file = os.path.join(trace_dir, "cleaned_trace.txt")
        with open(cleaned_trace_file, 'w') as f:
            f.write(f"# Cleaned Trace {i + 1} - Key Instructions Only\n")

            # Find all behaviors with template instructions
            trace_instrs = {}
            for instr_type in set([item["type"] for item in template_sequence]):
                trace_instrs[instr_type] = []

            # Go through path behaviors and collect all matching instructions
            for behavior in behaviors:
                if behavior not in equations:
                    continue

                rhs = equations[behavior]
                for instr_type in trace_instrs:
                    instrs = extract_instruction(rhs, instr_type)
                    if instrs:
                        for instr in instrs:
                            trace_instrs[instr_type].append((behavior, instr))

            # Output the instructions in order of appearance in the path
            f.write(f"# Start Instruction: {first_instr}\n")
            if trace_instrs[first_instr]:
                for behavior, instr in trace_instrs[first_instr]:
                    f.write(f"Start: {behavior} -> {instr}\n")

                    # Add assembly if available
                    if has_asm:
                        # Extract address from instruction
                        addr_match = re.search(r'\(([^)]+)\)', instr)
                        if addr_match:
                            addr_str = addr_match.group(1)
                            try:
                                if addr_str.startswith('0x'):
                                    addr_int = int(addr_str, 16)
                                else:
                                    addr_int = int(addr_str)

                                if addr_int in asm_map:
                                    f.write(f"        Assembly: {addr_int:x}: {asm_map[addr_int]}\n")
                            except ValueError:
                                pass

            # Middle instructions
            for idx, instr_item in enumerate(template_sequence):
                instr_type = instr_item["type"]
                if instr_type != first_instr and instr_type != last_instr:
                    f.write(f"\n# Middle Instruction: {instr_type}\n")
                    if trace_instrs[instr_type]:
                        for behavior, instr in trace_instrs[instr_type]:
                            f.write(f"Middle: {behavior} -> {instr}\n")

                            # Add assembly if available
                            if has_asm:
                                # Extract address from instruction
                                addr_match = re.search(r'\(([^)]+)\)', instr)
                                if addr_match:
                                    addr_str = addr_match.group(1)
                                    try:
                                        if addr_str.startswith('0x'):
                                            addr_int = int(addr_str, 16)
                                        else:
                                            addr_int = int(addr_str)

                                        if addr_int in asm_map:
                                            f.write(f"        Assembly: {addr_int:x}: {asm_map[addr_int]}\n")
                                    except ValueError:
                                        pass

            # End instruction
            f.write(f"\n# End Instruction: {last_instr}\n")
            if trace_instrs[last_instr]:
                for behavior, instr in trace_instrs[last_instr]:
                    f.write(f"End: {behavior} -> {instr}\n")

                    # Add assembly if available
                    if has_asm:
                        # Extract address from instruction
                        addr_match = re.search(r'\(([^)]+)\)', instr)
                        if addr_match:
                            addr_str = addr_match.group(1)
                            try:
                                if addr_str.startswith('0x'):
                                    addr_int = int(addr_str, 16)
                                else:
                                    addr_int = int(addr_str)

                                if addr_int in asm_map:
                                    f.write(f"        Assembly: {addr_int:x}: {asm_map[addr_int]}\n")
                            except ValueError:
                                pass

            # Also write a clean summary
            f.write("\n# Clean Summary (First occurrence of each instruction)\n")
            seen_behaviors = set()

            # First instruction
            for behavior, instr in trace_instrs[first_instr]:
                if behavior not in seen_behaviors:
                    f.write(f"{first_instr}: {behavior} -> {instr}\n")
                    seen_behaviors.add(behavior)

                    # Add assembly if available
                    if has_asm:
                        # Extract address from instruction
                        addr_match = re.search(r'\(([^)]+)\)', instr)
                        if addr_match:
                            addr_str = addr_match.group(1)
                            try:
                                if addr_str.startswith('0x'):
                                    addr_int = int(addr_str, 16)
                                else:
                                    addr_int = int(addr_str)

                                if addr_int in asm_map:
                                    f.write(f"    Assembly: {addr_int:x}: {asm_map[addr_int]}\n")
                            except ValueError:
                                pass
                    break

            # Middle instructions in order
            for idx, instr_item in enumerate(template_sequence):
                instr_type = instr_item["type"]
                if instr_type != first_instr and instr_type != last_instr:
                    for behavior, instr in trace_instrs[instr_type]:
                        if behavior not in seen_behaviors:
                            f.write(f"{instr_type}: {behavior} -> {instr}\n")
                            seen_behaviors.add(behavior)

                            # Add assembly if available
                            if has_asm:
                                # Extract address from instruction
                                addr_match = re.search(r'\(([^)]+)\)', instr)
                                if addr_match:
                                    addr_str = addr_match.group(1)
                                    try:
                                        if addr_str.startswith('0x'):
                                            addr_int = int(addr_str, 16)
                                        else:
                                            addr_int = int(addr_str)

                                        if addr_int in asm_map:
                                            f.write(f"    Assembly: {addr_int:x}: {asm_map[addr_int]}\n")
                                    except ValueError:
                                        pass
                            break

            # Last instruction
            for behavior, instr in trace_instrs[last_instr]:
                if behavior not in seen_behaviors:
                    f.write(f"{last_instr}: {behavior} -> {instr}\n")
                    seen_behaviors.add(behavior)

                    # Add assembly if available
                    if has_asm:
                        # Extract address from instruction
                        addr_match = re.search(r'\(([^)]+)\)', instr)
                        if addr_match:
                            addr_str = addr_match.group(1)
                            try:
                                if addr_str.startswith('0x'):
                                    addr_int = int(addr_str, 16)
                                else:
                                    addr_int = int(addr_str)

                                if addr_int in asm_map:
                                    f.write(f"    Assembly: {addr_int:x}: {asm_map[addr_int]}\n")
                            except ValueError:
                                pass
                    break

        # Create a filtered behaviors file
        filtered_file = os.path.join(trace_dir, "filtered_behaviors.txt")

        # Generate filtered behaviors for this path
        filtered_equations = create_filtered_behaviors(path_trace, equations, template_sequence)

        # Save the filtered behaviors
        with open(filtered_file, 'w') as f:
            f.write(f"# Filtered Behaviors for Trace {i + 1}\n")
            f.write(f"# Template: {template}\n")
            f.write("# The following behaviors have been:\n")
            f.write("#  1. Cleaned to remove unreachable paths (dynamic references or hex addresses)\n")
            f.write(f"#  2. Truncated at the template end instruction: {template_sequence[-1]['type']}\n\n")

            for behavior in path_trace.split(" -> "):
                if behavior in filtered_equations:
                    f.write(f"{behavior} = {filtered_equations[behavior]}\n")

                    # Add assembly if available
                    if has_asm:
                        asm_instructions = convert_behavior_to_asm(filtered_equations[behavior], asm_map)
                        if asm_instructions:
                            f.write("  # Assembly:\n")
                            for addr, instr_type, asm in asm_instructions:
                                addr_hex = f"0x{addr:x}" if isinstance(addr, int) else addr
                                f.write(f"  #   {addr_hex}: {asm}\n")
                        f.write("\n")

        # If we have assembly mapping, create a pure assembly trace file
        # If we have assembly mapping, create a pure assembly trace file
        if has_asm:
            asm_trace_file = os.path.join(trace_dir, "assembly_trace.txt")
            with open(asm_trace_file, 'w') as f:
                # Process each behavior in the path
                for behavior in path_trace.split(" -> "):
                    if behavior in filtered_equations:
                        # Get assembly instructions without adding behavior comments
                        asm_instructions = convert_behavior_to_asm(filtered_equations[behavior], asm_map)
                        for addr, instr_type, asm in asm_instructions:
                            addr_hex = f"0x{addr:x}" if isinstance(addr, int) else addr
                            f.write(f"{addr_hex}: {asm}\n")

            print(f"  Created pure assembly trace at {asm_trace_file}")

            asm_output_file = os.path.join(base_dir, "assembly_combined.asm")
            with open(asm_output_file, 'w') as f:
                # Process all paths
                for path_trace in path_traces:
                    behaviors = path_trace.split(" -> ")

                    # Get filtered behaviors for this path
                    filtered_behaviors = create_filtered_behaviors(path_trace, equations, template_sequence)

                    # Process each behavior
                    for behavior in behaviors:
                        if behavior in filtered_behaviors:
                            # Get assembly instructions
                            asm_instructions = convert_behavior_to_asm(filtered_behaviors[behavior], asm_map)
                            for addr, instr_type, asm in asm_instructions:
                                addr_hex = f"0x{addr:x}" if isinstance(addr, int) else addr
                                f.write(f"{addr_hex}: {asm}\n")

            print(f"Created combined assembly file at {asm_output_file}")

        print(f"  Created filtered behaviors at {filtered_file}")

    print(f"\nAll files saved to {base_dir} directory")
    return base_dir


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

    # Extract just the instruction types
    instruction_types = [item["type"] for item in template_sequence]

    # Find behaviors with each instruction type
    behaviors_by_instr = get_behaviors_with_instructions(equations, instruction_types)

    # Build the control flow graph
    graph, branch_info = build_control_flow_graph(equations)

    # Find paths matching the template sequence
    paths = find_paths_between_instructions(template_sequence, behaviors_by_instr, graph)

    # Verify all paths match the template
    valid_paths = []
    verified_paths = []
    for path in paths:
        is_valid, truncated_path = verify_path_matches_template(path, equations, template_sequence)
        if is_valid:
            valid_paths.append(path)
            verified_paths.append(truncated_path)  # Use the truncated path instead
        else:
            print(f"Warning: Path does not match template: {' -> '.join(path)}")

    print(f"Verified {len(valid_paths)} valid paths out of {len(paths)} found paths")

    # Create a slice combining:
    # 1. Behaviors with each instruction type
    # 2. Behaviors in the valid paths
    # 3. ALL behaviors referenced by behaviors in the slice (complete trace)
    slice_behaviors = set()
    path_traces = []

    # Add behaviors with each instruction type
    for instr, behaviors in behaviors_by_instr.items():
        print(f"Adding {len(behaviors)} behaviors with instruction type '{instr}'")
        for b in behaviors:
            slice_behaviors.add(b)

    # Add behaviors in the found paths (using verified/truncated paths)
    for path in verified_paths:
        path_trace = " -> ".join(path)
        path_traces.append(path_trace)

        print(f"Adding path: {path_trace}")
        for behavior in path:
            slice_behaviors.add(behavior)

    # Create initial slice
    slice_equations = {}
    for behavior in slice_behaviors:
        if behavior in equations:
            slice_equations[behavior] = equations[behavior]
        else:
            print(f"Warning: Behavior {behavior} referenced in path but not found in equations")

    # Now add ALL behaviors that are referenced by behaviors in the slice (complete trace)
    behaviors_to_add = set()
    for behavior, rhs in slice_equations.items():
        # Get all behavior references from the RHS
        refs = get_behavior_refs(rhs)
        for ref in refs:
            normalized_ref = normalize_behavior_ref(ref)
            # Remove B() wrapper
            if normalized_ref.startswith('B(') and normalized_ref.endswith(')'):
                clean_ref = normalized_ref[2:-1].strip()
                # Handle special cases
                if not (clean_ref.startswith('0x') or clean_ref.startswith('r') or clean_ref.startswith('qword')):
                    # This is a regular behavior reference
                    behavior_ref = f"B({clean_ref})"
                    behaviors_to_add.add(behavior_ref)

    # Convert behavior references to actual behavior keys
    new_behaviors = set()
    for ref in behaviors_to_add:
        if ref.startswith('B(') and ref.endswith(')'):
            behavior_key = ref
            if behavior_key in equations and behavior_key not in slice_equations:
                new_behaviors.add(behavior_key)

    # Add the new behaviors to the slice
    print(f"Adding {len(new_behaviors)} additional behaviors referenced in paths")
    for behavior in new_behaviors:
        slice_equations[behavior] = equations[behavior]

    print(f"Built a slice with {len(slice_equations)} behaviors from {len(valid_paths)} paths")

    # Print some sample behaviors in the slice for verification
    print("\nSample behaviors in the slice:")
    count = 0
    for behavior, rhs in slice_equations.items():
        if count < 5:  # Show first 5 behaviors
            print(f"{behavior} = {rhs}")
        count += 1

    return slice_equations, path_traces, equations, behaviors_by_instr, asm_map


def parse_objdump(file_path):
    """Parse an objdump output file to create a mapping of addresses to assembly instructions."""
    asm_map = {}

    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            # Match patterns like "44fabd: mov %eax,0x10(%rdx)"
            # This regex is more flexible with whitespace and different formats
            match = re.match(r'([0-9a-f]+):\s*(.*)', line)
            if match:
                addr_str = match.group(1)
                instruction = match.group(2).strip()

                # Try to convert the address to int in different ways
                try:
                    # Try as hex
                    addr = int(addr_str, 16)
                    asm_map[addr] = instruction
                    # Also store as decimal in case behaviors use decimal addresses
                    asm_map[int(addr_str, 16)] = instruction

                    # Debug print to verify
                    print(f"Added mapping: 0x{addr:x} -> {instruction}")
                except ValueError:
                    print(f"Warning: Could not parse address: {addr_str}")

    print(f"Loaded {len(asm_map)} assembly instructions from objdump")
    # Print a sample of the loaded instructions
    items = list(asm_map.items())
    if items:
        print("Sample of loaded instructions:")
        for addr, instr in items[:5]:
            print(f"  0x{addr:x}: {instr}")

    return asm_map


def convert_behavior_to_asm(behavior_rhs, asm_map):
    """Convert a behavior equation RHS to corresponding assembly code."""
    # Extract all instructions with their addresses
    instruction_pattern = r'([a-z]+)\(([^)]+)\)'
    instructions = re.findall(instruction_pattern, behavior_rhs)

    # Map each instruction to its assembly representation
    asm_instructions = []
    for instr_type, addr in instructions:
        try:
            # Always interpret addresses as hex (remove any 0x prefix if present)
            clean_addr = addr.replace('0x', '')
            addr_int = int(clean_addr, 16)

            # Check if we have this address in our map
            if addr_int in asm_map:
                asm_instr = asm_map[addr_int]
                asm_instructions.append((addr_int, instr_type, asm_instr))
            else:
                asm_instructions.append((addr_int, instr_type, f"{instr_type}({addr}) (assembly not found)"))
        except ValueError:
            # Handle case where address isn't a valid hex number
            asm_instructions.append((0, instr_type, f"{instr_type}({addr}) (cannot convert to assembly)"))

    # Sort by address to maintain correct instruction order
    asm_instructions.sort(key=lambda x: x[0])

    return asm_instructions


def main():
    if len(sys.argv) < 3:
        print("Usage: python slicer.py <equations_file> <template> [<objdump_file>]")
        print("Example: python slicer.py behavior_algebra.txt \"mov.X1;test.X2;nop\"")
        print("Example with objdump: python slicer.py behavior_algebra.txt \"mov.X1;test.X2;nop\" objdump.txt")
        return

    equations_file = sys.argv[1]
    template = sys.argv[2]

    # Check if objdump file is provided
    objdump_file = None
    if len(sys.argv) > 3:
        objdump_file = sys.argv[3]
        print(f"Using objdump file: {objdump_file}")

    # Build the slice
    slice_equations, path_traces, equations, behaviors_by_instr, asm_map = build_slice(equations_file, template,
                                                                                       objdump_file)

    # If we have assembly mapping, show some examples
    if asm_map and len(asm_map) > 0:
        print("\nSample assembly mapping:")
        count = 0
        for addr, asm in sorted(asm_map.items())[:5]:
            print(f"0x{addr:x}: {asm}")
            count += 1
        if len(asm_map) > 5:
            print(f"(Showing 5 of {len(asm_map)} assembly instructions)")

    # Save the slice to a file with the new directory structure
    save_slice(slice_equations, path_traces, template, equations, behaviors_by_instr, asm_map)

if __name__ == "__main__":
    main()