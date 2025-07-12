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

    # Iterate through each potential starting behavior
    for start in start_behaviors:
        print(f"Exploring paths from starting point: {start}")

        # BFS to find paths
        # Each queue entry is (current_behavior, path_so_far, template_index, wildcard_sequence)
        queue = deque([(start, [start], 0, [])])

        while queue:
            current, path, template_idx, wildcard_path = queue.popleft()

            # Create a state key to avoid reprocessing
            state_key = (current, template_idx)
            if state_key in processed_states:
                continue
            processed_states.add(state_key)

            # Skip if we've exceeded the maximum depth
            if len(path) > max_depth:
                continue

            # Check if we've reached the end of the template
            if template_idx >= len(template_sequence) - 1:
                # We need to ensure the final behavior has the instruction we're looking for
                final_instr = template_sequence[-1]["type"]
                if current in behaviors_by_instr.get(final_instr, []):
                    # We've found a complete path
                    path_key = tuple(path)
                    if path_key not in visited_paths:
                        print(f"Found complete path: {' -> '.join(path)}")
                        all_paths.append(path)
                        visited_paths.add(path_key)
                continue

            # Get the next instruction type to look for
            next_template = template_sequence[template_idx + 1]
            next_instr = next_template["type"]
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

                if neighbor in next_behaviors:
                    # Found a direct match to next instruction
                    new_path = path + [neighbor]
                    queue.append((neighbor, new_path, template_idx + 1, wildcard_path))
                elif has_wildcard:
                    # If there's a wildcard, we can continue traversing through other nodes
                    new_path = path + [neighbor]
                    new_wildcard = wildcard_path + [current]  # Add current to wildcard path
                    queue.append((neighbor, new_path, template_idx, new_wildcard))

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


def verify_path_matches_template(path, behaviors_by_instr, template_sequence):
    """Verify that a path matches the template sequence by checking if instructions appear in order."""
    instructions = [item["type"] for item in template_sequence]

    last_instr_idx = -1

    # Each instruction in the template should appear in sequence
    for instr in instructions:
        found = False

        for i in range(last_instr_idx + 1, len(path)):
            behavior = path[i]
            if behavior in behaviors_by_instr.get(instr, []):
                found = True
                last_instr_idx = i
                break

        if not found:
            return False

    return True


def build_slice(equations_file, template):
    """Build a behavior slice based on a template pattern."""
    equations = load_equations(equations_file)

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
    for path in paths:
        if verify_path_matches_template(path, behaviors_by_instr, template_sequence):
            valid_paths.append(path)
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

    # Add behaviors in the found paths
    for path in valid_paths:
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

    return slice_equations, path_traces


def extract_instruction(behavior_rhs, instr_type):
    """Extract a specific instruction from a behavior right-hand side."""
    pattern = fr'{instr_type}\([^)]+\)'
    match = re.search(pattern, behavior_rhs)
    if match:
        return match.group(0)
    return None


def save_slice(slice_equations, path_traces, template, equations, behaviors_by_instr):
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

        # Create a cleaned trace file with just the relevant instructions
        cleaned_trace_file = os.path.join(trace_dir, "cleaned_trace.txt")
        with open(cleaned_trace_file, 'w') as f:
            f.write(f"# Cleaned Trace {i + 1} - Key Instructions Only\n")

            # Find the start behavior (with first instruction)
            start_behavior = None
            for behavior in behaviors:
                if behavior in behaviors_by_instr.get(first_instr, []):
                    start_behavior = behavior
                    break

            if start_behavior and start_behavior in equations:
                # Get the first instruction
                first_instr_text = extract_instruction(equations[start_behavior], first_instr)
                if first_instr_text:
                    f.write(f"Start: {start_behavior} -> {first_instr_text}\n")

            # Find the end behavior (with last instruction)
            end_behavior = None
            for behavior in reversed(behaviors):
                if behavior in behaviors_by_instr.get(last_instr, []):
                    end_behavior = behavior
                    break

            if end_behavior and end_behavior in equations:
                # Get the last instruction
                last_instr_text = extract_instruction(equations[end_behavior], last_instr)
                if last_instr_text:
                    f.write(f"End: {end_behavior} -> {last_instr_text}\n")

            # Also include any intermediate template instructions
            for idx, instr_item in enumerate(template_sequence):
                if idx == 0 or idx == len(template_sequence) - 1:
                    continue  # Skip first and last as we already handled them

                instr = instr_item["type"]
                for behavior in behaviors:
                    if behavior in behaviors_by_instr.get(instr, []):
                        instr_text = extract_instruction(equations[behavior], instr)
                        if instr_text:
                            f.write(f"Middle: {behavior} -> {instr_text}\n")

    print(f"\nAll files saved to {base_dir} directory")
    return base_dir


def main():
    if len(sys.argv) < 3:
        print("Usage: python final_slice_builder.py <equations_file> <template>")
        print("Example: python final_slice_builder.py behavior_algebra.txt \"mov.X1;test.X2;nop\"")
        return

    equations_file = sys.argv[1]
    template = sys.argv[2]

    # Load all equations for reference
    equations = load_equations(equations_file)

    # Build the slice
    slice_equations, path_traces = build_slice(equations_file, template)

    # Extract behaviors by instruction type for the cleaned trace
    template_sequence = parse_template(template)
    instruction_types = [item["type"] for item in template_sequence]
    behaviors_by_instr = get_behaviors_with_instructions(equations, instruction_types)

    print("\nSample behaviors in the slice:")
    count = 0
    for behavior, rhs in slice_equations.items():
        print(f"{behavior} = {rhs}")
        count += 1
        if count >= 5:
            print(f"(Showing 5 of {len(slice_equations)} behaviors)")
            break

    print("\nSample path traces:")
    for i, trace in enumerate(path_traces[:3]):
        print(f"Path {i + 1}: {trace}")

    if len(path_traces) > 3:
        print(f"(Showing 3 of {len(path_traces)} paths)")

    # Save the slice to a file with the new directory structure
    save_slice(slice_equations, path_traces, template, equations, behaviors_by_instr)


if __name__ == "__main__":
    main()