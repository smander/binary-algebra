import re
import sys
from collections import deque
def load_equations(file_path):
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


def has_instruction(behavior_rhs, instruction):
    pattern = fr'{instruction}\([^)]+\)'
    return re.search(pattern, behavior_rhs) is not None


def get_behaviors_with_instructions(equations, instructions):
    result = {}

    for instr in instructions:
        behaviors = []
        for behavior, rhs in equations.items():
            if has_instruction(rhs, instr):
                behaviors.append(behavior)
        result[instr] = behaviors

    return result


def get_behavior_refs(rhs):
    refs = []
    pattern = r'B\(([^)]+)\)'

    for match in re.finditer(pattern, rhs):
        refs.append(match.group(0))

    return refs


def build_control_flow_graph(equations):
    graph = {}

    for behavior, rhs in equations.items():
        graph[behavior] = get_behavior_refs(rhs)

    return graph


def normalize_behavior_ref(ref):
    """Normalize a behavior reference to a standard form"""
    # Extract just the behavior name, stripping any operators
    return ref.split(';')[0].strip()
def can_reach(start, target_behaviors, graph, max_depth=5):
    queue = deque([start])
    visited = set([start])
    depth = 0

    while queue and depth < max_depth:
        size = len(queue)

        for _ in range(size):
            current = queue.popleft()

            # Check if current is a target
            if current in target_behaviors:
                return current

            # Add neighbors to queue
            for neighbor in graph.get(current, []):
                # Normalize the neighbor reference
                normalized = normalize_behavior_ref(neighbor)

                if normalized in graph and normalized not in visited:
                    visited.add(normalized)
                    queue.append(normalized)

        depth += 1

    return None


def find_path_between_instructions(instructions, behaviors_by_instr, graph, max_samples=5):
    samples = {}
    for instr in instructions:
        samples[instr] = behaviors_by_instr[instr][:max_samples]

    # Test paths between consecutive instructions
    paths = []

    for i in range(len(instructions) - 1):
        instr1 = instructions[i]
        instr2 = instructions[i + 1]

        for start in samples[instr1]:
            target = can_reach(start, samples[instr2], graph)
            if target:
                paths.append((start, target))
                break

    return paths


def build_slice(equations_file, pattern):
    equations = load_equations(equations_file)

    # Parse the pattern
    pattern_parts = re.split(r'[.;]', pattern)
    instructions = []
    for part in pattern_parts:
        if part and part[0].isalpha() and not part.startswith('X'):
            instructions.append(part)

    if not instructions:
        print("Invalid pattern")
        return {}

    print(f"Pattern instructions: {', '.join(instructions)}")

    # Find behaviors with each instruction
    behaviors_by_instr = get_behaviors_with_instructions(equations, instructions)

    for instr, behaviors in behaviors_by_instr.items():
        print(f"Found {len(behaviors)} behaviors with '{instr}'")

    # Build the control flow graph
    print("Building control flow graph...")
    graph = build_control_flow_graph(equations)
    print(f"Control flow graph built with {len(graph)} nodes")

    # Find paths between instructions
    print("Finding paths between instructions in the pattern...")
    paths = find_path_between_instructions(instructions, behaviors_by_instr, graph)

    if paths:
        print(f"Found {len(paths)} paths through the control flow")
        for i, (start, end) in enumerate(paths):
            print(f"Path {i + 1}: {start} -> {end}")
    else:
        print("No paths found through the control flow")

    # Create a slice combining:
    # 1. Behaviors with each instruction type
    # 2. Behaviors in the found paths
    slice_behaviors = set()

    # Add sample behaviors with each instruction type
    for instr, behaviors in behaviors_by_instr.items():
        for b in behaviors[:3]:  # Add up to 3 behaviors of each type
            slice_behaviors.add(b)

    # Add behaviors in the found paths
    for start, end in paths:
        slice_behaviors.add(start)
        slice_behaviors.add(end)

    # Create the slice
    slice_equations = {}
    for behavior in slice_behaviors:
        slice_equations[behavior] = equations[behavior]

    print(f"Built a slice with {len(slice_equations)} behaviors")
    return slice_equations


def main():
    if len(sys.argv) < 3:
        print("Usage: python slice_builder.py <equations_file> <pattern>")
        return

    equations_file = sys.argv[1]
    pattern = sys.argv[2]

    slice_equations = build_slice(equations_file, pattern)

    print("\nSample behaviors in the slice:")
    count = 0
    for behavior, rhs in slice_equations.items():
        print(f"{behavior} = {rhs}")
        count += 1
        if count >= 10:
            print("(Showing 10 of {len(slice_equations)} behaviors)")
            break

    # Save the slice to a file
    output_file = f"slice_{pattern.replace('.', '_').replace(';', '_')}.txt"
    with open(output_file, 'w') as f:
        for behavior, rhs in slice_equations.items():
            f.write(f"{behavior} = {rhs}\n")

    print(f"\nFull slice saved to {output_file}")


if __name__ == "__main__":
    main()