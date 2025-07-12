import os
from behavior_parser import BehaviorAlgebraParser
from symbolic_environment import SymbolicEnvironment

def extract_real_register_operations(behavior_file):
    """
    Extract real register operations from behavior algebra file

    Args:
        behavior_file: Path to behavior algebra file

    Returns:
        List of (address, instruction sequence) tuples involving register operations
    """
    # Read the behavior file
    with open(behavior_file, 'r') as f:
        behavior_content = f.read()

    # Parse the behavior algebra
    parser = BehaviorAlgebraParser(behavior_content)

    # Find sequences with register operations
    register_ops = []
    for item in parser.get_all_sequences().items():
        if isinstance(item, tuple) and len(item) == 2:
            addr, sequence = item
            # Check if sequence contains register operations
            has_reg_ops = False
            for instr in sequence:
                if instr['name'].lower() in ['mov', 'add', 'sub', 'mul', 'div', 'xor', 'and', 'or', 'push', 'pop']:
                    has_reg_ops = True
                    break
            if has_reg_ops:
                register_ops.append((addr, sequence))
        else:
            print(f"Warning: Unexpected item in sequences: {item}")
    return register_ops


def trace_specific_sequence(behavior_file, address):
    """
    Trace execution of a specific instruction sequence

    Args:
        behavior_file: Path to behavior algebra file
        address: Address of sequence to trace

    Returns:
        Tracer object with execution results
    """
    # Read the behavior file
    with open(behavior_file, 'r') as f:
        behavior_content = f.read()

    # Parse the behavior algebra
    parser = BehaviorAlgebraParser(behavior_content)

    # Get the sequence for the specified address
    sequence = parser.get_sequence(address)

    if not sequence:
        print(f"No sequence found for address {address}")
        return None

    # Create environment and set up initial state
    env = SymbolicEnvironment()

    # Execute the sequence
    env.execute_sequence(sequence)

    # Save the trace
    trace_file = f"trace_{address}.json"
    env.save_trace(trace_file)

    return env
