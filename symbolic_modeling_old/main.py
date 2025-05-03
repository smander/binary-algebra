from helpers import  extract_real_register_operations, trace_specific_sequence



def main():
    """Main function to demonstrate tracing of symbolic execution"""
    behavior_file = "data/behavior_algebra_20250326_194917.txt"

    # Extract register operations
    register_ops = extract_real_register_operations(behavior_file)
    print(f"Found {len(register_ops)} sequences with register operations")

    # Filter out any non-2-tuple items (failsafe)
    register_ops = [item for item in register_ops if isinstance(item, tuple) and len(item) == 2]

    if not register_ops:
        print("No register operations found in behavior file.")
        return

    # Select sequences to trace - focus on ones with interesting instructions
    sequences_to_trace = []
    for addr, sequence in register_ops:
        # Look for sequences with multiple register operations
        ops = set()
        for instr in sequence:
            if instr['name'].lower() in ['mov', 'add', 'sub', 'xor', 'push', 'pop', 'lea']:
                ops.add(instr['name'].lower())

        # If sequence has 3+ different register operations, trace it
        if len(ops) >= 3:
            sequences_to_trace.append(addr)
            if len(sequences_to_trace) >= 3:
                break

    # If we didn't find enough interesting sequences, just use the first few
    if len(sequences_to_trace) < 3 and register_ops:
        for addr, _ in register_ops[:3]:
            if addr not in sequences_to_trace:
                sequences_to_trace.append(addr)
                if len(sequences_to_trace) >= 3:
                    break

    # Trace the selected sequences
    print("\nTracing selected sequences:")
    for i, addr in enumerate(sequences_to_trace):
        print(f"\nTracing sequence {i + 1}/{len(sequences_to_trace)} at address {addr}")
        trace_specific_sequence(behavior_file, addr)

    print("\nExecution tracing complete. JSON trace files have been created.")


if __name__ == "__main__":
    main()