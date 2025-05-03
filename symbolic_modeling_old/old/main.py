# main.py
"""
Entry point for symbolic modeling using a modular workflow.
"""
from behavior_parser import parse_behavior_file
from symmod import SymMod

def main():
    # Read template.txt
    try:
        with open('template.txt', 'r') as f:
            template = f.read()
    except IOError as e:
        print("Error reading template file:", e)
        return

    # Read and parse the behavior file
    behavior_file = 'data/behavior_algebra_20250326_194917.txt'
    instructions, _ = parse_behavior_file(behavior_file)
    if not instructions:
        print("No valid instructions found in behavior file.")
        return

    print("Running SymMod with instructions from file...")
    final_env = SymMod(instructions, template)

    if final_env:
        print("Symbolic modeling completed successfully!")
        final_env.print_state()
    else:
        print("Symbolic modeling failed - constraints not satisfiable.")

if __name__ == "__main__":
    main()
