#!/usr/bin/env python3
"""Debug script to understand why pattern matching fails for single-behavior patterns."""

import re

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
    
    return equations

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
    
    return result

def find_behaviors_with_all_instructions(equations, instructions):
    """Find behaviors that contain ALL specified instructions in order."""
    matching_behaviors = []
    
    for behavior, rhs in equations.items():
        # Check if this behavior contains all instructions
        all_present = True
        positions = {}
        
        for instr in instructions:
            pattern = fr'{instr}\(([^)]+)\)'
            match = re.search(pattern, rhs)
            if match:
                positions[instr] = match.start()
            else:
                all_present = False
                break
        
        if all_present:
            # Check if they appear in the correct order
            sorted_instrs = sorted(positions.items(), key=lambda x: x[1])
            actual_order = [instr for instr, _ in sorted_instrs]
            
            if actual_order == instructions:
                matching_behaviors.append(behavior)
                print(f"Found matching behavior: {behavior}")
                print(f"  Instructions in order: {actual_order}")
                print(f"  Positions: {positions}")
    
    return matching_behaviors

# Test the pattern matching
equations = load_equations('../../slicer/data/behavior_algebra_20250711_131715.txt')
instructions = ['lea', 'movzx', 'sub', 'movsxd']

print("=== Debug Pattern Matching ===")
print(f"Looking for pattern: {' -> '.join(instructions)}")
print(f"Total behaviors loaded: {len(equations)}")

# Find behaviors with each instruction
behaviors_by_instr = get_behaviors_with_instructions(equations, instructions)
print(f"\nBehaviors with each instruction:")
for instr, behaviors in behaviors_by_instr.items():
    print(f"  {instr}: {len(behaviors)} behaviors")

# Find behaviors that contain all instructions in order
print(f"\nFinding behaviors with ALL instructions in order:")
matching_behaviors = find_behaviors_with_all_instructions(equations, instructions)

print(f"\nResult: Found {len(matching_behaviors)} behaviors with the complete pattern")
if matching_behaviors:
    print("Matching behaviors:")
    for behavior in matching_behaviors:
        print(f"  {behavior}")
        print(f"    RHS: {equations[behavior]}")