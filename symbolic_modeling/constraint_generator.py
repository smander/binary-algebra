from z3 import *


def parse_operand(operand, env):
    """
    Parse an operand and return its value and type

    Args:
        operand: String representation of operand
        env: Symbolic environment

    Returns:
        (value, type): Value of operand and its type (register, memory, immediate)
    """
    operand = operand.strip()

    # Check for registers
    if operand in env.REG_SIZES:
        return env.get_register(operand), 'register'

    # Check for immediate values (e.g., 0x1f, 2)
    if operand.startswith('0x') or operand.isdigit() or (operand.startswith('-') and operand[1:].isdigit()):
        if operand.startswith('0x'):
            value = int(operand, 16)
        else:
            value = int(operand)
        return BitVecVal(value, 64), 'immediate'

    # Check for memory references
    if '[' in operand and ']' in operand:
        mem_ref = operand[operand.index('[') + 1:operand.index(']')]

        # Handle memory reference parsing with support for hex values
        if '+' in mem_ref:
            # Format like [rbx + 4] or [rip + 0x9cdab]
            parts = [p.strip() for p in mem_ref.split('+')]
            base_reg = env.get_register(parts[0])

            # Parse offset value with hex support
            offset_str = parts[1]
            if offset_str.startswith('0x'):
                offset = int(offset_str, 16)
            else:
                offset = int(offset_str)

            address = base_reg + BitVecVal(offset, 64)
        elif '-' in mem_ref:
            # Format like [rax - 8]
            parts = [p.strip() for p in mem_ref.split('-')]
            base_reg = env.get_register(parts[0])

            # Parse offset value with hex support
            offset_str = parts[1]
            if offset_str.startswith('0x'):
                offset = int(offset_str, 16)
            else:
                offset = int(offset_str)

            address = base_reg - BitVecVal(offset, 64)
        else:
            # Format like [rax]
            address = env.get_register(mem_ref)

        # Get the value at this memory address
        return env.get_memory(address), 'memory'

    # Handle other operand types as needed

    raise ValueError(f"Unknown operand format: {operand}")


def generate_constraint(instruction, semantics, env):
    """
    Generate a constraint from instruction semantics

    Args:
        instruction: Instruction object
        semantics: InstructionSemantics object
        env: Symbolic environment

    Returns:
        constraint: Z3 constraint or None if no constraint
    """
    precondition = semantics.precondition

    # If precondition is "1", it's always true (no constraint)
    if precondition == "1":
        return None

    # Handle flag-based conditions
    flag_conditions = {
        "ZF == 0": Not(env.get_flag("ZF")),
        "ZF == 1": env.get_flag("ZF"),
        "SF == 0": Not(env.get_flag("SF")),
        "SF == 1": env.get_flag("SF"),
        "CF == 0": Not(env.get_flag("CF")),
        "CF == 1": env.get_flag("CF"),
        "OF == 0": Not(env.get_flag("OF")),
        "OF == 1": env.get_flag("OF")
    }

    if precondition in flag_conditions:
        return flag_conditions[precondition]

    # Handle custom or more complex preconditions
    # This would need to be expanded based on actual semantics

    return None