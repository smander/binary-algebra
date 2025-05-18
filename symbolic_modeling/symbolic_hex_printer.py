def value_to_symbolic_hex(value):
    """
    Convert a Z3 value to a symbolic hex representation

    Args:
        value: Z3 value (bit vector or expression)

    Returns:
        str: Symbolic hex representation using $ for symbolic bits
    """
    import z3

    # Try to check if value is concrete
    try:
        if z3.is_bv_value(value):
            concrete_value = value.as_long()
            # Value is concrete, convert to hex
            hex_str = hex(concrete_value)[2:]
            # Ensure even length
            if len(hex_str) % 2 != 0:
                hex_str = '0' + hex_str
            return hex_str
    except:
        pass

    # Check if it's a simple symbolic variable
    try:
        if z3.is_const(value) and value.decl().kind() == z3.Z3_OP_UNINTERPRETED:
            # Simple symbolic variable
            # Return all $ for the appropriate length
            bit_size = value.size() if hasattr(value, 'size') else 64
            nibble_count = (bit_size + 3) // 4
            return '$' * nibble_count
    except:
        pass

    # Handle boolean expressions
    try:
        if z3.is_bool(value):
            if z3.is_true(value):
                return "1"
            elif z3.is_false(value):
                return "0"
            else:
                return "$"  # Symbolic boolean
    except:
        pass

    # Handle complex expressions - special cases
    try:
        # For equality expressions like "x == y"
        if z3.is_eq(value):
            return "$"  # Symbolic boolean

        # For extract expressions like "Extract(63, 63, x)"
        if str(value.decl()) == "Extract":
            return "$"  # Part of a bit vector, so symbolic
    except:
        pass

    # For any other expression, just use $ to indicate it's symbolic
    try:
        if hasattr(value, 'size'):
            bit_size = value.size()
            nibble_count = (bit_size + 3) // 4
            return '$' * nibble_count
    except:
        pass

    # Last resort - just return $ for any symbolic value
    return "$"


def flag_to_symbolic(flag_value):
    """
    Convert a flag value to a symbolic representation

    Args:
        flag_value: Flag value (Z3 expression)

    Returns:
        str: Symbolic representation
    """
    import z3

    try:
        # Try to get concrete value
        if z3.is_true(flag_value):
            return "1"
        elif z3.is_false(flag_value):
            return "0"
    except:
        pass

    # Check if it's a simple comparison
    try:
        if z3.is_eq(flag_value):
            return "$"
    except:
        pass

    # For complex expressions
    return "$"


def pretty_print_state(env):
    """
    Print a user-friendly representation of the symbolic state

    Args:
        env: Symbolic environment
    """
    print("Registers:")
    for reg in sorted(env.registers.keys()):
        value = env.registers[reg]
        sym_hex = value_to_symbolic_hex(value)
        print(f"  {reg}: {sym_hex}")

    print("\nFlags:")
    for flag in sorted(env.flags.keys()):
        value = env.flags[flag]
        sym_value = flag_to_symbolic(value)
        print(f"  {flag}: {sym_value}")

    print("\nMemory:")
    for addr in env.memory.keys():
        value = env.memory[addr]
        sym_hex = value_to_symbolic_hex(value)
        print(f"  {addr}: {sym_hex}")