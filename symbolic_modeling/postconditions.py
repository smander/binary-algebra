from z3 import *
from constraint_generator import parse_operand


def sym_copy(env, dest, source):
    """
    Symbolic copy operation (BIN_COPY) from source to destination

    Args:
        env: Symbolic environment
        dest: Destination operand
        source: Source operand
    """
    # Parse source operand
    source_value, source_type = parse_operand(source, env)

    # Handle destination based on its type
    if dest in env.REG_SIZES:
        # Destination is a register
        env.set_register(dest, source_value)
    elif '[' in dest and ']' in dest:
        # Destination is a memory reference
        mem_ref = dest[dest.index('[') + 1:dest.index(']')]
        # Parse memory address
        addr_value, _ = parse_operand(f"[{mem_ref}]", env)
        # Set memory at this address
        env.set_memory(addr_value, source_value)
    else:
        raise ValueError(f"Unsupported destination operand format: {dest}")


def sym_mov(env, dest, source):
    """
    Implementation of MOV instruction

    Args:
        env: Symbolic environment
        dest: Destination operand
        source: Source operand
    """
    # Parse source operand
    source_value, source_type = parse_operand(source, env)

    # Handle destination based on its type
    if dest in env.REG_SIZES:
        # Destination is a register
        env.set_register(dest, source_value)
    elif '[' in dest and ']' in dest:
        # Destination is a memory reference
        mem_ref = dest[dest.index('[') + 1:dest.index(']')]
        # Parse memory address
        addr_value, _ = parse_operand(f"[{mem_ref}]", env)
        # Set memory at this address
        env.set_memory(addr_value, source_value)
    else:
        raise ValueError(f"Unsupported destination operand format: {dest}")


def sym_lea(env, dest, source):
    """
    Implementation of LEA instruction

    Args:
        env: Symbolic environment
        dest: Destination register
        source: Source effective address
    """
    # For LEA, we calculate the effective address but don't dereference it
    if '[' in source and ']' in source:
        address_expr = source[source.index('[') + 1:source.index(']')]

        # Parse components of the address
        components = []
        if '+' in address_expr:
            for part in address_expr.split('+'):
                part = part.strip()
                if part in env.REG_SIZES:
                    components.append(env.get_register(part))
                elif part.startswith('0x') or part.isdigit():
                    if part.startswith('0x'):
                        value = int(part, 16)
                    else:
                        value = int(part)
                    components.append(BitVecVal(value, 64))
        elif address_expr in env.REG_SIZES:
            components.append(env.get_register(address_expr))

        # Calculate effective address
        if components:
            address = components[0]
            for component in components[1:]:
                address = address + component
        else:
            # Default to symbolic address if we can't parse
            address = env.create_fresh_symbol("lea_addr", 64)

        # Set destination register to the calculated address
        if dest in env.REG_SIZES:
            env.set_register(dest, address)


def sym_add(env, dest, source):
    """
    Implementation of ADD instruction

    Args:
        env: Symbolic environment
        dest: Destination operand
        source: Source operand
    """
    # Parse operands
    if dest in env.REG_SIZES:
        dest_value = env.get_register(dest)
        dest_type = 'register'
    else:
        dest_value, dest_type = parse_operand(dest, env)

    source_value, source_type = parse_operand(source, env)

    # Perform addition
    result = dest_value + source_value

    # Update destination
    if dest_type == 'register':
        env.set_register(dest, result)
    elif dest_type == 'memory':
        mem_ref = dest[dest.index('[') + 1:dest.index(']')]
        addr_value, _ = parse_operand(f"[{mem_ref}]", env)
        env.set_memory(addr_value, result)

    # Update flags
    env.set_flag('ZF', result == 0)
    env.set_flag('SF', Extract(result.size() - 1, result.size() - 1, result) == 1)
    # Simplified carry and overflow flags
    env.set_flag('CF', ULT(result, dest_value))  # Carry if result < original value (unsigned)
    env.set_flag('OF', And(
        Extract(dest_value.size() - 1, dest_value.size() - 1, dest_value) ==
        Extract(source_value.size() - 1, source_value.size() - 1, source_value),
        Extract(result.size() - 1, result.size() - 1, result) !=
        Extract(dest_value.size() - 1, dest_value.size() - 1, dest_value)
    ))  # Overflow if sign bit changes unexpectedly


def sym_sub(env, dest, source):
    """
    Implementation of SUB instruction

    Args:
        env: Symbolic environment
        dest: Destination operand
        source: Source operand
    """
    # Parse operands - fix the logic to avoid referencing dest_type before it's defined
    if dest in env.REG_SIZES:
        dest_value = env.get_register(dest)
        dest_type = 'register'
    else:
        dest_value, dest_type = parse_operand(dest, env)

    source_value, source_type = parse_operand(source, env)

    # Perform subtraction
    result = dest_value - source_value

    # Update destination
    if dest_type == 'register':
        env.set_register(dest, result)
    elif dest_type == 'memory':
        mem_ref = dest[dest.index('[') + 1:dest.index(']')]
        addr_value, _ = parse_operand(f"[{mem_ref}]", env)
        env.set_memory(addr_value, result)

    # Update flags
    env.set_flag('ZF', result == 0)
    env.set_flag('SF', Extract(result.size() - 1, result.size() - 1, result) == 1)
    # Simplified carry and overflow flags
    env.set_flag('CF', ULT(dest_value, source_value))  # Carry if dest < source (unsigned)
    env.set_flag('OF', And(
        Extract(dest_value.size() - 1, dest_value.size() - 1, dest_value) !=
        Extract(source_value.size() - 1, source_value.size() - 1, source_value),
        Extract(result.size() - 1, result.size() - 1, result) !=
        Extract(dest_value.size() - 1, dest_value.size() - 1, dest_value)
    ))  # Overflow if sign bit changes unexpectedly


def sym_and(env, dest, source):
    """
    Implementation of symbolic AND operation (BIN_AND)

    Rules:
    - 0 & $ = 0 (any bit AND with 0 is 0)
    - 1 & $ = $ (any bit AND with 1 preserves the bit)
    - $ & $ = $ (symbolic AND symbolic remains symbolic)

    Args:
        env: Symbolic environment
        dest: Destination operand
        source: Source operand
    """
    # Parse operands - use the same correct pattern as in sym_sub
    if dest in env.REG_SIZES:
        dest_value = env.get_register(dest)
        dest_type = 'register'
    else:
        dest_value, dest_type = parse_operand(dest, env)

    source_value, source_type = parse_operand(source, env)

    # Perform symbolic AND operation
    # Z3's bitwise operators already handle the symbolic rules correctly
    result = dest_value & source_value

    # Update destination
    if dest_type == 'register':
        env.set_register(dest, result)
    elif dest_type == 'memory':
        mem_ref = dest[dest.index('[') + 1:dest.index(']')]
        # Parse memory address
        addr_value, _ = parse_operand(f"[{mem_ref}]", env)
        # Set memory at this address
        env.set_memory(addr_value, result)

    # Update flags
    env.set_flag('ZF', result == 0)
    env.set_flag('SF', Extract(result.size() - 1, result.size() - 1, result) == 1)
    env.set_flag('OF', BoolVal(False))  # AND clears OF
    env.set_flag('CF', BoolVal(False))  # AND clears CF


def sym_xor(env, dest, source):
    """
    Implementation of symbolic XOR operation (BIN_XOR)

    Rules:
    - 0 ^ $ = $ (any bit XOR with 0 preserves the bit)
    - 1 ^ $ = !$ (any bit XOR with 1 inverts the bit)
    - $ ^ $ = 0 (same symbolic bits XOR to 0)

    Args:
        env: Symbolic environment
        dest: Destination operand
        source: Source operand
    """
    # Parse operands - use the same correct pattern as in sym_sub
    if dest in env.REG_SIZES:
        dest_value = env.get_register(dest)
        dest_type = 'register'
    else:
        dest_value, dest_type = parse_operand(dest, env)

    source_value, source_type = parse_operand(source, env)

    # Perform symbolic XOR operation
    # Z3's bitwise operators already handle the symbolic rules correctly
    result = dest_value ^ source_value

    # Update destination
    if dest_type == 'register':
        env.set_register(dest, result)
    elif dest_type == 'memory':
        mem_ref = dest[dest.index('[') + 1:dest.index(']')]
        # Parse memory address
        addr_value, _ = parse_operand(f"[{mem_ref}]", env)
        # Set memory at this address
        env.set_memory(addr_value, result)

    # Update flags
    env.set_flag('ZF', result == 0)
    env.set_flag('SF', Extract(result.size() - 1, result.size() - 1, result) == 1)
    env.set_flag('OF', BoolVal(False))  # XOR clears OF
    env.set_flag('CF', BoolVal(False))  # XOR clears CF


def sym_test(env, op1, op2):
    """
    Implementation of TEST instruction

    Args:
        env: Symbolic environment
        op1: First operand
        op2: Second operand
    """
    # Parse operands
    op1_value, op1_type = parse_operand(op1, env)
    op2_value, op2_type = parse_operand(op2, env)

    # Perform AND operation (but don't store result)
    result = op1_value & op2_value

    # Update flags only
    env.set_flag('ZF', result == 0)
    env.set_flag('SF', Extract(result.size() - 1, result.size() - 1, result) == 1)
    env.set_flag('OF', BoolVal(False))  # TEST clears OF
    env.set_flag('CF', BoolVal(False))  # TEST clears CF


def sym_neg(env, operand):
    """
    Implementation of NEG instruction

    Args:
        env: Symbolic environment
        operand: Operand to negate
    """
    # Parse operand
    if operand in env.REG_SIZES:
        value = env.get_register(operand)
        operand_type = 'register'
    else:
        value, operand_type = parse_operand(operand, env)

    # Calculate two's complement negation
    result = 0 - value

    # Update operand
    if operand_type == 'register':
        env.set_register(operand, result)
    elif operand_type == 'memory':
        mem_ref = operand[operand.index('[') + 1:operand.index(']')]
        addr_value, _ = parse_operand(f"[{mem_ref}]", env)
        env.set_memory(addr_value, result)

    # Update flags
    env.set_flag('ZF', result == 0)
    env.set_flag('SF', Extract(result.size() - 1, result.size() - 1, result) == 1)
    env.set_flag('CF', result != 0)  # CF=0 only if operand=0

    # OF=1 only if operand=MIN_INT (negating would overflow)
    # For 64-bit, that's 0x8000000000000000 (most negative value)
    min_int = BitVecVal(1 << (value.size() - 1), value.size())
    env.set_flag('OF', value == min_int)


def sym_push(env, operand):
    """
    Implementation of PUSH instruction

    Args:
        env: Symbolic environment
        operand: Value to push onto stack
    """
    # Parse operand
    value, _ = parse_operand(operand, env)

    # Get current stack pointer
    rsp = env.get_register('rsp')

    # Decrement stack pointer (8 bytes for 64-bit mode)
    new_rsp = rsp - BitVecVal(8, 64)

    # Update stack pointer
    env.set_register('rsp', new_rsp)

    # Store value at new stack pointer
    env.set_memory(new_rsp, value)


def sym_pop(env, operand):
    """
    Implementation of POP instruction

    Args:
        env: Symbolic environment
        operand: Destination for popped value
    """
    # Get current stack pointer
    rsp = env.get_register('rsp')

    # Get value from stack
    value = env.get_memory(rsp)

    # Increment stack pointer (8 bytes for 64-bit mode)
    new_rsp = rsp + BitVecVal(8, 64)

    # Update stack pointer
    env.set_register('rsp', new_rsp)

    # Store value to destination
    if operand in env.REG_SIZES:
        env.set_register(operand, value)
    elif '[' in operand and ']' in operand:
        mem_ref = operand[operand.index('[') + 1:operand.index(']')]
        addr_value, _ = parse_operand(f"[{mem_ref}]", env)
        env.set_memory(addr_value, value)
    else:
        raise ValueError(f"Unsupported POP destination: {operand}")


def sym_jne(env, target):
    """
    Implementation of JNE instruction

    Args:
        env: Symbolic environment
        target: Jump target
    """
    # JNE is conditional on ZF = 0
    # No need to implement jump logic here as the symbolic execution
    # will handle branching based on constraints
    pass


def sym_js(env, target):
    """
    Implementation of JS instruction

    Args:
        env: Symbolic environment
        target: Jump target
    """
    # JS is conditional on SF = 1
    # No need to implement jump logic here as it's handled by preconditions
    pass


def sym_jle(env, target):
    """
    Implementation of JLE instruction

    Args:
        env: Symbolic environment
        target: Jump target
    """
    # JLE is conditional on ZF = 1 or SF != OF
    # No need to implement jump logic here
    pass


def sym_jmp(env, target):
    """
    Implementation of JMP instruction

    Args:
        env: Symbolic environment
        target: Jump target
    """
    # Unconditional jump
    # No need to implement jump logic here as it's handled by the execution engine
    pass


def sym_syscall(env):
    """
    Implementation of SYSCALL instruction

    Args:
        env: Symbolic environment
    """
    # Placeholder for syscall implementation
    # In a real implementation, this would handle system calls based on rax value
    pass


def sym_endbr64(env):
    """
    Implementation of ENDBR64 instruction

    Args:
        env: Symbolic environment
    """
    # No effect in our model
    pass


def sym_nop(env):
    """
    Implementation of NOP instruction

    Args:
        env: Symbolic environment
    """
    # NOP does nothing
    pass


# Map of instruction opcodes to their postcondition functions
POSTCONDITION_MAP = {
    'mov': sym_mov,
    'lea': sym_lea,
    'add': sym_add,
    'sub': sym_sub,
    'and': sym_and,
    'xor': sym_xor,
    'test': sym_test,
    'neg': sym_neg,
    'push': sym_push,
    'pop': sym_pop,
    'jne': sym_jne,
    'js': sym_js,
    'jle': sym_jle,
    'jmp': sym_jmp,
    'syscall': sym_syscall,
    'endbr64': sym_endbr64,
    'nop': sym_nop
}