from z3 import *
from constraint_generator import parse_operand

"""
Consolidated implementation of basic symbolic operations and instruction handlers
"""


#############################################################
# Basic Symbolic Operations
#############################################################

def BIN_COPY(env, dest, source):
    """
    Basic symbolic copy operation

    Args:
        env: Symbolic environment
        dest: Destination operand (string or value)
        source: Source operand (string or value)
    """
    # Parse source value
    source_value = parse_value(source, env)

    # Store the value
    store_value(env, dest, source_value)


def BIN_ADD(env, dest, source):
    """
    Basic symbolic addition operation

    Args:
        env: Symbolic environment
        dest: Destination operand
        source: Source operand
    """
    dest_value = get_value(dest, env)
    source_value = parse_value(source, env)

    # Ensure both operands have the same bit width
    dest_size = dest_value.size()
    source_size = source_value.size()
    
    if dest_size != source_size:
        if dest_size < source_size:
            # Truncate source to match destination size
            source_value = Extract(dest_size - 1, 0, source_value)
        else:
            # Zero-extend source to match destination size
            source_value = ZeroExt(dest_size - source_size, source_value)

    # Perform addition
    result = dest_value + source_value

    # Store result
    store_value(env, dest, result)

    # Update flags
    update_flags_after_add(env, dest_value, source_value, result)


def BIN_SUB(env, dest, source):
    """
    Basic symbolic subtraction operation

    Args:
        env: Symbolic environment
        dest: Destination operand
        source: Source operand
    """
    dest_value = get_value(dest, env)
    source_value = parse_value(source, env)

    # Ensure both operands have the same bit width
    dest_size = dest_value.size()
    source_size = source_value.size()
    
    if dest_size != source_size:
        if dest_size < source_size:
            # Truncate source to match destination size
            source_value = Extract(dest_size - 1, 0, source_value)
        else:
            # Zero-extend source to match destination size
            source_value = ZeroExt(dest_size - source_size, source_value)

    # Perform subtraction
    result = dest_value - source_value

    # Store result
    store_value(env, dest, result)

    # Update flags
    update_flags_after_sub(env, dest_value, source_value, result)


def BIN_AND(env, dest, source):
    """
    Basic symbolic AND operation

    Args:
        env: Symbolic environment
        dest: Destination operand
        source: Source operand
    """
    dest_value = get_value(dest, env)
    source_value = parse_value(source, env)

    # Perform AND operation - Z3 will handle the symbolic rules:
    # 0 & $ = 0
    # 1 & $ = $
    # $ & $ = $
    result = dest_value & source_value

    # Store result
    store_value(env, dest, result)

    # Update flags
    update_flags_after_logical(env, result)


def BIN_XOR(env, dest, source):
    """
    Basic symbolic XOR operation

    Args:
        env: Symbolic environment
        dest: Destination operand
        source: Source operand
    """
    dest_value = get_value(dest, env)
    source_value = parse_value(source, env)

    # Perform XOR operation - Z3 will handle the symbolic rules:
    # 0 ^ $ = $
    # 1 ^ $ = !$
    # $ ^ $ = 0 (for same symbolic values)
    result = dest_value ^ source_value

    # Store result
    store_value(env, dest, result)

    # Update flags
    update_flags_after_logical(env, result)


def BIN_TEST(env, op1, op2):
    """
    Basic symbolic TEST operation (AND without storing result)

    Args:
        env: Symbolic environment
        op1: First operand
        op2: Second operand
    """
    op1_value = parse_value(op1, env)
    op2_value = parse_value(op2, env)

    # Perform AND but don't store
    result = op1_value & op2_value

    # Update flags only
    update_flags_after_logical(env, result)


def BIN_NEG(env, op):
    """
    Basic symbolic negation operation

    Args:
        env: Symbolic environment
        op: Operand to negate
    """
    op_value = get_value(op, env)

    # Perform two's complement negation
    result = 0 - op_value

    # Store result
    store_value(env, op, result)

    # Update flags
    env.set_flag('ZF', result == 0)
    env.set_flag('SF', Extract(result.size() - 1, result.size() - 1, result) == 1)
    env.set_flag('CF', result != 0)  # CF=0 only if operand=0

    # OF=1 only if operand=MIN_INT
    min_int = BitVecVal(1 << (op_value.size() - 1), op_value.size())
    env.set_flag('OF', op_value == min_int)


#############################################################
# Helper Functions
#############################################################

def parse_value(operand, env):
    """
    Parse operand to get its value

    Args:
        operand: Operand to parse
        env: Symbolic environment

    Returns:
        Z3 BitVec value
    """
    if not isinstance(operand, str):
        return operand

    # Handle address calculation for LEA
    if operand.startswith('*'):
        return calculate_address(operand[1:], env)

    # Handle arithmetic expressions with +
    if '+' in operand and not (('[' in operand and ']' in operand)):
        parts = [p.strip() for p in operand.split('+')]
        result = parse_value(parts[0], env)
        for part in parts[1:]:
            result = result + parse_value(part, env)
        return result

    # Handle arithmetic expressions with *
    if '*' in operand and not operand.startswith('*') and not (('[' in operand and ']' in operand)):
        parts = [p.strip() for p in operand.split('*')]
        result = parse_value(parts[0], env)
        for part in parts[1:]:
            result = result * parse_value(part, env)
        return result

    # Handle normal operand
    value, _ = parse_operand(operand, env)
    return value

def get_value(operand, env):
    """
    Get value from a destination operand

    Args:
        operand: Destination operand
        env: Symbolic environment

    Returns:
        Z3 BitVec current value
    """
    if not isinstance(operand, str):
        return operand

    
    if operand in env.REG_SIZES or operand in env.REG_PARENT:
        return env.get_register(operand)
    else:
        value, _ = parse_operand(operand, env)
        return value


def store_value(env, dest, value):
    """
    Store value to destination

    Args:
        env: Symbolic environment
        dest: Destination operand
        value: Value to store
    """
    if not isinstance(dest, str):
        return

    if dest in env.REG_SIZES or dest in env.REG_PARENT:
        env.set_register(dest, value)
    elif '[' in dest and ']' in dest:
        mem_ref = dest[dest.index('[') + 1:dest.index(']')]
        addr_value, _ = parse_operand(f"[{mem_ref}]", env)
        env.set_memory(addr_value, value)
    else:
        raise ValueError(f"Unsupported destination: {dest}")


def calculate_address(addr_expr, env):
    """
    Calculate effective address from expression

    Args:
        addr_expr: Address expression
        env: Symbolic environment

    Returns:
        Z3 BitVec address
    """
    if '[' in addr_expr and ']' in addr_expr:
        addr_components = addr_expr[addr_expr.index('[') + 1:addr_expr.index(']')]

        # First, handle any multiplication within the address
        # For expressions like [base + index*scale + disp]
        if '*' in addr_components:
            new_components = []
            for component in addr_components.split('+'):
                component = component.strip()
                if '*' in component:
                    # Handle index*scale
                    mul_parts = component.split('*')
                    if len(mul_parts) == 2:
                        index = mul_parts[0].strip()
                        scale = mul_parts[1].strip()

                        # Get index value
                        if index in env.REG_SIZES:
                            index_val = env.get_register(index)
                        else:
                            # Try parsing as a number
                            try:
                                if index.startswith('0x'):
                                    index_val = BitVecVal(int(index, 16), 64)
                                else:
                                    index_val = BitVecVal(int(index), 64)
                            except ValueError:
                                # Use symbolic value if parsing fails
                                index_val = env.create_fresh_symbol(f"index_{index}", 64)

                        # Get scale value
                        try:
                            if scale.startswith('0x'):
                                scale_val = BitVecVal(int(scale, 16), 64)
                            else:
                                scale_val = BitVecVal(int(scale), 64)
                        except ValueError:
                            if scale in env.REG_SIZES:
                                scale_val = env.get_register(scale)
                            else:
                                # Use symbolic value if parsing fails
                                scale_val = env.create_fresh_symbol(f"scale_{scale}", 64)

                        # Add the product to components
                        new_components.append(index_val * scale_val)
                    else:
                        # Just add the original if parsing fails
                        new_components.append(component)
                else:
                    new_components.append(component)

            # Replace addr_components with the modified version
            addr_components = ' + '.join([str(c) for c in new_components])

        # Now handle addition and subtraction
        components = []
        if '+' in addr_components:
            for part in addr_components.split('+'):
                part = part.strip()
                if part in env.REG_SIZES:
                    components.append(env.get_register(part))
                elif part.startswith('0x') or part.isdigit():
                    if part.startswith('0x'):
                        value = int(part, 16)
                    else:
                        value = int(part)
                    components.append(BitVecVal(value, 64))
                else:
                    # If we can't parse, add a symbolic value
                    components.append(env.create_fresh_symbol(f"addr_part_{part}", 64))
        elif '-' in addr_components:
            # Handle subtraction in address calculation
            parts = [p.strip() for p in addr_components.split('-')]
            base_reg = env.get_register(parts[0]) if parts[0] in env.REG_SIZES else env.create_fresh_symbol(
                f"base_{parts[0]}", 64)

            # Parse offset
            offset_str = parts[1]
            if offset_str.startswith('0x'):
                offset = int(offset_str, 16)
            elif offset_str.isdigit():
                offset = int(offset_str)
            elif offset_str in env.REG_SIZES:
                return base_reg - env.get_register(offset_str)
            else:
                offset = env.create_fresh_symbol(f"offset_{offset_str}", 64)

            return base_reg - BitVecVal(offset, 64) if isinstance(offset, int) else base_reg - offset
        else:
            if addr_components in env.REG_SIZES:
                components.append(env.get_register(addr_components))
            else:
                # If we can't parse, add a symbolic value
                components.append(env.create_fresh_symbol(f"addr_{addr_components}", 64))

        # Calculate address by adding components
        if components:
            address = components[0]
            for component in components[1:]:
                address = address + component
            return address

    # Return symbolic address for unsupported expressions
    return env.create_fresh_symbol("addr", 64)


def update_flags_after_add(env, dest, source, result):
    """
    Update flags after addition

    Args:
        env: Symbolic environment
        dest: Destination value
        source: Source value
        result: Result value
    """
    env.set_flag('ZF', result == 0)
    env.set_flag('SF', Extract(result.size() - 1, result.size() - 1, result) == 1)
    env.set_flag('CF', ULT(result, dest))  # Carry if result < original (unsigned)
    env.set_flag('OF', And(
        Extract(dest.size() - 1, dest.size() - 1, dest) ==
        Extract(source.size() - 1, source.size() - 1, source),
        Extract(result.size() - 1, result.size() - 1, result) !=
        Extract(dest.size() - 1, dest.size() - 1, dest)
    ))  # Overflow if sign bit changes unexpectedly


def update_flags_after_sub(env, dest, source, result):
    """
    Update flags after subtraction

    Args:
        env: Symbolic environment
        dest: Destination value
        source: Source value
        result: Result value
    """
    env.set_flag('ZF', result == 0)
    env.set_flag('SF', Extract(result.size() - 1, result.size() - 1, result) == 1)
    env.set_flag('CF', ULT(dest, source))  # Carry if dest < source (unsigned)
    env.set_flag('OF', And(
        Extract(dest.size() - 1, dest.size() - 1, dest) !=
        Extract(source.size() - 1, source.size() - 1, source),
        Extract(result.size() - 1, result.size() - 1, result) !=
        Extract(dest.size() - 1, dest.size() - 1, dest)
    ))  # Overflow if sign bit changes unexpectedly


def update_flags_after_logical(env, result):
    """
    Update flags after logical operations (AND, OR, XOR)

    Args:
        env: Symbolic environment
        result: Result value
    """
    env.set_flag('ZF', result == 0)
    env.set_flag('SF', Extract(result.size() - 1, result.size() - 1, result) == 1)
    env.set_flag('CF', BoolVal(False))  # Logical ops clear CF
    env.set_flag('OF', BoolVal(False))  # Logical ops clear OF


#############################################################
# Instruction implementations using basic operations
#############################################################

def sym_mov(env, dest, source):
    """
    Implementation of MOV instruction using basic operations

    Args:
        env: Symbolic environment
        dest: Destination operand
        source: Source operand
    """
    BIN_COPY(env, dest, source)


def sym_lea(env, dest, source):
    """
    Implementation of LEA instruction using basic operations

    Args:
        env: Symbolic environment
        dest: Destination register
        source: Source effective address
    """
    # For LEA, the source is the address expression, we need to prefix with *
    BIN_COPY(env, dest, f"*{source}")


def sym_add(env, dest, source):
    """
    Implementation of ADD instruction using basic operations

    Args:
        env: Symbolic environment
        dest: Destination operand
        source: Source operand
    """
    BIN_ADD(env, dest, source)


def sym_sub(env, dest, source):
    """
    Implementation of SUB instruction using basic operations

    Args:
        env: Symbolic environment
        dest: Destination operand
        source: Source operand
    """
    BIN_SUB(env, dest, source)


def sym_and(env, dest, source):
    """
    Implementation of symbolic AND operation using basic operations

    Args:
        env: Symbolic environment
        dest: Destination operand
        source: Source operand
    """
    BIN_AND(env, dest, source)


def sym_movzx(env, source, dest):
    """
    Implementation of symbolic MOVZX (move with zero extend) operation

    Args:
        env: Symbolic environment
        source: Source operand
        dest: Destination operand
    """
    BIN_COPY(env, source, dest)


def sym_movsxd(env, source, dest):
    """
    Implementation of symbolic MOVSXD (move with sign extend doubleword) operation

    Args:
        env: Symbolic environment
        source: Source operand
        dest: Destination operand
    """
    BIN_COPY(env, source, dest)


def sym_xor(env, dest, source):
    """
    Implementation of symbolic XOR operation using basic operations

    Args:
        env: Symbolic environment
        dest: Destination operand
        source: Source operand
    """
    BIN_XOR(env, dest, source)


def sym_test(env, op1, op2):
    """
    Implementation of TEST instruction using basic operations

    Args:
        env: Symbolic environment
        op1: First operand
        op2: Second operand
    """
    BIN_TEST(env, op1, op2)


def sym_neg(env, operand):
    """
    Implementation of NEG instruction using basic operations

    Args:
        env: Symbolic environment
        operand: Operand to negate
    """
    BIN_NEG(env, operand)


#############################################################
# Existing instruction handlers that we'll keep
#############################################################

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


#############################################################
# Map of instruction opcodes to their postcondition functions
#############################################################

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
    'nop': sym_nop,
    'movzx': sym_movzx,
    'movsxd': sym_movsxd
}