"""
Symbolic Environment for Intel x86 instructions
"""

import z3


class SymbolicEnvironment:
    # Register sizes in bits
    REG_SIZES = {
        'rax': 64, 'eax': 32, 'ax': 16, 'ah': 8, 'al': 8,
        'rbx': 64, 'ebx': 32, 'bx': 16, 'bh': 8, 'bl': 8,
        'rcx': 64, 'ecx': 32, 'cx': 16, 'ch': 8, 'cl': 8,
        'rdx': 64, 'edx': 32, 'dx': 16, 'dh': 8, 'dl': 8,
        'rsi': 64, 'esi': 32, 'si': 16, 'sil': 8,
        'rdi': 64, 'edi': 32, 'di': 16, 'dil': 8,
        'rbp': 64, 'ebp': 32, 'bp': 16, 'bpl': 8,
        'rsp': 64, 'esp': 32, 'sp': 16, 'spl': 8,
        'r8': 64, 'r8d': 32, 'r8w': 16, 'r8b': 8,
        'r9': 64, 'r9d': 32, 'r9w': 16, 'r9b': 8,
        'r10': 64, 'r10d': 32, 'r10w': 16, 'r10b': 8,
        'r11': 64, 'r11d': 32, 'r11w': 16, 'r11b': 8,
        'r12': 64, 'r12d': 32, 'r12w': 16, 'r12b': 8,
        'r13': 64, 'r13d': 32, 'r13w': 16, 'r13b': 8,
        'r14': 64, 'r14d': 32, 'r14w': 16, 'r14b': 8,
        'r15': 64, 'r15d': 32, 'r15w': 16, 'r15b': 8,
        'rip': 64
    }

    # Mapping of sub-registers to their parent 64-bit register
    REG_PARENT = {
        'eax': 'rax', 'ax': 'rax', 'ah': 'rax', 'al': 'rax',
        'ebx': 'rbx', 'bx': 'rbx', 'bh': 'rbx', 'bl': 'rbx',
        'ecx': 'rcx', 'cx': 'rcx', 'ch': 'rcx', 'cl': 'rcx',
        'edx': 'rdx', 'dx': 'rdx', 'dh': 'rdx', 'dl': 'rdx',
        'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
        'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
        'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
        'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp',
        'r8d': 'r8', 'r8w': 'r8', 'r8b': 'r8',
        'r9d': 'r9', 'r9w': 'r9', 'r9b': 'r9',
        'r10d': 'r10', 'r10w': 'r10', 'r10b': 'r10',
        'r11d': 'r11', 'r11w': 'r11', 'r11b': 'r11',
        'r12d': 'r12', 'r12w': 'r12', 'r12b': 'r12',
        'r13d': 'r13', 'r13w': 'r13', 'r13b': 'r13',
        'r14d': 'r14', 'r14w': 'r14', 'r14b': 'r14',
        'r15d': 'r15', 'r15w': 'r15', 'r15b': 'r15'
    }

    def __init__(self):
        # Initialize registers with symbolic values
        self.registers = self._init_registers()
        # Initialize flags
        self.flags = self._init_flags()
        # Initialize memory (sparse representation)
        self.memory = {}
        # Accumulated constraints
        self.constraints = []
        # Unique counter for creating symbolic variables
        self.sym_counter = 0
        # Map to track complex arithmetic operations
        self.complex_ops = set()

    def _init_registers(self):
        # Create symbolic variables for all 64-bit registers
        registers = {}
        for reg, size in self.REG_SIZES.items():
            if size == 64:
                if reg == 'rsp':
                    # Set RSP to 2^64 - 1
                    registers[reg] = z3.BitVecVal(2 ** 64 - 1, 64)
                elif reg == 'rip':
                    # Set RIP to a concrete value
                    registers[reg] = z3.BitVecVal(0, 64)
                else:
                    # Initialize other 64-bit registers with symbolic values
                    registers[reg] = z3.BitVec(f"{reg}_0", 64)

        return registers

    def _init_flags(self):
        # Initialize flags with symbolic values
        flags = {
            'ZF': z3.Bool('ZF_0'),
            'SF': z3.Bool('SF_0'),
            'CF': z3.Bool('CF_0'),
            'OF': z3.Bool('OF_0')
        }
        return flags

    def create_fresh_symbol(self, name, size):
        """Create a fresh symbolic variable with a unique name"""
        self.sym_counter += 1
        return z3.BitVec(f"{name}_{self.sym_counter}", size)

    def get_register(self, reg_name):
        """Get the value of a register, handling sub-registers appropriately"""
        if reg_name in self.registers:
            return self.registers[reg_name]

        if reg_name in self.REG_PARENT:
            parent = self.REG_PARENT[reg_name]
            parent_value = self.registers[parent]
            size = self.REG_SIZES[reg_name]

            # Extract the appropriate bits based on the register name
            if reg_name.endswith('d'):  # 32-bit
                return z3.Extract(31, 0, parent_value)
            elif reg_name.endswith('w'):  # 16-bit
                return z3.Extract(15, 0, parent_value)
            elif reg_name.endswith('l'):  # Lower 8-bit
                return z3.Extract(7, 0, parent_value)
            elif reg_name.endswith('h'):  # Higher 8-bit
                return z3.Extract(15, 8, parent_value)

        raise ValueError(f"Unknown register: {reg_name}")

    def set_register(self, reg_name, value):
        """Set the value of a register, handling sub-registers appropriately"""
        if reg_name in self.registers:
            self.registers[reg_name] = value
            return

        if reg_name in self.REG_PARENT:
            parent = self.REG_PARENT[reg_name]
            parent_value = self.registers[parent]

            # Update the appropriate bits based on the register name
            if reg_name.endswith('d'):  # 32-bit
                # Clear upper 32 bits, set lower 32 bits
                self.registers[parent] = z3.Concat(
                    z3.Extract(63, 32, parent_value),
                    value
                )
            elif reg_name.endswith('w'):  # 16-bit
                # Clear bits 15-0, set with new value
                self.registers[parent] = z3.Concat(
                    z3.Extract(63, 16, parent_value),
                    value
                )
            elif reg_name.endswith('l'):  # Lower 8-bit
                # Clear bits 7-0, set with new value
                self.registers[parent] = z3.Concat(
                    z3.Extract(63, 8, parent_value),
                    value
                )
            elif reg_name.endswith('h'):  # Higher 8-bit
                # Clear bits 15-8, set with new value
                self.registers[parent] = z3.Concat(
                    z3.Extract(63, 16, parent_value),
                    z3.Concat(value, z3.Extract(7, 0, parent_value))
                )
            return

        raise ValueError(f"Unknown register: {reg_name}")

    def get_memory(self, address, size=8):
        """Get value from memory at the given address with specified size (in bytes)"""
        if address in self.memory:
            return self.memory[address]

        # Create a new symbolic variable for this memory location
        sym_var = self.create_fresh_symbol(f"mem_{address}", size * 8)
        self.memory[address] = sym_var
        return sym_var

    def set_memory(self, address, value, size=8):
        """Set value in memory at the given address with specified size (in bytes)"""
        self.memory[address] = value

    def get_flag(self, flag_name):
        """Get the value of a flag"""
        if flag_name in self.flags:
            return self.flags[flag_name]
        raise ValueError(f"Unknown flag: {flag_name}")

    def set_flag(self, flag_name, value):
        """Set the value of a flag"""
        if flag_name in self.flags:
            self.flags[flag_name] = value
        else:
            raise ValueError(f"Unknown flag: {flag_name}")

    def add_constraint(self, constraint):
        """Add a constraint to the environment"""
        if constraint is not None:
            self.constraints.append(constraint)

    def is_satisfiable(self, solver):
        """Check if all constraints are satisfiable using the given solver"""
        return solver.check_sat(self.constraints)

    def mark_complex_arithmetic(self, reg_name):
        """Mark a register as containing the result of a complex arithmetic operation"""
        self.complex_ops.add(reg_name)

    def is_complex_arithmetic(self, value):
        """Check if a value is related to complex arithmetic operations"""
        if isinstance(value, str) and value in self.complex_ops:
            return True
        return False

    def clone(self):
        """Create a deep copy of the current environment"""
        new_env = SymbolicEnvironment()
        new_env.registers = {k: v for k, v in self.registers.items()}
        new_env.flags = {k: v for k, v in self.flags.items()}
        new_env.memory = {k: v for k, v in self.memory.items()}
        new_env.constraints = [c for c in self.constraints]
        new_env.sym_counter = self.sym_counter
        new_env.complex_ops = set(self.complex_ops)
        return new_env

    def get_state_str(self):
        """Get a string representation of the current state"""
        result = "Registers:\n"
        for reg in sorted(self.registers.keys()):
            result += f"  {reg}: {self.registers[reg]}\n"

        result += "\nFlags:\n"
        for flag in sorted(self.flags.keys()):
            result += f"  {flag}: {self.flags[flag]}\n"

        if self.memory:
            result += "\nMemory:\n"
            # Can't sort symbolic keys directly, so just iterate
            for addr in self.memory.keys():
                # Use string representation to avoid sorting issues
                result += f"  {addr}: {self.memory[addr]}\n"

        return result

        return result

    def get_concrete_bits(self, bv):
        """
        Return a dictionary mapping bit positions to concrete values (0 or 1)
        for bits that are known to be concrete
        """
        result = {}

        # Simple case: the entire value is concrete
        if z3.is_bv_value(bv):
            val = bv.as_long()
            for i in range(bv.size()):
                result[i] = (val >> i) & 1
            return result

        # For complex expressions, return empty dictionary (no concrete bits)
        return result