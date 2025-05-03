from z3 import *


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

    def _init_registers(self):
        # Create symbolic variables for all 64-bit registers
        registers = {}
        for reg, size in self.REG_SIZES.items():
            if size == 64 and reg != 'rip':  # Only create 64-bit registers initially
                registers[reg] = BitVec(f"{reg}_0", 64)

        # Set RIP to a concrete value
        registers['rip'] = BitVecVal(0, 64)

        return registers

    def _init_flags(self):
        # Initialize flags with symbolic values
        flags = {
            'ZF': Bool('ZF_0'),
            'SF': Bool('SF_0'),
            'CF': Bool('CF_0'),
            'OF': Bool('OF_0')
        }
        return flags

    def create_fresh_symbol(self, name, size):
        """Create a fresh symbolic variable with a unique name"""
        self.sym_counter += 1
        return BitVec(f"{name}_{self.sym_counter}", size)

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
                return parent_value.extract(31, 0)
            elif reg_name.endswith('w'):  # 16-bit
                return parent_value.extract(15, 0)
            elif reg_name.endswith('l'):  # Lower 8-bit
                return parent_value.extract(7, 0)
            elif reg_name.endswith('h'):  # Higher 8-bit
                return parent_value.extract(15, 8)

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
                self.registers[parent] = parent_value & BitVecVal(0xFFFFFFFF00000000, 64) | value.zero_extend(32)
            elif reg_name.endswith('w'):  # 16-bit
                # Clear bits 15-0, set with new value
                self.registers[parent] = parent_value & BitVecVal(0xFFFFFFFFFFFF0000, 64) | value.zero_extend(48)
            elif reg_name.endswith('l'):  # Lower 8-bit
                # Clear bits 7-0, set with new value
                self.registers[parent] = parent_value & BitVecVal(0xFFFFFFFFFFFFFF00, 64) | value.zero_extend(56)
            elif reg_name.endswith('h'):  # Higher 8-bit
                # Clear bits 15-8, set with new value
                high_byte = value.zero_extend(56) << 8
                self.registers[parent] = parent_value & BitVecVal(0xFFFFFFFFFFFF00FF, 64) | high_byte
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

    def clone(self):
        """Create a deep copy of the current environment"""
        new_env = SymbolicEnvironment()
        new_env.registers = {k: v for k, v in self.registers.items()}
        new_env.flags = {k: v for k, v in self.flags.items()}
        new_env.memory = {k: v for k, v in self.memory.items()}
        new_env.constraints = [c for c in self.constraints]
        new_env.sym_counter = self.sym_counter
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
            for addr in sorted(self.memory.keys()):
                result += f"  {addr:x}: {self.memory[addr]}\n"

        return result