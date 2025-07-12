# symbolic_modeling/core.py

class SymbolicValue:
    def __init__(self, value=None, symbolic=True, size=1, name=None):
        self.value = value  # Concrete value, if available
        self.symbolic = symbolic  # True if value is symbolic
        self.size = size  # Size in bytes
        self.name = name  # Symbolic variable name

    def __str__(self):
        if not self.symbolic and self.value is not None:
            return str(self.value)
        return f"${self.name}" if self.name else "$sym"

class SymbolicEnvironment:
    def __init__(self):
        self.R = [-1] * 64  # -1 represents symbolic values
        self.REG_LENGTH = {
            'AL': 1, 'BL': 1, 'CL': 1, 'DL': 1,
            'AX': 2, 'BX': 2, 'CX': 2, 'DX': 2,
            'EAX': 4, 'EBX': 4, 'ECX': 4, 'EDX': 4,
            'RAX': 8, 'RBX': 8, 'RCX': 8, 'RDX': 8,
            'RSI': 8, 'RDI': 8, 'RBP': 8, 'RSP': 8,
            'R8': 8, 'R9': 8, 'R10': 8, 'R11': 8,
            'R12': 8, 'R13': 8, 'R14': 8, 'R15': 8
        }
        self.REG_START = {
            'AL': 0, 'BL': 16, 'CL': 32, 'DL': 48,
            'AX': 0, 'BX': 16, 'CX': 32, 'DX': 48,
            'EAX': 0, 'EBX': 16, 'ECX': 32, 'EDX': 48,
            'RAX': 0, 'RBX': 16, 'RCX': 32, 'RDX': 48,
            'RSI': 8, 'RDI': 24, 'RBP': 40, 'RSP': 56,
            'R8': 0, 'R9': 8, 'R10': 16, 'R11': 24,
            'R12': 32, 'R13': 40, 'R14': 48, 'R15': 56
        }
        self.registers = {
            'RAX': SymbolicValue(name="RAX", size=8),
            'RBX': SymbolicValue(name="RBX", size=8),
            'RCX': SymbolicValue(name="RCX", size=8),
            'RDX': SymbolicValue(name="RDX", size=8),
            'RSI': SymbolicValue(name="RSI", size=8),
            'RDI': SymbolicValue(name="RDI", size=8),
            'RBP': SymbolicValue(name="RBP", size=8),
            'RSP': SymbolicValue(name="RSP", size=8),
            'R8': SymbolicValue(name="R8", size=8),
            'R9': SymbolicValue(name="R9", size=8),
            'R10': SymbolicValue(name="R10", size=8),
            'R11': SymbolicValue(name="R11", size=8),
            'R12': SymbolicValue(name="R12", size=8),
            'R13': SymbolicValue(name="R13", size=8),
            'R14': SymbolicValue(name="R14", size=8),
            'R15': SymbolicValue(name="R15", size=8),
        }
        self.flags_array = [-1] * 32  # -1 represents symbolic values
        self.flags = {
            'CF': SymbolicValue(name="CF", size=1),  # Carry flag
            'PF': SymbolicValue(name="PF", size=1),  # Parity flag
            'AF': SymbolicValue(name="AF", size=1),  # Auxiliary carry flag
            'ZF': SymbolicValue(name="ZF", size=1),  # Zero flag
            'SF': SymbolicValue(name="SF", size=1),  # Sign flag
            'OF': SymbolicValue(name="OF", size=1),  # Overflow flag
        }
        self.memory = {}
        self.constraints = []
        self._sync_registers_to_array()
        self._sync_flags_to_array()

    def set_register(self, register, value):
        if register not in self.registers:
            raise ValueError(f"Invalid register: {register}")
        if not isinstance(value, SymbolicValue):
            raise ValueError(f"Invalid value: {value}")
        self.registers[register] = value
        self._sync_registers_to_array()

    def _sync_registers_to_array(self):
        for register, value in self.registers.items():
            start = self.REG_START[register]
            size = self.REG_LENGTH[register]
            self.R[start:start+size] = [-1] * size if value.symbolic else [value.value] * size

    def _sync_flags_to_array(self):
        for flag, value in self.flags.items():
            index = list(self.flags.keys()).index(flag)
            self.flags_array[index] = -1 if value.symbolic else value.value
