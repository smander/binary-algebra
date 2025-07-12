# snapshot.py
"""
State snapshotting and serialization for symbolic execution environments.
"""
from symbolic_environment import EnhancedSymbolicEnvironment

class SymbolicStateSnapshot:
    """Captures and serializes the state of a symbolic environment.
    
    Args:
        env (EnhancedSymbolicEnvironment): The environment to snapshot.
        instruction (str, optional): The instruction at this step.
        step (int, optional): The step index.
    """
    def __init__(self, env: EnhancedSymbolicEnvironment, instruction=None, step=None):
        self.step = step
        self.instruction = instruction
        self.registers = {k: v for k, v in env.registers.items()}
        self.flags = {k: v for k, v in env.flags.items()}
        self.memory = {str(k): v for k, v in env.memory.items()}
        self.constraints = list(env.constraints)
        self.stack = list(getattr(env, 'stack', []))
        rsp = env.get_register('RSP')
        self.rsp_value = rsp.value if not rsp.symbolic and rsp.value is not None else None

    def to_dict(self):
        """Return a dictionary representation of the snapshot."""
        return {
            'step': self.step,
            'instruction': self.instruction,
            'registers': self.registers,
            'flags': self.flags,
            'memory': self.memory,
            'constraints': list(self.constraints),
            'stack': list(self.stack),
            'rsp_value': self.rsp_value
        }
    def __str__(self):
        """Pretty-print the snapshot for debugging and logs."""
        output = []
        if self.step is not None:
            output.append(f"Step {self.step}")
        if self.instruction:
            output.append(f"Instruction: {self.instruction}")
        output.append("Registers:")
        for reg_name, reg_info in self.registers.items():
            if reg_name in ['RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP']:
                val_str = f"${reg_info.name}" if getattr(reg_info, 'symbolic', True) else f"0x{getattr(reg_info, 'value', 0):x}"
                output.append(f"  {reg_name}: {val_str}")
        output.append("Flags:")
        flag_list = []
        for flag_name in ['CF', 'ZF', 'SF', 'OF']:
            flag_info = self.flags.get(flag_name, None)
            if flag_info is not None and getattr(flag_info, 'symbolic', True):
                val_str = "$"
            else:
                val_str = str(getattr(flag_info, 'value', 'None'))
            flag_list.append(f"{flag_name}={val_str}")
        output.append("  " + ", ".join(flag_list))
        if self.stack:
            output.append("Stack (top 5 values):")
            for i, value in enumerate(self.stack[:5]):
                if hasattr(value, 'symbolic') and value.symbolic:
                    val_str = f"${getattr(value, 'name', 'sym')}"
                else:
                    val_str = f"0x{getattr(value, 'value', 0):x}" if hasattr(value, 'value') else str(value)
                output.append(f"  [{i}]: {val_str}")
            if len(self.stack) > 5:
                output.append(f"  ... and {len(self.stack) - 5} more values")
        if self.rsp_value is not None:
            output.append(f"RSP points to: 0x{self.rsp_value:x}")
        if self.memory:
            output.append("Memory:")
            for addr, mem_info in self.memory.items():
                val_str = f"${mem_info.name}" if getattr(mem_info, 'symbolic', True) else f"0x{getattr(mem_info, 'value', 0):x}"
                output.append(f"  {addr}: {val_str}")
        if self.constraints:
            output.append("Constraints:")
            for constraint in self.constraints:
                output.append(f"  {constraint}")
        return "\n".join(output)
