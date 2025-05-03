import re
from datetime import datetime
import json

# Symbolic value for registers, flags, memory, etc.
class SymbolicValue:
    def __init__(self, value=None, symbolic=True, size=1, name=None):
        self.value = value
        self.symbolic = symbolic
        self.size = size
        self.name = name
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
            'RAX': SymbolicValue(value=0, symbolic=False, name="RAX", size=8),
            'RBX': SymbolicValue(value=0, symbolic=False, name="RBX", size=8),
            'RCX': SymbolicValue(value=0, symbolic=False, name="RCX", size=8),
            'RDX': SymbolicValue(value=0, symbolic=False, name="RDX", size=8),
            'RSI': SymbolicValue(value=0, symbolic=False, name="RSI", size=8),
            'RDI': SymbolicValue(value=0, symbolic=False, name="RDI", size=8),
            'RBP': SymbolicValue(value=0, symbolic=False, name="RBP", size=8),
            'RSP': SymbolicValue(value=0, symbolic=False, name="RSP", size=8),
            'R8': SymbolicValue(value=0, symbolic=False, name="R8", size=8),
            'R9': SymbolicValue(value=0, symbolic=False, name="R9", size=8),
            'R10': SymbolicValue(value=0, symbolic=False, name="R10", size=8),
            'R11': SymbolicValue(value=0, symbolic=False, name="R11", size=8),
            'R12': SymbolicValue(value=0, symbolic=False, name="R12", size=8),
            'R13': SymbolicValue(value=0, symbolic=False, name="R13", size=8),
            'R14': SymbolicValue(value=0, symbolic=False, name="R14", size=8),
            'R15': SymbolicValue(value=0, symbolic=False, name="R15", size=8),
        }
        self.flags_array = [-1] * 32
        self.flags = {
            'CF': SymbolicValue(name="CF", size=1),
            'PF': SymbolicValue(name="PF", size=1),
            'AF': SymbolicValue(name="AF", size=1),
            'ZF': SymbolicValue(name="ZF", size=1),
            'SF': SymbolicValue(name="SF", size=1),
            'OF': SymbolicValue(name="OF", size=1),
        }
        self.memory = {}
        self.constraints = []
        self._sync_registers_to_array()
        self._sync_flags_to_array()
        self.stack = []
        self.snapshots = []
        self.current_step = 0
        self.execution_path = []
        # Initialize RSP to a reasonable value
        self.set_register('RSP', 0xFFFF0000)

    def _sync_registers_to_array(self):
        for reg_name, sym_val in self.registers.items():
            if not sym_val.symbolic and sym_val.value is not None:
                start = self.REG_START[reg_name]
                length = self.REG_LENGTH[reg_name]
                for i in range(length):
                    byte_val = (sym_val.value >> (i * 8)) & 0xFF
                    self.R[start + i] = byte_val

    def _sync_array_to_registers(self):
        for reg_name, start in self.REG_START.items():
            length = self.REG_LENGTH[reg_name]
            value = 0
            for i in range(length):
                byte_val = self.R[start + i]
                if byte_val == -1:
                    value = None
                    break
                value |= (byte_val << (i * 8))
            if value is not None:
                self.registers[reg_name] = SymbolicValue(value=value, symbolic=False, name=reg_name, size=length)
            else:
                self.registers[reg_name] = SymbolicValue(symbolic=True, name=reg_name, size=length)

    def _sync_flags_to_array(self):
        pass  # Not implemented for brevity

    def set_register(self, reg_name, value):
        if isinstance(value, SymbolicValue):
            self.registers[reg_name] = value
        else:
            self.registers[reg_name] = SymbolicValue(value=value, symbolic=False, name=reg_name, size=self.REG_LENGTH.get(reg_name, 8))

    def get_register(self, reg_name):
        return self.registers.get(reg_name, SymbolicValue(symbolic=True, name=reg_name))

    def set_flag(self, flag_name, value):
        if isinstance(value, SymbolicValue):
            self.flags[flag_name] = value
        else:
            self.flags[flag_name] = SymbolicValue(value=value, symbolic=False, name=flag_name, size=1)

    def get_flag(self, flag_name):
        return self.flags.get(flag_name, SymbolicValue(symbolic=True, name=flag_name, size=1))

    def set_memory(self, addr, value):
        if isinstance(value, SymbolicValue):
            self.memory[addr] = value
        else:
            self.memory[addr] = SymbolicValue(value=value, symbolic=False, size=4)

    def get_memory(self, addr):
        return self.memory.get(addr, SymbolicValue(symbolic=True, name=f"mem_{hex(addr)}", size=4))

    def push(self, value):
        """
        Push a value onto the stack

        Args:
            value: Value to push (concrete or symbolic)
        """
        # Add to stack representation
        if isinstance(value, SymbolicValue):
            self.stack.insert(0, {
                'value': value.value,
                'symbolic': value.symbolic,
                'size': value.size,
                'name': value.name
            })
        else:
            self.stack.insert(0, value)

        # Update RSP
        rsp = self.get_register('RSP')
        if not rsp.symbolic and rsp.value is not None:
            # Decrement RSP by 8 (size of a 64-bit value)
            self.set_register('RSP', rsp.value - 8)
        else:
            # RSP is symbolic, create a new symbolic value
            self.set_register('RSP', SymbolicValue(name="RSP-8", size=8, symbolic=True))

        # Store value in memory at [RSP]
        if not rsp.symbolic and rsp.value is not None:
            if isinstance(value, SymbolicValue):
                self.set_memory(rsp.value - 8, value)
            else:
                self.set_memory(rsp.value - 8, value)

    def pop(self):
        """
        Pop a value from the stack

        Returns:
            Popped value (concrete or symbolic)
        """
        # Get value from stack
        if self.stack:
            value = self.stack.pop(0)
        else:
            # Stack underflow, return symbolic value
            return SymbolicValue(name="stack_underflow", size=8, symbolic=True)

        # Update RSP
        rsp = self.get_register('RSP')
        if not rsp.symbolic and rsp.value is not None:
            # Increment RSP by 8 (size of a 64-bit value)
            new_rsp = rsp.value + 8
            self.set_register('RSP', new_rsp)

            # Get the value from memory at [RSP]
            mem_val = self.get_memory(rsp.value)

            # Return the value
            if isinstance(value, dict):
                return SymbolicValue(
                    value=value.get('value'),
                    symbolic=value.get('symbolic', True),
                    size=value.get('size', 8),
                    name=value.get('name')
                )
            else:
                return value
        else:
            # RSP is symbolic, create a new symbolic value
            self.set_register('RSP', SymbolicValue(name="RSP+8", size=8, symbolic=True))

            # Return a symbolic value since RSP is symbolic
            return SymbolicValue(name="pop_result", size=8, symbolic=True)

    def load_effective_address(self, dst_reg, src_addr):
        """
        Implement lea instruction (Load Effective Address)

        Args:
            dst_reg: Destination register
            src_addr: Source address expression (RIP + offset, etc.)
        """
        # Parse the address expression
        if isinstance(src_addr, str):
            if "rip" in src_addr.lower() and "+" in src_addr:
                # RIP-relative addressing
                try:
                    # Extract offset
                    parts = src_addr.split("+")
                    offset_part = parts[1].strip()
                    if offset_part.startswith("0x"):
                        offset = int(offset_part, 16)
                    else:
                        offset = int(offset_part)

                    # Get RIP value (use a placeholder value for now)
                    rip_value = 0x400000  # Placeholder

                    # Calculate effective address
                    effective_addr = rip_value + offset

                    # Store in destination register
                    self.set_register(dst_reg, effective_addr)
                except:
                    # If parsing fails, set to symbolic
                    self.set_register(dst_reg, SymbolicValue(name=f"lea_{src_addr}", size=8, symbolic=True))
            else:
                # Other addressing modes (base + index*scale + disp)
                # For simplicity, just set to symbolic
                self.set_register(dst_reg, SymbolicValue(name=f"lea_{src_addr}", size=8, symbolic=True))
        else:
            # Direct address
            self.set_register(dst_reg, src_addr)

    def sym_xor_reg_reg(self, dst_reg, src_reg):
        """
        Symbolically XOR two registers

        Args:
            dst_reg: Destination register name
            src_reg: Source register name
        """
        dst_val = self.get_register(dst_reg)
        src_val = self.get_register(src_reg)

        # Special case: XOR register with itself zeroes the register
        if dst_reg == src_reg:
            self.set_register(dst_reg, 0)

            # Set flags
            self.set_flag('ZF', 1)  # Result is zero
            self.set_flag('CF', 0)  # No carry
            self.set_flag('OF', 0)  # No overflow
            self.set_flag('SF', 0)  # Sign flag clear
            return

        # Normal XOR operation
        if not dst_val.symbolic and not src_val.symbolic:
            # Both values are concrete
            result = dst_val.value ^ src_val.value
            self.set_register(dst_reg, result)

            # Set flags
            self.set_flag('ZF', 1 if result == 0 else 0)
            self.set_flag('CF', 0)  # XOR clears CF
            self.set_flag('OF', 0)  # XOR clears OF
            self.set_flag('SF', 1 if result < 0 else 0)
        else:
            # At least one value is symbolic, result is symbolic
            self.set_register(dst_reg, SymbolicValue(name=f"{dst_reg}^{src_reg}", size=dst_val.size))

            # Flags are also symbolic
            self.set_flag('ZF', SymbolicValue(name=f"ZF({dst_reg}^{src_reg})", size=1))
            self.set_flag('CF', 0)  # XOR always clears CF
            self.set_flag('OF', 0)  # XOR always clears OF
            self.set_flag('SF', SymbolicValue(name=f"SF({dst_reg}^{src_reg})", size=1))

    def sym_and_reg_reg(self, dst_reg, src_reg):
        """
        Symbolically AND two registers

        Args:
            dst_reg: Destination register name
            src_reg: Source register name
        """
        dst_val = self.get_register(dst_reg)
        src_val = self.get_register(src_reg)

        if not dst_val.symbolic and not src_val.symbolic:
            # Both values are concrete
            result = dst_val.value & src_val.value
            self.set_register(dst_reg, result)

            # Set flags
            self.set_flag('ZF', 1 if result == 0 else 0)
            self.set_flag('CF', 0)  # AND clears CF
            self.set_flag('OF', 0)  # AND clears OF
            self.set_flag('SF', 1 if result < 0 else 0)
        else:
            # At least one value is symbolic, result is symbolic
            self.set_register(dst_reg, SymbolicValue(name=f"{dst_reg}&{src_reg}", size=dst_val.size))

            # Flags are also symbolic
            self.set_flag('ZF', SymbolicValue(name=f"ZF({dst_reg}&{src_reg})", size=1))
            self.set_flag('CF', 0)  # AND always clears CF
            self.set_flag('OF', 0)  # AND always clears OF
            self.set_flag('SF', SymbolicValue(name=f"SF({dst_reg}&{src_reg})", size=1))

    def sym_test_reg_reg(self, dst_reg, src_reg):
        """
        Symbolically test registers (AND without storing result)

        Args:
            dst_reg: First register to test
            src_reg: Second register to test
        """
        dst_val = self.get_register(dst_reg)
        src_val = self.get_register(src_reg)

        if not dst_val.symbolic and not src_val.symbolic:
            # Both values are concrete
            result = dst_val.value & src_val.value

            # Set flags based on result
            self.set_flag('ZF', 1 if result == 0 else 0)
            self.set_flag('CF', 0)  # Test clears CF
            self.set_flag('OF', 0)  # Test clears OF
            self.set_flag('SF', 1 if result < 0 else 0)
        else:
            # At least one value is symbolic, flags are symbolic
            self.set_flag('ZF', SymbolicValue(name=f"ZF(test {dst_reg},{src_reg})", size=1))
            self.set_flag('CF', 0)  # Test always clears CF
            self.set_flag('OF', 0)  # Test always clears OF
            self.set_flag('SF', SymbolicValue(name=f"SF(test {dst_reg},{src_reg})", size=1))

    def handle_conditional_jump(self, mnemonic, target):
        """
        Handle conditional jump instructions

        Args:
            mnemonic: Jump mnemonic (je, jne, jg, etc.)
            target: Jump target address

        Returns:
            Tuple of (taken, target) where taken is True/False/None
            None means the outcome is symbolic
        """
        # Check specific jump condition
        if mnemonic in ['je', 'jz']:
            # Jump if equal (ZF=1)
            zf = self.get_flag('ZF')
            if not zf.symbolic:
                return (zf.value == 1, target)
            else:
                return (None, target)

        elif mnemonic in ['jne', 'jnz']:
            # Jump if not equal (ZF=0)
            zf = self.get_flag('ZF')
            if not zf.symbolic:
                return (zf.value == 0, target)
            else:
                return (None, target)

        elif mnemonic == 'jg' or mnemonic == 'jnle':
            # Jump if greater (ZF=0 and SF=OF)
            zf = self.get_flag('ZF')
            sf = self.get_flag('SF')
            of = self.get_flag('OF')

            if not zf.symbolic and not sf.symbolic and not of.symbolic:
                return (zf.value == 0 and sf.value == of.value, target)
            else:
                return (None, target)

        elif mnemonic == 'jge' or mnemonic == 'jnl':
            # Jump if greater or equal (SF=OF)
            sf = self.get_flag('SF')
            of = self.get_flag('OF')

            if not sf.symbolic and not of.symbolic:
                return (sf.value == of.value, target)
            else:
                return (None, target)

        elif mnemonic == 'jl' or mnemonic == 'jnge':
            # Jump if less (SF≠OF)
            sf = self.get_flag('SF')
            of = self.get_flag('OF')

            if not sf.symbolic and not of.symbolic:
                return (sf.value != of.value, target)
            else:
                return (None, target)

        elif mnemonic == 'jle' or mnemonic == 'jng':
            # Jump if less or equal (ZF=1 or SF≠OF)
            zf = self.get_flag('ZF')
            sf = self.get_flag('SF')
            of = self.get_flag('OF')

            if not zf.symbolic and not sf.symbolic and not of.symbolic:
                return (zf.value == 1 or sf.value != of.value, target)
            else:
                return (None, target)

        elif mnemonic == 'jmp':
            # Unconditional jump
            return (True, target)

        # Default: can't determine
        return (None, target)

    def setup_initial_state(self, initial_values=None):
        """
        Set up the initial state of the environment

        Args:
            initial_values: Dictionary with initial values for registers and memory
        """
        if not initial_values:
            initial_values = {}

        # Set register values
        for reg_name, value in initial_values.get('registers', {}).items():
            if isinstance(value, dict) and value.get('symbolic', False):
                # Symbolic value
                self.set_register(reg_name, SymbolicValue(
                    name=value.get('name', f"sym_{reg_name}"),
                    size=value.get('size', 8),
                    symbolic=True
                ))
            else:
                # Concrete value
                self.set_register(reg_name, value)

        # Set memory values
        for addr_str, value in initial_values.get('memory', {}).items():
            addr = int(addr_str, 0) if isinstance(addr_str, str) else addr_str
            if isinstance(value, dict) and value.get('symbolic', False):
                # Symbolic value
                self.set_memory(addr, SymbolicValue(
                    name=value.get('name', f"mem_{hex(addr)}"),
                    size=value.get('size', 4),
                    symbolic=True
                ))
            else:
                # Concrete value
                self.set_memory(addr, value)

        # Set flags
        for flag_name, value in initial_values.get('flags', {}).items():
            if isinstance(value, dict) and value.get('symbolic', False):
                # Symbolic value
                self.set_flag(flag_name, SymbolicValue(
                    name=value.get('name', f"flag_{flag_name}"),
                    size=1,
                    symbolic=True
                ))
            else:
                # Concrete value
                self.set_flag(flag_name, value)

        # Take initial snapshot
        self.take_snapshot("Initial state")

    def take_snapshot(self, instruction=None):
        """
        Take a snapshot of the current environment state

        Args:
            instruction: The instruction that was just executed (optional)
        """
        snapshot = self._snapshot_state(instruction, self.current_step)
        self.snapshots.append(snapshot)
        return snapshot

    def _snapshot_state(self, instruction, step):
        # Equivalent to SymbolicStateSnapshot.to_dict
        rsp = self.get_register('RSP')
        rsp_value = rsp.value if not rsp.symbolic and rsp.value is not None else None
        return {
            'step': step,
            'instruction': instruction,
            'registers': {k: v for k, v in self.registers.items()},
            'flags': {k: v for k, v in self.flags.items()},
            'memory': {str(k): v for k, v in self.memory.items()},
            'constraints': list(self.constraints),
            'stack': list(self.stack),
            'rsp_value': rsp_value
        }

    def execute_instruction(self, instruction):
        """
        Execute a single instruction symbolically and take a snapshot

        Args:
            instruction: Dictionary with instruction details

        Returns:
            Snapshot of the environment after execution
        """
        instr_name = instruction.get('name', '').lower()

        # Default operands if not specified
        operands = instruction.get('operands', ['RAX'])
        dst_reg = operands[0] if len(operands) > 0 else 'RAX'
        src_reg = operands[1] if len(operands) > 1 else 'RBX'

        # Format instruction for display
        instr_str = f"{instr_name} {', '.join(operands)}" if operands else instr_name

        # Record the instruction in execution path
        self.execution_path.append({
            'step': self.current_step,
            'instruction': instr_str,
            'mnemonic': instr_name,
            'operands': operands
        })

        # Execute the instruction
        try:
            if instr_name == 'mov':
                self.sym_copy_reg_reg(dst_reg, src_reg)
            elif instr_name == 'add':
                self.sym_add_reg_reg(dst_reg, src_reg)
            elif instr_name == 'sub':
                self.sym_sub_reg_reg(dst_reg, src_reg)
            elif instr_name == 'mul' or instr_name == 'imul':
                self.sym_mul_reg_reg(dst_reg, src_reg)
            elif instr_name == 'div' or instr_name == 'idiv':
                self.sym_div_reg_reg(dst_reg, src_reg)
            elif instr_name == 'xor':
                self.sym_xor_reg_reg(dst_reg, src_reg)
            elif instr_name == 'and':
                self.sym_and_reg_reg(dst_reg, src_reg)
            elif instr_name == 'or':
                # Symbolic OR implementation would go here
                pass  # Placeholder
            elif instr_name == 'push':
                # Get value from register
                value = self.get_register(dst_reg)
                # Push onto stack
                self.push(value)
            elif instr_name == 'pop':
                # Pop value from stack
                value = self.pop()
                # Store in destination register
                self.set_register(dst_reg, value)
            elif instr_name == 'lea':
                # Load effective address
                self.load_effective_address(dst_reg, instruction.get('address', '0'))
            elif instr_name == 'test':
                self.sym_test_reg_reg(dst_reg, src_reg)
            elif instr_name in ['je', 'jne', 'jz', 'jnz', 'jg', 'jl', 'jge', 'jle', 'jmp']:
                # Handle conditional jumps
                taken, target = self.handle_conditional_jump(instr_name, instruction.get('address', '0'))
                if taken is not None:
                    # Add jump information to execution path
                    self.execution_path[-1]['jump_taken'] = taken
                    self.execution_path[-1]['jump_target'] = target
            elif instr_name == 'nop':
                # No operation
                pass
            elif instr_name == 'ret':
                # Return - pop value and use as target
                target = self.pop()
                # Add return information to execution path
                self.execution_path[-1]['return_target'] = target
            elif instr_name == 'hlt':
                # Halt execution
                self.execution_path[-1]['halted'] = True
            elif instr_name == 'shr' or instr_name == 'sar':
                # Shift right logical or arithmetic (simplified)
                # For simplicity, just set to symbolic
                self.set_register(dst_reg, SymbolicValue(name=f"{dst_reg}_shifted", size=8, symbolic=True))
            else:
                # Unimplemented instruction
                print(f"Warning: Unimplemented instruction '{instr_name}'")
        except Exception as e:
            print(f"Error executing instruction '{instr_str}': {e}")

        # Increment step counter
        self.current_step += 1

        # Take snapshot
        return self.take_snapshot(instr_str)

    def execute_sequence(self, instructions):
        """
        Execute a sequence of instructions symbolically and record state at each step

        Args:
            instructions: List of instruction dictionaries

        Returns:
            List of snapshots after each instruction
        """
        step_snapshots = []

        for i, instruction in enumerate(instructions):
            print(
                f"Executing step {self.current_step}: {instruction.get('name', '')} {instruction.get('operands', [])}")
            snapshot = self.execute_instruction(instruction)
            step_snapshots.append(snapshot)
            print(snapshot)
            print("-" * 50)

        return step_snapshots

    def make_json_serializable(self, obj):
        """
        Recursively convert a complex object to a JSON serializable format.
        Handles SymbolicValue objects, dictionaries, lists, and primitive types.

        Args:
            obj: Any Python object to convert

        Returns:
            JSON serializable version of the object
        """
        if obj is None:
            return None

        # Handle basic types directly
        if isinstance(obj, (str, bool, int, float)):
            return obj

        # Handle SymbolicValue objects
        if hasattr(obj, 'symbolic') and hasattr(obj, 'value') and hasattr(obj, 'name'):
            return {
                'value': self.make_json_serializable(obj.value),
                'symbolic': obj.symbolic,
                'size': getattr(obj, 'size', 8),
                'name': obj.name
            }

        # Handle dictionaries
        if isinstance(obj, dict):
            return {str(k): self.make_json_serializable(v) for k, v in obj.items()}

        # Handle lists and tuples
        if isinstance(obj, (list, tuple)):
            return [self.make_json_serializable(item) for item in obj]

        # Handle sets
        if isinstance(obj, set):
            return [self.make_json_serializable(item) for item in obj]

        # Default: convert to string
        try:
            return str(obj)
        except:
            return "UNSERIALIZABLE_OBJECT"

    def save_trace(self, filename=None):
        """
        Save the execution trace to a file

        Args:
            filename: Output filename (default: trace_<timestamp>.json)

        Returns:
            Path to the saved file
        """
        import json
        from datetime import datetime

        if filename is None:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"trace_{timestamp}.json"

        # Convert snapshots to dictionaries and make them JSON serializable
        serializable_snapshots = []
        for snapshot in self.snapshots:
            # Convert each snapshot to a dictionary
            snapshot_dict = snapshot
            # Make the dictionary JSON serializable
            serializable_snapshots.append(self.make_json_serializable(snapshot_dict))

        # Build the trace data structure with serialized snapshots
        trace_data = {
            'total_steps': self.current_step,
            'execution_path': self.make_json_serializable(self.execution_path),
            'snapshots': serializable_snapshots
        }

        # Save to JSON file
        try:
            with open(filename, 'w') as f:
                json.dump(trace_data, f, indent=2)
            print(f"Saved execution trace to {filename}")
        except Exception as e:
            print(f"Error saving trace to {filename}: {e}")
            # Try a simpler approach
            try:
                with open(f"simple_{filename}", 'w') as f:
                    # Just save basic information
                    simple_data = {
                        'total_steps': self.current_step,
                        'instructions': [path.get('instruction', 'unknown') for path in self.execution_path]
                    }
                    json.dump(simple_data, f, indent=2)
                print(f"Saved simplified trace to simple_{filename}")
            except:
                print("Failed to save even simplified trace")

        return filename

    def reset_trace(self):
        """
        Reset the execution trace
        """
        self.snapshots = []
        self.current_step = 0
        self.execution_path = []
