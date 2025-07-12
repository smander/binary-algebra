import copy
import json
import re
from datetime import datetime

# Import the existing modeling classes
from modeling import SymbolicValue, SymbolicEnvironment, parse_behavior_file


class SymbolicStateSnapshot:
    """Class to capture and store the state of the symbolic environment at a point in time"""

    def __init__(self, env, instruction=None, step=None):
        """
        Create a snapshot of the current environment state

        Args:
            env: The SymbolicEnvironment to snapshot
            instruction: The instruction that was just executed (optional)
            step: The execution step number (optional)
        """
        self.step = step
        self.instruction = instruction

        # Copy register state
        self.registers = {}
        for reg_name, sym_val in env.registers.items():
            self.registers[reg_name] = {
                'value': sym_val.value,
                'symbolic': sym_val.symbolic,
                'size': sym_val.size,
                'name': sym_val.name
            }

        # Copy flag state
        self.flags = {}
        for flag_name, sym_val in env.flags.items():
            self.flags[flag_name] = {
                'value': sym_val.value,
                'symbolic': sym_val.symbolic,
                'size': sym_val.size,
                'name': sym_val.name
            }

        # Copy memory state (only defined values)
        self.memory = {}
        for addr, sym_val in env.memory.items():
            self.memory[str(addr)] = {
                'value': sym_val.value,
                'symbolic': sym_val.symbolic,
                'size': sym_val.size,
                'name': sym_val.name
            }

        # Copy constraints
        self.constraints = list(env.constraints)

        # Copy stack
        self.stack = list(getattr(env, 'stack', []))

        # Add stack pointer value
        rsp = env.get_register('RSP')
        if not rsp.symbolic and rsp.value is not None:
            self.rsp_value = rsp.value
        else:
            self.rsp_value = None

    def __str__(self):
        """String representation of the snapshot for debugging"""
        output = []
        if self.step is not None:
            output.append(f"Step {self.step}")
        if self.instruction:
            output.append(f"Instruction: {self.instruction}")

        output.append("Registers:")
        for reg_name, reg_info in self.registers.items():
            if reg_name in ['RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP']:  # Just show main registers
                if reg_info['symbolic']:
                    val_str = f"${reg_info['name'] if reg_info['name'] else 'sym'}"
                else:
                    val_str = f"0x{reg_info['value']:x}" if reg_info['value'] is not None else 'None'
                output.append(f"  {reg_name}: {val_str}")

        output.append("Flags:")
        flag_list = []
        for flag_name in ['CF', 'ZF', 'SF', 'OF']:  # Just show main flags
            flag_info = self.flags.get(flag_name, {})
            if flag_info.get('symbolic', True):
                val_str = "$"
            else:
                val_str = str(flag_info.get('value', 'None'))
            flag_list.append(f"{flag_name}={val_str}")
        output.append("  " + ", ".join(flag_list))

        # Show stack information if available
        if hasattr(self, 'stack') and self.stack:
            output.append("Stack (top 5 values):")
            for i, value in enumerate(self.stack[:5]):
                if isinstance(value, dict):
                    if value.get('symbolic', True):
                        val_str = f"${value.get('name', 'sym')}"
                    else:
                        val_str = f"0x{value.get('value'):x}" if value.get('value') is not None else 'None'
                else:
                    val_str = f"0x{value:x}" if value is not None else 'None'
                output.append(f"  [{i}]: {val_str}")
            if len(self.stack) > 5:
                output.append(f"  ... and {len(self.stack) - 5} more values")

        # Show RSP value if available
        if hasattr(self, 'rsp_value') and self.rsp_value is not None:
            output.append(f"RSP points to: 0x{self.rsp_value:x}")

        # Show all memory locations
        if self.memory:
            output.append("Memory:")
            for addr, mem_info in self.memory.items():
                if mem_info['symbolic']:
                    val_str = f"${mem_info['name']}"
                else:
                    val_str = f"0x{mem_info['value']:x}"
                output.append(f"  {addr}: {val_str}")

        if self.constraints:
            output.append("Constraints:")
            for constraint in self.constraints:
                output.append(f"  {constraint}")

        return "\n".join(output)

    def to_dict(self):
        """Convert snapshot to dictionary for JSON serialization"""
        result = {
            'step': self.step,
            'instruction': self.instruction,
            'registers': self.registers,
            'flags': self.flags,
            'memory': self.memory,
            'constraints': list(self.constraints)
        }

        # Add stack if available
        if hasattr(self, 'stack'):
            result['stack'] = self.stack

        # Add RSP value if available
        if hasattr(self, 'rsp_value'):
            result['rsp_value'] = self.rsp_value

        return result


class EnhancedSymbolicEnvironment(SymbolicEnvironment):
    """
    Enhanced Symbolic Environment with stack support and additional instructions
    """

    def __init__(self):
        """Initialize the environment with stack support"""
        super().__init__()
        self.stack = []
        # Initialize RSP to a reasonable value
        self.set_register('RSP', 0xFFFF0000)

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


class SymbolicExecutionTracer:
    """Class to execute and trace symbolic execution of an instruction sequence"""

    def __init__(self):
        """Initialize the tracer"""
        self.env = EnhancedSymbolicEnvironment()
        self.snapshots = []
        self.current_step = 0
        self.execution_path = []

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
                self.env.set_register(reg_name, SymbolicValue(
                    name=value.get('name', f"sym_{reg_name}"),
                    size=value.get('size', 8),
                    symbolic=True
                ))
            else:
                # Concrete value
                self.env.set_register(reg_name, value)

        # Set memory values
        for addr_str, value in initial_values.get('memory', {}).items():
            addr = int(addr_str, 0) if isinstance(addr_str, str) else addr_str
            if isinstance(value, dict) and value.get('symbolic', False):
                # Symbolic value
                self.env.set_memory(addr, SymbolicValue(
                    name=value.get('name', f"mem_{hex(addr)}"),
                    size=value.get('size', 4),
                    symbolic=True
                ))
            else:
                # Concrete value
                self.env.set_memory(addr, value)

        # Set flags
        for flag_name, value in initial_values.get('flags', {}).items():
            if isinstance(value, dict) and value.get('symbolic', False):
                # Symbolic value
                self.env.set_flag(flag_name, SymbolicValue(
                    name=value.get('name', f"flag_{flag_name}"),
                    size=1,
                    symbolic=True
                ))
            else:
                # Concrete value
                self.env.set_flag(flag_name, value)

        # Take initial snapshot
        self.take_snapshot("Initial state")

    def take_snapshot(self, instruction=None):
        """
        Take a snapshot of the current environment state

        Args:
            instruction: The instruction that was just executed (optional)
        """
        snapshot = SymbolicStateSnapshot(self.env, instruction, self.current_step)
        self.snapshots.append(snapshot)
        return snapshot

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
                self.env.sym_copy_reg_reg(dst_reg, src_reg)
            elif instr_name == 'add':
                self.env.sym_add_reg_reg(dst_reg, src_reg)
            elif instr_name == 'sub':
                self.env.sym_sub_reg_reg(dst_reg, src_reg)
            elif instr_name == 'mul' or instr_name == 'imul':
                self.env.sym_mul_reg_reg(dst_reg, src_reg)
            elif instr_name == 'div' or instr_name == 'idiv':
                self.env.sym_div_reg_reg(dst_reg, src_reg)
            elif instr_name == 'xor':
                self.env.sym_xor_reg_reg(dst_reg, src_reg)
            elif instr_name == 'and':
                self.env.sym_and_reg_reg(dst_reg, src_reg)
            elif instr_name == 'or':
                # Symbolic OR implementation would go here
                pass  # Placeholder
            elif instr_name == 'push':
                # Get value from register
                value = self.env.get_register(dst_reg)
                # Push onto stack
                self.env.push(value)
            elif instr_name == 'pop':
                # Pop value from stack
                value = self.env.pop()
                # Store in destination register
                self.env.set_register(dst_reg, value)
            elif instr_name == 'lea':
                # Load effective address
                self.env.load_effective_address(dst_reg, instruction.get('address', '0'))
            elif instr_name == 'test':
                self.env.sym_test_reg_reg(dst_reg, src_reg)
            elif instr_name in ['je', 'jne', 'jz', 'jnz', 'jg', 'jl', 'jge', 'jle', 'jmp']:
                # Handle conditional jumps
                taken, target = self.env.handle_conditional_jump(instr_name, instruction.get('address', '0'))
                if taken is not None:
                    # Add jump information to execution path
                    self.execution_path[-1]['jump_taken'] = taken
                    self.execution_path[-1]['jump_target'] = target
            elif instr_name == 'nop':
                # No operation
                pass
            elif instr_name == 'ret':
                # Return - pop value and use as target
                target = self.env.pop()
                # Add return information to execution path
                self.execution_path[-1]['return_target'] = target
            elif instr_name == 'hlt':
                # Halt execution
                self.execution_path[-1]['halted'] = True
            elif instr_name == 'shr' or instr_name == 'sar':
                # Shift right logical or arithmetic (simplified)
                # For simplicity, just set to symbolic
                self.env.set_register(dst_reg, SymbolicValue(name=f"{dst_reg}_shifted", size=8, symbolic=True))
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

    # Update the save_trace method in SymbolicExecutionTracer
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
            snapshot_dict = snapshot.to_dict()
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

    # Update the to_dict method in SymbolicStateSnapshot
    def to_dict(self):
        """Convert snapshot to dictionary for JSON serialization"""
        result = {
            'step': self.step,
            'instruction': self.instruction,
            'registers': {},
            'flags': {},
            'memory': {},
            'constraints': list(self.constraints)
        }

        # Manually convert registers
        for reg_name, reg_info in self.registers.items():
            # Ensure we convert any None values or other problematic types
            result['registers'][reg_name] = {
                'value': reg_info.get('value'),
                'symbolic': reg_info.get('symbolic', True),
                'size': reg_info.get('size', 8),
                'name': reg_info.get('name', '')
            }

        # Manually convert flags
        for flag_name, flag_info in self.flags.items():
            result['flags'][flag_name] = {
                'value': flag_info.get('value'),
                'symbolic': flag_info.get('symbolic', True),
                'size': flag_info.get('size', 1),
                'name': flag_info.get('name', '')
            }

        # Manually convert memory
        for addr, mem_info in self.memory.items():
            result['memory'][str(addr)] = {
                'value': mem_info.get('value'),
                'symbolic': mem_info.get('symbolic', True),
                'size': mem_info.get('size', 4),
                'name': mem_info.get('name', '')
            }

        # Add stack if available
        if hasattr(self, 'stack'):
            # Convert each stack item
            result['stack'] = []
            for item in self.stack:
                if isinstance(item, dict):
                    result['stack'].append({
                        'value': item.get('value'),
                        'symbolic': item.get('symbolic', True),
                        'size': item.get('size', 8),
                        'name': item.get('name', '')
                    })
                else:
                    result['stack'].append(item)

        # Add RSP value if available
        if hasattr(self, 'rsp_value'):
            result['rsp_value'] = self.rsp_value

        return result

    def visualize_trace(self, snapshot_indices=None):
        """
        Visualize the execution trace

        Args:
            snapshot_indices: List of indices to visualize (default: all)
        """
        if not self.snapshots:
            print("No snapshots to visualize.")
            return

        if snapshot_indices is None:
            snapshot_indices = range(len(self.snapshots))

        for idx in snapshot_indices:
            if 0 <= idx < len(self.snapshots):
                print(self.snapshots[idx])
                print("-" * 50)
            else:
                print(f"Warning: Invalid snapshot index {idx}")


class BehaviorAlgebraParser:
    """Class to parse behavior algebra expressions and extract instruction sequences"""

    def __init__(self, behavior_content):
        """
        Initialize with behavior algebra content

        Args:
            behavior_content: String containing behavior algebra expressions
        """
        self.behavior_content = behavior_content
        self.behavior_dict = {}
        self.parse()

    def parse(self):
        """Parse the behavior algebra and build instruction dictionary"""
        lines = self.behavior_content.strip().split('\n')

        for line in lines:
            line = line.strip()
            if '=' in line:
                # Parse a behavior equation like B(401000) = sub(401000).mov(401004)...
                left, right = line.split('=', 1)
                left = left.strip()
                right = right.strip()

                # Extract the address from B(address)
                address_match = re.search(r'B\((0x[0-9a-fA-F]+|[0-9a-fA-F]+)\)', left)
                if not address_match:
                    continue

                address = address_match.group(1)

                # Extract instruction sequence from the right side
                instr_sequence = []
                # Match instruction patterns
                instr_pattern = r'([a-zA-Z_]+)\((0x[0-9a-fA-F]+|[0-9a-fA-F]+|\w+(?:\s+\+\s+\w+)?|\w+\s*\[\w+(?:\s*\+\s*0x[0-9a-fA-F]+)?\]|rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r\d+|qword ptr \[.*?\])\)'

                for instr_match in re.finditer(instr_pattern, right):
                    mnemonic, operand = instr_match.groups()
                    if mnemonic.lower() != 'b':  # Skip behavior references
                        instr_sequence.append({
                            'name': mnemonic,
                            'address': operand,
                            'operands': self.parse_operands(mnemonic, operand),
                            'full': f"{mnemonic}({operand})"
                        })

                # Store the instruction sequence for this address
                self.behavior_dict[address] = instr_sequence

    def parse_operands(self, mnemonic, operand_str):
        """
        Parse operands from instruction

        Args:
            mnemonic: Instruction mnemonic
            operand_str: String containing the operand

        Returns:
            List of operands
        """
        # For better operand handling
        if operand_str.lower() in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp']:
            return [operand_str.upper()]
        elif operand_str.lower().startswith('r') and operand_str[1:].isdigit():
            return [operand_str.upper()]
        elif 'ptr' in operand_str.lower():
            # Memory operand, extract register if possible
            if '[' in operand_str and ']' in operand_str:
                reg_match = re.search(r'\[(rax|rbx|rcx|rdx|rsi|rdi|rsp|rbp|r\d+|rip)', operand_str.lower())
                if reg_match:
                    return [reg_match.group(1).upper()]
            return ['RSP']  # Default for memory operands
        else:
            # For instruction-specific handling
            if mnemonic.lower() == 'sub':
                return ['RAX', 'RBX']
            elif mnemonic.lower() == 'mov':
                return ['RAX', 'RBX']
            elif mnemonic.lower() == 'add':
                return ['RAX', 'RBX']
            elif mnemonic.lower() == 'xor':
                return ['RAX', 'RAX']  # Common for zeroing a register
            elif mnemonic.lower() == 'push':
                return ['RAX']
            elif mnemonic.lower() == 'pop':
                return ['RAX']
            elif mnemonic.lower() == 'lea':
                return ['RAX']
            elif mnemonic.lower() in ['je', 'jne', 'jg', 'jl', 'jmp']:
                return []  # Jump instructions don't have register operands

            # Default case
            return ['RAX']

    def get_sequence(self, address):
        """
        Get instruction sequence for a specific address

        Args:
            address: Address to look up

        Returns:
            List of instruction dictionaries
        """
        return self.behavior_dict.get(address, [])

    def get_all_sequences(self):
        """
        Get all instruction sequences

        Returns:
            Dictionary mapping addresses to instruction sequences
        """
        return self.behavior_dict

    def get_sequence_addresses(self):
        """
        Get list of all sequence addresses

        Returns:
            List of addresses
        """
        return list(self.behavior_dict.keys())


def extract_real_register_operations(behavior_file):
    """
    Extract real register operations from behavior algebra file

    Args:
        behavior_file: Path to behavior algebra file

    Returns:
        List of instruction sequences involving register operations
    """
    # Read the behavior file
    with open(behavior_file, 'r') as f:
        behavior_content = f.read()

    # Parse the behavior algebra
    parser = BehaviorAlgebraParser(behavior_content)

    # Find sequences with register operations
    register_ops = []
    for addr, sequence in parser.get_all_sequences().items():
        # Check if sequence contains register operations
        has_reg_ops = False
        for instr in sequence:
            if instr['name'].lower() in ['mov', 'add', 'sub', 'mul', 'div', 'xor', 'and', 'or', 'push', 'pop']:
                has_reg_ops = True
                break

        if has_reg_ops:
            register_ops.append((addr, sequence))

    return register_ops


def trace_specific_sequence(behavior_file, address):
    """
    Trace execution of a specific instruction sequence

    Args:
        behavior_file: Path to behavior algebra file
        address: Address of sequence to trace

    Returns:
        Tracer object with execution results
    """
    # Read the behavior file
    with open(behavior_file, 'r') as f:
        behavior_content = f.read()

    # Parse the behavior algebra
    parser = BehaviorAlgebraParser(behavior_content)

    # Get the sequence for the specified address
    sequence = parser.get_sequence(address)

    if not sequence:
        print(f"No sequence found for address {address}")
        return None

    # Create tracer and set up initial state
    tracer = SymbolicExecutionTracer()
    tracer.setup_initial_state({
        'registers': {
            'RAX': 0x100,
            'RBX': 0x200,
            'RCX': {'symbolic': True, 'name': 'input_x'},
            'RDX': {'symbolic': True, 'name': 'input_y'},
            'RSP': 0xFFFF0000,  # Initial stack pointer
            'RBP': 0xFFFF0100  # Initial base pointer
        },
        'memory': {
            '0x1000': 0x42,
            '0x2000': {'symbolic': True, 'name': 'mem_value'}
        },
        'flags': {
            'ZF': 0,  # Initial zero flag
            'CF': 0  # Initial carry flag
        }
    })

    # Execute the sequence
    tracer.execute_sequence(sequence)

    # Save the trace
    trace_file = f"trace_{address}.json"
    tracer.save_trace(trace_file)

    return tracer


def main():
    """Main function to demonstrate tracing of symbolic execution"""
    behavior_file = "behavior_algebra_20250326_194917.txt"

    # Extract register operations
    register_ops = extract_real_register_operations(behavior_file)
    print(f"Found {len(register_ops)} sequences with register operations")

    if not register_ops:
        print("No register operations found in behavior file.")
        return

    # Select sequences to trace - focus on ones with interesting instructions
    sequences_to_trace = []
    for addr, sequence in register_ops:
        # Look for sequences with multiple register operations
        ops = set()
        for instr in sequence:
            if instr['name'].lower() in ['mov', 'add', 'sub', 'xor', 'push', 'pop', 'lea']:
                ops.add(instr['name'].lower())

        # If sequence has 3+ different register operations, trace it
        if len(ops) >= 3:
            sequences_to_trace.append(addr)
            if len(sequences_to_trace) >= 3:
                break

    # If we didn't find enough interesting sequences, just use the first few
    if len(sequences_to_trace) < 3 and register_ops:
        for addr, _ in register_ops[:3]:
            if addr not in sequences_to_trace:
                sequences_to_trace.append(addr)
                if len(sequences_to_trace) >= 3:
                    break

    # Trace the selected sequences
    print("\nTracing selected sequences:")
    for i, addr in enumerate(sequences_to_trace):
        print(f"\nTracing sequence {i + 1}/{len(sequences_to_trace)} at address {addr}")
        trace_specific_sequence(behavior_file, addr)

    print("\nExecution tracing complete. JSON trace files have been created.")


if __name__ == "__main__":
    main()