import re

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
        # Underlying array representation for bit-level operations
        self.R = [-1] * 64  # -1 represents symbolic values

        # Register information - mapping to register file
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

        # Abstract register representation for high-level operations
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

        # Flags array for bit-level access
        self.flags_array = [-1] * 32  # -1 represents symbolic values

        # Abstract flags representation
        self.flags = {
            'CF': SymbolicValue(name="CF", size=1),  # Carry flag
            'PF': SymbolicValue(name="PF", size=1),  # Parity flag
            'AF': SymbolicValue(name="AF", size=1),  # Auxiliary carry flag
            'ZF': SymbolicValue(name="ZF", size=1),  # Zero flag
            'SF': SymbolicValue(name="SF", size=1),  # Sign flag
            'OF': SymbolicValue(name="OF", size=1),  # Overflow flag
        }

        # Memory: Maps addresses to symbolic values
        self.memory = {}

        # Constraints
        self.constraints = []

        # Sync the abstract and array representation initially
        self._sync_registers_to_array()
        self._sync_flags_to_array()

    def _sync_registers_to_array(self):
        """Sync abstract register representation to array"""
        for reg_name, sym_val in self.registers.items():
            if not sym_val.symbolic and sym_val.value is not None:
                # Set concrete value in array
                start = self.REG_START[reg_name]
                length = self.REG_LENGTH[reg_name]

                # Convert integer to bytes
                for i in range(length):
                    byte_val = (sym_val.value >> (i * 8)) & 0xFF
                    self.R[start + i] = byte_val

    def _sync_array_to_registers(self):
        """Sync array representation to abstract registers"""
        for reg_name, sym_val in self.registers.items():
            start = self.REG_START[reg_name]
            length = self.REG_LENGTH[reg_name]

            # Check if any bytes are symbolic
            has_symbolic = False
            for i in range(length):
                if self.R[start + i] == -1:
                    has_symbolic = True
                    break

            if has_symbolic:
                # Register contains symbolic bytes
                sym_val.symbolic = True
                sym_val.value = None
            else:
                # Register has concrete value, reconstruct it
                value = 0
                for i in range(length):
                    value |= (self.R[start + i] & 0xFF) << (i * 8)

                sym_val.symbolic = False
                sym_val.value = value

    def _sync_flags_to_array(self):
        """Sync abstract flags to array"""
        flag_map = {'CF': 0, 'PF': 2, 'AF': 4, 'ZF': 6, 'SF': 7, 'OF': 11}

        for flag_name, idx in flag_map.items():
            sym_val = self.flags.get(flag_name)
            if sym_val and not sym_val.symbolic and sym_val.value is not None:
                self.flags_array[idx] = sym_val.value

    def _sync_array_to_flags(self):
        """Sync array to abstract flags"""
        flag_map = {'CF': 0, 'PF': 2, 'AF': 4, 'ZF': 6, 'SF': 7, 'OF': 11}

        for flag_name, idx in flag_map.items():
            if idx < len(self.flags_array):
                flag_val = self.flags_array[idx]
                sym_val = self.flags.get(flag_name)

                if flag_val == -1:
                    # Symbolic flag
                    if sym_val:
                        sym_val.symbolic = True
                        sym_val.value = None
                else:
                    # Concrete flag
                    if sym_val:
                        sym_val.symbolic = False
                        sym_val.value = flag_val

    def get_register(self, reg_name):
        """Get register value (abstract approach)"""
        if reg_name in self.registers:
            # Sync array to registers first
            self._sync_array_to_registers()
            return self.registers[reg_name]

        return None

    def set_register(self, reg_name, value):
        """Set register value (abstract approach)"""
        if reg_name in self.registers:
            if isinstance(value, SymbolicValue):
                # Defensive: If symbolic is False, value must not be None
                if not value.symbolic and value.value is None:
                    raise ValueError(f"Non-symbolic register {reg_name} assigned None value!")
                self.registers[reg_name] = value
            else:
                if value is None:
                    raise ValueError(f"Non-symbolic register {reg_name} assigned None value!")
                self.registers[reg_name].symbolic = False
                self.registers[reg_name].value = value

            # Sync registers to array
            self._sync_registers_to_array()

    def get_flag(self, flag_name):
        """Get flag value (abstract approach)"""
        if flag_name in self.flags:
            # Sync array to flags first
            self._sync_array_to_flags()
            return self.flags[flag_name]

        return None

    def set_flag(self, flag_name, value):
        """Set flag value (abstract approach)"""
        if flag_name in self.flags:
            if isinstance(value, SymbolicValue):
                self.flags[flag_name] = value
            else:
                self.flags[flag_name].symbolic = False
                self.flags[flag_name].value = value

            # Sync flags to array
            self._sync_flags_to_array()

    def get_memory(self, address, size=1):
        """Get memory value"""
        if address in self.memory:
            return self.memory[address]

        # Memory not initialized, create symbolic value
        sym_val = SymbolicValue(name=f"Mem_{hex(address)}", size=size)
        self.memory[address] = sym_val
        return sym_val

    def set_memory(self, address, value):
        """Set memory value"""
        if isinstance(value, SymbolicValue):
            self.memory[address] = value
        else:
            sym_val = SymbolicValue(value=value, symbolic=False, size=1)
            self.memory[address] = sym_val

    def get_bit_value(self, bit_position):
        """
        Get value of a bit from register file (bit-level approach)

        Args:
            bit_position: Absolute bit position

        Returns:
            '0', '1', or '$' (symbolic)
        """
        byte_index = bit_position // 8
        bit_in_byte = bit_position % 8

        if byte_index < 0 or byte_index >= len(self.R):
            return '0'  # Outside array bounds

        byte_value = self.R[byte_index]

        if byte_value == -1:
            return '$'  # Symbolic bit

        # Get specific bit value
        return '1' if (byte_value & (1 << bit_in_byte)) else '0'

    def set_bit_value(self, bit_position, bit_value):
        """
        Set value of a bit in register file (bit-level approach)

        Args:
            bit_position: Absolute bit position
            bit_value: '0', '1', or '$' (symbolic)
        """
        byte_index = bit_position // 8
        bit_in_byte = bit_position % 8

        if byte_index < 0 or byte_index >= len(self.R):
            return  # Outside array bounds

        if bit_value == '$':
            self.R[byte_index] = -1  # Mark byte as symbolic
        else:
            # If byte was symbolic, initialize with zeros
            if self.R[byte_index] == -1:
                self.R[byte_index] = 0

            # Set or clear bit
            if bit_value == '1':
                self.R[byte_index] |= (1 << bit_in_byte)
            else:
                self.R[byte_index] &= ~(1 << bit_in_byte)

        # After modifying array, sync to abstract representation
        self._sync_array_to_registers()

    def sym_add_bits(self, bit_a, bit_b, carry_in):
        """
        Symbolic addition of two bits with carry (bit-level approach)

        Args:
            bit_a, bit_b: '0', '1', or '$'
            carry_in: '0', '1', or '$'

        Returns:
            Tuple of (result_bit, carry_out) - both can be '0', '1', or '$'
        """

        # Convert to sets of possible values {0,1}
        def to_set(x):
            if x == '$':
                return {0, 1}
            else:
                return {int(x)}

        a_set = to_set(bit_a)
        b_set = to_set(bit_b)
        c_set = to_set(carry_in)

        # Enumerate all combinations
        possible_results = set()
        possible_carries = set()

        for a in a_set:
            for b in b_set:
                for c in c_set:
                    s = a + b + c  # sum of three bits
                    res_bit = s % 2
                    c_out = s // 2  # 0 or 1
                    possible_results.add(res_bit)
                    possible_carries.add(c_out)

        # Determine result and carry
        if len(possible_results) == 1:
            res_bit_str = '1' if (1 in possible_results) else '0'
        else:
            res_bit_str = '$'

        if len(possible_carries) == 1:
            carry_out_str = '1' if (1 in possible_carries) else '0'
        else:
            carry_out_str = '$'

        return (res_bit_str, carry_out_str)

    def sym_copy_reg_reg(self, dst_reg, src_reg):
        """
        Symbolically copy src_reg to dst_reg (bit-level approach)

        Args:
            dst_reg: Destination register name
            src_reg: Source register name
        """
        # Define starting bits and number of bits to copy
        start_bit_dst = self.REG_START[dst_reg] * 8
        start_bit_src = self.REG_START[src_reg] * 8
        num_bits = self.REG_LENGTH[dst_reg] * 8

        # Copy bits
        for i in range(num_bits):
            bit_position_dst = start_bit_dst + i
            bit_position_src = start_bit_src + i

            # Get bit value from source
            bit_value = self.get_bit_value(bit_position_src)

            # Set bit value in destination
            self.set_bit_value(bit_position_dst, bit_value)

        # After bit-level operation, sync to abstract representation
        self._sync_array_to_registers()

    def sym_add_reg_reg(self, dst_reg, src_reg):
        """
        Symbolically add src_reg to dst_reg (bit-level approach)

        Args:
            dst_reg: Destination register name
            src_reg: Source register name
        """
        # Starting bits
        start_bit_dst = self.REG_START[dst_reg] * 8
        start_bit_src = self.REG_START[src_reg] * 8
        num_bits = self.REG_LENGTH[dst_reg] * 8

        # Initialize carry as '0'
        carry = '0'

        for i in range(num_bits):
            # Absolute bit positions
            bit_position_dst = start_bit_dst + i
            bit_position_src = start_bit_src + i

            # Read bit values from dst and src
            bit_dst = self.get_bit_value(bit_position_dst)
            bit_src = self.get_bit_value(bit_position_src)

            # Perform symbolic addition with carry
            (res_bit, new_carry) = self.sym_add_bits(bit_dst, bit_src, carry)

            # Write result bit back to dst
            self.set_bit_value(bit_position_dst, res_bit)

            # Update carry
            carry = new_carry

        # Update CF flag based on final carry
        if carry == '1':
            self.flags_array[0] = 1
        elif carry == '0':
            self.flags_array[0] = 0
        else:  # carry == '$'
            self.flags_array[0] = -1

        # Sync array to abstract representation
        self._sync_array_to_registers()
        self._sync_array_to_flags()

    def abstract_add(self, dst_reg, src_reg):
        """
        Add src_reg to dst_reg (abstract approach)

        Args:
            dst_reg: Destination register name
            src_reg: Source register name
        """
        dst_val = self.get_register(dst_reg)
        src_val = self.get_register(src_reg)

        if dst_val and src_val:
            if not dst_val.symbolic and not src_val.symbolic:
                # Both values are concrete
                result = dst_val.value + src_val.value
                # Check if result exceeds register size
                max_val = (1 << (dst_val.size * 8)) - 1
                carry = 1 if result > max_val else 0
                result = result & max_val  # Truncate to register size

                # Set result
                self.set_register(dst_reg, result)

                # Set CF flag
                self.set_flag('CF', carry)
            else:
                # At least one value is symbolic, result is symbolic
                self.set_register(dst_reg, SymbolicValue(name=f"{dst_reg}+{src_reg}", size=dst_val.size))
                self.set_flag('CF', SymbolicValue(name=f"CF({dst_reg}+{src_reg})", size=1))

    def sym_subtract_bits(self, bit_a, bit_b, borrow_in):
        """
        Symbolic subtraction of two bits with borrow (bit-level approach)

        Args:
            bit_a, bit_b: '0', '1', or '$'
            borrow_in: '0', '1', or '$'

        Returns:
            Tuple of (result_bit, borrow_out) - both can be '0', '1', or '$'
        """

        # Convert to sets of possible values {0,1}
        def to_set(x):
            if x == '$':
                return {0, 1}
            else:
                return {int(x)}

        a_set = to_set(bit_a)
        b_set = to_set(bit_b)
        borrow_set = to_set(borrow_in)

        # Enumerate all combinations
        possible_results = set()
        possible_borrows = set()

        for a in a_set:
            for b in b_set:
                for borrow in borrow_set:
                    # Subtraction with borrow: a - b - borrow
                    # If a < b + borrow, we need to borrow from next bit
                    if a < b + borrow:
                        res_bit = a + 2 - b - borrow
                        borrow_out = 1
                    else:
                        res_bit = a - b - borrow
                        borrow_out = 0

                    possible_results.add(res_bit)
                    possible_borrows.add(borrow_out)

        # Determine result and borrow out
        if len(possible_results) == 1:
            res_bit_str = '1' if (1 in possible_results) else '0'
        else:
            res_bit_str = '$'

        if len(possible_borrows) == 1:
            borrow_out_str = '1' if (1 in possible_borrows) else '0'
        else:
            borrow_out_str = '$'

        return (res_bit_str, borrow_out_str)

    def sym_multiply_bits(self, bit_a, bit_b):
        """
        Symbolic multiplication of two bits (bit-level approach)

        Args:
            bit_a, bit_b: '0', '1', or '$'

        Returns:
            Result bit - can be '0', '1', or '$'
        """
        # For binary multiplication, result is just AND of inputs

        # If either bit is '0', result is '0'
        if bit_a == '0' or bit_b == '0':
            return '0'

        # If both bits are '1', result is '1'
        if bit_a == '1' and bit_b == '1':
            return '1'

        # If we reach here, at least one bit is symbolic, result is symbolic
        # unless the other bit is '0' (which is handled above)
        return '$'

    def sym_divide_bits(self, bit_a, bit_b):
        """
        Symbolic division of two bits (bit-level approach)

        Args:
            bit_a: Dividend bit - '0', '1', or '$'
            bit_b: Divisor bit - '0', '1', or '$'

        Returns:
            Tuple of (result_bit, error) where error is True if division by zero might occur
        """
        # Division by zero check
        if bit_b == '0':
            return ('$', True)  # Error: division by zero

        if bit_b == '$':
            # Divisor might be zero
            if bit_a == '0':
                # 0 divided by anything (including potentially zero) gives either 0 or undefined
                return ('0', True)
            else:
                # Result is symbolic, and error is possible
                return ('$', True)

        # At this point, bit_b is '1'
        if bit_a == '0':
            return ('0', False)
        elif bit_a == '1':
            return ('1', False)
        else:  # bit_a is '$'
            return ('$', False)

    def sym_sub_reg_reg(self, dst_reg, src_reg):
        """
        Symbolically subtract src_reg from dst_reg (bit-level approach)

        Args:
            dst_reg: Destination register name
            src_reg: Source register name
        """
        # Starting bits
        start_bit_dst = self.REG_START[dst_reg] * 8
        start_bit_src = self.REG_START[src_reg] * 8
        num_bits = self.REG_LENGTH[dst_reg] * 8

        # Initialize borrow as '0'
        borrow = '0'

        for i in range(num_bits):
            # Absolute bit positions
            bit_position_dst = start_bit_dst + i
            bit_position_src = start_bit_src + i

            # Read bit values from dst and src
            bit_dst = self.get_bit_value(bit_position_dst)
            bit_src = self.get_bit_value(bit_position_src)

            # Perform symbolic subtraction with borrow
            (res_bit, new_borrow) = self.sym_subtract_bits(bit_dst, bit_src, borrow)

            # Write result bit back to dst
            self.set_bit_value(bit_position_dst, res_bit)

            # Update borrow
            borrow = new_borrow

        # Update CF flag based on final borrow (CF works as borrow flag in subtraction)
        if borrow == '1':
            self.flags_array[0] = 1
        elif borrow == '0':
            self.flags_array[0] = 0
        else:  # borrow == '$'
            self.flags_array[0] = -1

        # Sync array to abstract representation
        self._sync_array_to_registers()
        self._sync_array_to_flags()

    def sym_mul_reg_reg(self, dst_reg, src_reg):
        """
        Symbolically multiply dst_reg by src_reg (bit-level approach)

        Args:
            dst_reg: Destination register name (result will be stored here)
            src_reg: Source register name (multiplier)
        """
        # This is a simplified approach. Full multiplication would require
        # partial products and shifts, similar to the long multiplication algorithm.

        # For simplicity, we'll implement single-precision multiplication

        # Take copies of the original values
        start_bit_dst = self.REG_START[dst_reg] * 8
        start_bit_src = self.REG_START[src_reg] * 8
        num_bits = min(self.REG_LENGTH[dst_reg], self.REG_LENGTH[src_reg]) * 8

        # Create temporary registers to store the original values
        temp_dst = ['0'] * num_bits
        temp_src = ['0'] * num_bits

        # Read the bits from the registers
        for i in range(num_bits):
            temp_dst[i] = self.get_bit_value(start_bit_dst + i)
            temp_src[i] = self.get_bit_value(start_bit_src + i)

        # Array to store the result (initially all zeros)
        result = ['0'] * (num_bits * 2)

        # Simulate the multiplication process
        for i in range(num_bits):
            # If the multiplier bit is symbolic or 1, we need to add the multiplicand
            if temp_src[i] == '1' or temp_src[i] == '$':
                # We need to add the multiplicand shifted by i positions
                carry = '0'
                for j in range(num_bits):
                    if j + i < len(result):
                        # Multiplicand bit j added to result bit j+i
                        if temp_src[i] == '1':
                            # If multiplier bit is 1, directly add the multiplicand bit
                            bit_a = result[j + i]
                            bit_b = temp_dst[j]
                            (new_bit, new_carry) = self.sym_add_bits(bit_a, bit_b, carry)
                            result[j + i] = new_bit
                            carry = new_carry
                        else:  # temp_src[i] == '$'
                            # If multiplier bit is symbolic, result bit becomes symbolic
                            # unless multiplicand bit is 0
                            if temp_dst[j] != '0':
                                result[j + i] = '$'
                                carry = '$'

        # Write the result back to the destination register
        # We'll just write as many bits as fit in the destination register
        for i in range(min(num_bits * 2, self.REG_LENGTH[dst_reg] * 8)):
            self.set_bit_value(start_bit_dst + i, result[i])

        # Set flags based on result
        # For simplicity, we'll just set CF and OF to symbolic if any input is symbolic
        if '$' in temp_dst or '$' in temp_src:
            self.flags_array[0] = -1  # CF
            self.flags_array[11] = -1  # OF
        else:
            # Zero flag (ZF) is set if the result is zero
            if all(bit == '0' for bit in result):
                self.flags_array[6] = 1
            else:
                self.flags_array[6] = 0

        # Sync array to abstract representation
        self._sync_array_to_registers()
        self._sync_array_to_flags()

    def sym_div_reg_reg(self, dst_reg, src_reg):
        """
        Symbolically divide dst_reg by src_reg (bit-level approach)

        Args:
            dst_reg: Destination register name (dividend, result stored here)
            src_reg: Source register name (divisor)
        """
        # Division is complex at the bit level
        # This is a simplified implementation

        # Check for potential division by zero
        start_bit_src = self.REG_START[src_reg] * 8
        num_bits = self.REG_LENGTH[src_reg] * 8

        # Read divisor bits
        divisor_bits = []
        for i in range(num_bits):
            divisor_bits.append(self.get_bit_value(start_bit_src + i))

        # If all divisor bits are 0, or any is symbolic and the rest are 0,
        # we have a potential division by zero
        potential_div_by_zero = True
        has_one_bit = False

        for bit in divisor_bits:
            if bit == '1':
                potential_div_by_zero = False
                has_one_bit = True
                break

        # If potential division by zero, result is symbolic and flags are set
        if potential_div_by_zero:
            # Set destination register to symbolic
            for i in range(self.REG_LENGTH[dst_reg] * 8):
                self.set_bit_value(self.REG_START[dst_reg] * 8 + i, '$')

            # Set flags to symbolic
            for flag_pos in [0, 6, 7, 11]:  # CF, ZF, SF, OF
                self.flags_array[flag_pos] = -1

            # Add constraint about division by zero
            self.constraints.append(f"Potential division by zero when dividing {dst_reg} by {src_reg}")

            # Sync and return
            self._sync_array_to_registers()
            self._sync_array_to_flags()
            return

        # If any bit in divisor or dividend is symbolic, result is symbolic
        start_bit_dst = self.REG_START[dst_reg] * 8
        dividend_bits = []
        for i in range(self.REG_LENGTH[dst_reg] * 8):
            dividend_bits.append(self.get_bit_value(start_bit_dst + i))

        if '$' in divisor_bits or '$' in dividend_bits:
            # Set destination register to symbolic
            for i in range(self.REG_LENGTH[dst_reg] * 8):
                self.set_bit_value(self.REG_START[dst_reg] * 8 + i, '$')

            # Set flags to symbolic
            for flag_pos in [0, 6, 7, 11]:  # CF, ZF, SF, OF
                self.flags_array[flag_pos] = -1

            # Sync and return
            self._sync_array_to_registers()
            self._sync_array_to_flags()
            return

        # At this point, both operands are concrete, so we can perform the division
        # But since we're in a symbolic execution engine, we'll just make the implementation simple

        # Get concrete values from bits
        dividend_val = 0
        for i, bit in enumerate(dividend_bits):
            if bit == '1':
                dividend_val |= (1 << i)

        divisor_val = 0
        for i, bit in enumerate(divisor_bits):
            if bit == '1':
                divisor_val |= (1 << i)

        # Perform division
        quotient_val = dividend_val // divisor_val

        # Convert result back to bits
        for i in range(self.REG_LENGTH[dst_reg] * 8):
            bit_val = '1' if (quotient_val & (1 << i)) else '0'
            self.set_bit_value(start_bit_dst + i, bit_val)

        # Set flags based on result
        self.flags_array[6] = 1 if quotient_val == 0 else 0  # ZF
        self.flags_array[7] = 1 if quotient_val < 0 else 0  # SF

        # Sync array to abstract representation
        self._sync_array_to_registers()
        self._sync_array_to_flags()

    def abstract_subtract(self, dst_reg, src_reg):
        """
        Subtract src_reg from dst_reg (abstract approach)

        Args:
            dst_reg: Destination register name
            src_reg: Source register name
        """
        dst_val = self.get_register(dst_reg)
        src_val = self.get_register(src_reg)

        if dst_val and src_val:
            if not dst_val.symbolic and not src_val.symbolic:
                # Both values are concrete
                result = dst_val.value - src_val.value
                # Check for borrowing
                borrow = 1 if result < 0 else 0

                # Truncate to register size
                max_val = (1 << (dst_val.size * 8)) - 1
                if result < 0:
                    result = (result & max_val)

                # Set result
                self.set_register(dst_reg, result)

                # Set CF flag
                self.set_flag('CF', borrow)
            else:
                # At least one value is symbolic, result is symbolic
                self.set_register(dst_reg, SymbolicValue(name=f"{dst_reg}-{src_reg}", size=dst_val.size))
                self.set_flag('CF', SymbolicValue(name=f"CF({dst_reg}-{src_reg})", size=1))

    def abstract_multiply(self, dst_reg, src_reg):
        """
        Multiply dst_reg by src_reg (abstract approach)

        Args:
            dst_reg: Destination register name
            src_reg: Source register name
        """
        dst_val = self.get_register(dst_reg)
        src_val = self.get_register(src_reg)

        if dst_val and src_val:
            if not dst_val.symbolic and not src_val.symbolic:
                # Both values are concrete
                result = dst_val.value * src_val.value

                # Truncate to register size
                max_val = (1 << (dst_val.size * 8)) - 1
                truncated_result = result & max_val

                # Check if truncation happened
                overflow = (result != truncated_result)

                # Set result
                self.set_register(dst_reg, truncated_result)

                # Set flags
                self.set_flag('CF', 1 if overflow else 0)
                self.set_flag('OF', 1 if overflow else 0)
            else:
                # At least one value is symbolic, result is symbolic
                self.set_register(dst_reg, SymbolicValue(name=f"{dst_reg}*{src_reg}", size=dst_val.size))
                self.set_flag('CF', SymbolicValue(name=f"CF({dst_reg}*{src_reg})", size=1))
                self.set_flag('OF', SymbolicValue(name=f"OF({dst_reg}*{src_reg})", size=1))

    def abstract_divide(self, dst_reg, src_reg):
        """
        Divide dst_reg by src_reg (abstract approach)

        Args:
            dst_reg: Destination register name
            src_reg: Source register name
        """
        dst_val = self.get_register(dst_reg)
        src_val = self.get_register(src_reg)

        if dst_val and src_val:
            if not src_val.symbolic and src_val.value == 0:
                # Division by zero
                self.constraints.append(f"Division by zero: {dst_reg} / {src_reg}")
                self.set_register(dst_reg, SymbolicValue(name=f"{dst_reg}/0", size=dst_val.size))
                return

            if not dst_val.symbolic and not src_val.symbolic:
                # Both values are concrete
                result = dst_val.value // src_val.value

                # Set result
                self.set_register(dst_reg, result)

                # Set flags
                self.set_flag('ZF', 1 if result == 0 else 0)
                self.set_flag('SF', 1 if result < 0 else 0)
            else:
                # At least one value is symbolic, result is symbolic
                if src_val.symbolic:
                    # Add constraint for division by zero
                    self.constraints.append(f"Assuming {src_reg} != 0 for division")

                self.set_register(dst_reg, SymbolicValue(name=f"{dst_reg}/{src_reg}", size=dst_val.size))
                self.set_flag('ZF', SymbolicValue(name=f"ZF({dst_reg}/{src_reg})", size=1))
                self.set_flag('SF', SymbolicValue(name=f"SF({dst_reg}/{src_reg})", size=1))

    def clone(self):
        """Create a deep copy of the environment"""
        new_env = SymbolicEnvironment()

        # Copy array representation
        new_env.R = self.R.copy()
        new_env.flags_array = self.flags_array.copy()

        # Copy abstract representation
        for reg_name, sym_val in self.registers.items():
            new_env.registers[reg_name] = SymbolicValue(
                value=sym_val.value,
                symbolic=sym_val.symbolic,
                size=sym_val.size,
                name=sym_val.name
            )

        for flag_name, sym_val in self.flags.items():
            new_env.flags[flag_name] = SymbolicValue(
                value=sym_val.value,
                symbolic=sym_val.symbolic,
                size=sym_val.size,
                name=sym_val.name
            )

        # Copy memory
        for addr, sym_val in self.memory.items():
            new_env.memory[addr] = SymbolicValue(
                value=sym_val.value,
                symbolic=sym_val.symbolic,
                size=sym_val.size,
                name=sym_val.name
            )

        # Copy constraints
        new_env.constraints = self.constraints.copy()

        return new_env

    def print_state(self):
        """Print environment state for debugging"""
        print("Register State:")
        for reg_name in ['RAX', 'RBX', 'RCX', 'RDX', 'RSI', 'RDI', 'RBP', 'RSP']:
            reg_val = self.get_register(reg_name)
            if reg_val.symbolic:
                val_str = '$'
            else:
                val_str = hex(reg_val.value) if reg_val.value is not None else 'None'
            print(f"{reg_name}: {val_str}")

        print("\nFlag State:")
        for flag_name in ['CF', 'ZF', 'SF', 'OF']:
            flag_val = self.get_flag(flag_name)
            if flag_val.symbolic:
                val_str = '$'
            else:
                val_str = str(flag_val.value) if flag_val.value is not None else 'None'
            print(f"{flag_name}: {val_str}")

        print("\nConstraints:")
        for constraint in self.constraints:
            print(f"- {constraint}")


def parse_template(template_str):
    """Parse template string to extract parts and constraints"""
    template_parts = []
    constraints = {}

    # Split by lines and semicolons
    lines = template_str.strip().split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            continue

        if ';' in line:
            # Multiple parts on one line
            parts = line.split(';')
            for part in parts:
                part = part.strip()
                if not part:
                    continue

                if ':' in part:
                    # This is a constraint
                    label, constraint = part.split(':', 1)
                    label = label.strip()
                    constraint = constraint.strip()
                    constraints[label] = constraint
                else:
                    # This is a template part
                    template_parts.append(part)
        elif ':' in line:
            # This is a constraint
            label, constraint = line.split(':', 1)
            label = label.strip()
            constraint = constraint.strip()
            constraints[label] = constraint
        else:
            # This is a template part
            template_parts.append(line)

    return template_parts, constraints


def check_constraint(env, constraint):
    """Check if a constraint is satisfiable"""
    # Parse memory constraints (e.g., "Mem(i) != 0")
    if "Mem(" in constraint and ")" in constraint:
        index_str = constraint[constraint.find("(") + 1:constraint.find(")")]

        # Extract operator and value
        if "!=" in constraint:
            op = "!="
            parts = constraint.split("!=", 1)
        elif "==" in constraint:
            op = "=="
            parts = constraint.split("==", 1)
        else:
            return True  # Unknown operator

        value_str = parts[1].strip()
        try:
            value = int(value_str)
        except:
            return True  # Non-numeric value

        # Handle symbolic or concrete index
        if index_str == 'i':
            # Symbolic index
            env.constraints.append(constraint)
            return True
        else:
            try:
                addr = int(index_str)
                # Check memory at address
                mem_val = env.get_memory(addr)

                if not mem_val.symbolic:
                    # Concrete memory value
                    if op == "!=":
                        return mem_val.value != value
                    elif op == "==":
                        return mem_val.value == value

                # Memory is symbolic - add constraint
                env.constraints.append(constraint)
                return True
            except:
                return True  # Invalid index

    # Parse flag constraints (e.g., "FLAGS[0] == 0")
    elif "FLAGS[" in constraint and "]" in constraint:
        index_str = constraint[constraint.find("[") + 1:constraint.find("]")]

        # Extract operator and value
        if "!=" in constraint:
            op = "!="
            parts = constraint.split("!=", 1)
        elif "==" in constraint:
            op = "=="
            parts = constraint.split("==", 1)
        else:
            return True  # Unknown operator

        value_str = parts[1].strip()
        try:
            value = int(value_str)
        except:
            return True  # Non-numeric value

        try:
            index = int(index_str)
            # Map index to flag name
            flag_names = ['CF', 'PF', 'AF', 'ZF', 'SF', 'OF']

            if index < len(flag_names):
                flag_name = flag_names[index]
                flag_val = env.get_flag(flag_name)

                if flag_val and not flag_val.symbolic:
                    # Concrete flag value
                    if op == "!=":
                        return flag_val.value != value
                    elif op == "==":
                        return flag_val.value == value

            # Flag is symbolic or invalid index - add constraint
            env.constraints.append(constraint)
            return True
        except:
            return True  # Invalid index

    return True  # Unknown constraint format


def execute_instruction(env, instruction):
    """Execute instruction symbolically"""
    mnemonic = instruction['name'].lower()

    if mnemonic == 'add':
        print("Performing symbolic addition")
        env.sym_add_reg_reg('RAX', 'RBX')
    elif mnemonic == 'sub':
        print("Performing symbolic subtraction")
        env.sym_sub_reg_reg('RAX', 'RBX')
    elif mnemonic == 'imul' or mnemonic == 'imul':
        print("Performing symbolic multiplication")
        env.sym_mul_reg_reg('RAX', 'RBX')
    elif mnemonic == 'div' or mnemonic == 'idiv':
        print("Performing symbolic division")
        env.sym_div_reg_reg('RAX', 'RBX')
    elif mnemonic == 'mov':
        print("Performing symbolic move")
        env.sym_copy_reg_reg('RAX', 'RBX')
    elif mnemonic == 'xor':
        print("Simulating XOR (setting register to 0)")
        env.set_register('RAX', 0)
    else:
        print(f"Skipping unimplemented operation: {mnemonic}")


    return env


def SymModStep(env, instruction):
    """Perform one step of symbolic modeling"""
    return execute_instruction(env, instruction)


def SymMod(trace, template):
    """Symbolic modeling of instruction trace according to template"""
    # Parse template and constraints
    template_parts, constraints = parse_template(template)

    # Initialize symbolic environment
    env = SymbolicEnvironment()

    # Process each instruction in trace
    for i, instruction in enumerate(trace):
        # Check if instruction is part of template
        for part in template_parts:
            if '.' in part:
                label, _ = part.split('.')
                if label.startswith('a') and label[1:].isdigit():
                    template_index = int(label[1:]) - 1  # Convert a1 to index 0

                    if i == template_index and label in constraints:
                        # Apply constraint
                        constraint = constraints[label]
                        if not check_constraint(env, constraint):
                            print(f"Constraint not satisfiable: {constraint}")
                            return None

        # Execute instruction symbolically
        env = SymModStep(env, instruction)

    return env


def parse_behavior_file(content):
    """
    A simple parser that extracts instructions from the behavior file.
    It searches for patterns like: mnemonic(address)
    and returns a list of instruction dictionaries.
    """
    pattern = r'(\w+)\((0x[0-9A-Fa-f]+|\d+)\)'
    instructions = []
    for match in re.finditer(pattern, content):
        name, address = match.groups()
        # Skip labels or non-instruction symbols (e.g. "B")
        if name.upper() == "B":
            continue
        instructions.append({'name': name, 'address': address})
    return instructions


def main():
    """Main function to test hybrid symbolic modeling using files"""

    # Read the behavior (trace) file
    try:
        with open('data/behavior_algebra_20250326_194917.txt', 'r') as f:
            behavior_content = f.read()
    except IOError as e:
        print("Error reading behavior file:", e)
        return

    # Read the template file
    try:
        with open('template.txt', 'r') as f:
            template = f.read()
    except IOError as e:
        print("Error reading template file:", e)
        return

    # Parse the behavior file into a trace (list of instruction dictionaries)
    test_trace = parse_behavior_file(behavior_content)
    if not test_trace:
        print("No valid instructions found in behavior file.")
        return

    print("Running SymMod with instructions from file...")
    final_env = SymMod(test_trace, template)

    if final_env:
        print("Symbolic modeling completed successfully!")
        final_env.print_state()
    else:
        print("Symbolic modeling failed - constraints not satisfiable.")


if __name__ == "__main__":
    main()
