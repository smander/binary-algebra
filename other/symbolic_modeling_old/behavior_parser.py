# behavior_parser.py
"""
Parser for behavior algebra files and extraction of instruction sequences.
"""
import re

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
