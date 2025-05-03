class Instruction:
    def __init__(self, address, opcode, operands):
        self.address = address
        self.opcode = opcode
        self.operands = operands

    def __str__(self):
        if not self.operands:
            return f"{self.address}: {self.opcode}"
        return f"{self.address}: {self.opcode} {', '.join(self.operands)}"


def parse_trace_file(filename):
    """
    Parse a trace file with Intel x86 instructions

    Format expected:
    0x42394c: mov r15, r10
    0x42394f: mov r10, r14
    ...

    Returns:
        list: List of Instruction objects
    """
    instructions = []
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Parse address and instruction
            if ':' not in line:
                continue

            parts = line.split(':', 1)
            address = parts[0].strip()
            instruction_text = parts[1].strip()

            # Split opcode and operands
            if ' ' in instruction_text:
                opcode, operands_text = instruction_text.split(' ', 1)
                operands = [op.strip() for op in operands_text.split(',')]
            else:
                opcode = instruction_text
                operands = []

            instruction = Instruction(address, opcode, operands)
            instructions.append(instruction)

    return instructions