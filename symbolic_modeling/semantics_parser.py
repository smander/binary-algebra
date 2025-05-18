class InstructionSemantics:
    def __init__(self, opcode, operands, precondition, postcondition):
        self.opcode = opcode
        self.operands = operands  # List of operand names like ["SRC", "DST"]
        self.precondition = precondition
        self.postcondition = postcondition

    def __str__(self):
        if self.operands:
            return f"{self.opcode} ({', '.join(self.operands)}): {self.precondition} -> {self.postcondition}"
        else:
            return f"{self.opcode}: {self.precondition} -> {self.postcondition}"


def parse_semantics_file(filename):
    """
    Parse a semantics file with instruction semantics

    Format expected:
    mov (SRC,DST) : 1 -> DST = sym_copy(SRC,DST)
    lea (ADDR,DST) : 1 -> DST = sym_copy(*ADDR,DST)
    syscall : 1 ->
    ...

    Returns:
        dict: Dictionary mapping opcode to InstructionSemantics
    """
    semantics = {}
    with open(filename, 'r') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue

            # Parse opcode and operands
            if ':' not in line:
                continue

            opcode_part, rest = line.split(':', 1)
            opcode_part = opcode_part.strip()

            # Check if there are operands in parentheses
            operands = []
            base_opcode = opcode_part
            if '(' in opcode_part and ')' in opcode_part:
                parts = opcode_part.split('(', 1)
                base_opcode = parts[0].strip()
                operands_part = parts[1].split(')', 1)[0].strip()
                operands = [op.strip() for op in operands_part.split(',')]

            # Parse precondition and postcondition
            if '->' not in rest:
                continue

            sem_parts = rest.strip().split('->')
            precondition = sem_parts[0].strip()
            postcondition = ""
            if len(sem_parts) > 1:
                postcondition = sem_parts[1].strip()

            # Store with just the base opcode as key
            semantics[base_opcode.lower()] = InstructionSemantics(base_opcode, operands, precondition, postcondition)

    return semantics