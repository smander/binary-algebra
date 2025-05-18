#!/usr/bin/env python3

"""
Semantics parser for symbolic modeling
Parses semantics files defining instruction semantics
"""


class InstructionSemantics:
    """
    Class representing the semantics of an instruction
    """

    def __init__(self, opcode, precondition, postcondition):
        self.opcode = opcode
        self.precondition = precondition
        self.postcondition = postcondition

    def __str__(self):
        return f"{self.opcode}: {self.precondition} -> {self.postcondition}"


def parse_semantics_file(filename):
    """
    Parse a semantics file with instruction semantics

    Format expected:
    mov : 1 -> DST = BIN_COPY(SRC,DST)
    lea : 1 -> DST = BIN_COPY(*ADDR,DST)
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

            # Parse semantics line
            # Format: opcode : precondition -> postcondition
            if ':' not in line:
                continue

            parts = line.split(':', 1)
            opcode = parts[0].strip()

            if '->' not in parts[1]:
                continue

            sem_parts = parts[1].strip().split('->')
            precondition = sem_parts[0].strip()
            postcondition = ""
            if len(sem_parts) > 1:
                postcondition = sem_parts[1].strip()

            semantics[opcode] = InstructionSemantics(opcode, precondition, postcondition)

    return semantics