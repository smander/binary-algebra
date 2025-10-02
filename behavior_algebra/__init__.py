"""behavior_algebra public package interface."""

from .disassembler import (
    DyninstDisassembler, 
    disassemble_binary, 
    generate_behavior_algebra,
    InstructionRecord,
    OperandInfo,
    FunctionInfo,
    LoopInfo
)

__version__ = "0.2.0"
__all__ = [
    "DyninstDisassembler", 
    "disassemble_binary", 
    "generate_behavior_algebra",
    "InstructionRecord",
    "OperandInfo", 
    "FunctionInfo",
    "LoopInfo"
]
