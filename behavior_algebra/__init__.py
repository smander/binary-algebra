"""
Behavior Algebra Disassembler - A tool to analyze binary files and generate behavior algebra expressions.
"""
from .disassembler import disassemble_binary, generate_behavior_algebra

__version__ = '0.1.0'
__all__ = ['disassemble_binary', 'generate_behavior_algebra']

# File: behavior_algebra/disassembler.py
# !/usr/bin/env python3
"""
Core functionality for disassembling binaries and generating behavior algebra.
"""