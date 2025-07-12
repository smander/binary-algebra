#!/usr/bin/env python3
"""
Angr-based disassembler for CWE-787 analysis
Extracts assembly code with focus on main function
"""

import angr
import sys
import os

def disassemble_with_angr(binary_path, output_file=None, focus_main=True):
    """
    Use angr to disassemble binary and extract assembly
    """
    if not os.path.exists(binary_path):
        print(f"Error: Binary {binary_path} not found")
        return False
    
    print(f"Loading binary: {binary_path}")
    
    # Load binary without auto-loading libraries to reduce noise
    proj = angr.Project(binary_path, auto_load_libs=False)
    
    # Get main object (the actual binary, not libraries)
    main_obj = proj.loader.main_object
    
    print(f"Architecture: {proj.arch}")
    print(f"Entry point: 0x{proj.entry:x}")
    
    # Find main function if focusing on it
    main_addr = None
    if focus_main:
        try:
            main_symbol = main_obj.get_symbol('main')
            if main_symbol:
                main_addr = main_symbol.rebased_addr
                print(f"Main function at: 0x{main_addr:x}")
        except:
            print("Warning: Could not find main symbol, using entry point")
            main_addr = proj.entry
    
    # Create CFG (Control Flow Graph)
    print("Analyzing control flow...")
    if focus_main and main_addr:
        cfg = proj.analyses.CFGFast(start_at_entry=False, function_starts=[main_addr])
        start_addr = main_addr
    else:
        cfg = proj.analyses.CFGFast()
        start_addr = proj.entry
    
    # Prepare output
    if output_file:
        out = open(output_file, 'w')
    else:
        out = sys.stdout
    
    try:
        out.write(f"# Angr Disassembly of {binary_path}\n")
        out.write(f"# Architecture: {proj.arch}\n")
        out.write(f"# Entry: 0x{proj.entry:x}\n")
        if main_addr:
            out.write(f"# Main: 0x{main_addr:x}\n")
        out.write("#" + "="*60 + "\n\n")
        
        # Get all functions
        functions = cfg.functions
        
        if focus_main and main_addr and main_addr in functions:
            # Focus only on main function
            functions_to_analyze = [main_addr]
            out.write("# MAIN FUNCTION ONLY\n\n")
        else:
            # Analyze all functions in main object
            functions_to_analyze = [addr for addr in functions.keys() 
                                  if main_obj.min_addr <= addr <= main_obj.max_addr]
            out.write("# ALL FUNCTIONS IN MAIN BINARY\n\n")
        
        total_instructions = 0
        
        for func_addr in sorted(functions_to_analyze):
            func = functions[func_addr]
            out.write(f"Function: {func.name} @ 0x{func_addr:x}\n")
            out.write("-" * 50 + "\n")
            
            # Get basic blocks in function
            for block_addr in sorted(func.block_addrs):
                try:
                    block = proj.factory.block(block_addr)
                    out.write(f"\nBasic Block @ 0x{block_addr:x}:\n")
                    
                    # Disassemble each instruction
                    for insn in block.capstone.insns:
                        out.write(f"0x{insn.address:08x}:  {insn.mnemonic:8s} {insn.op_str}\n")
                        total_instructions += 1
                        
                        # Highlight potential CWE-787 patterns
                        if any(x in insn.mnemonic.lower() for x in ['mov', 'store', 'str']):
                            if '[' in insn.op_str and ('+' in insn.op_str or '-' in insn.op_str):
                                out.write("                    ^^ Potential buffer access\n")
                
                except Exception as e:
                    out.write(f"Error disassembling block 0x{block_addr:x}: {e}\n")
            
            out.write("\n" + "="*60 + "\n")
        
        out.write(f"\n# Total instructions analyzed: {total_instructions}\n")
        print(f"Total instructions: {total_instructions}")
        
    finally:
        if output_file:
            out.close()
            print(f"Assembly saved to: {output_file}")
    
    return True

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 angr_disasm.py <binary> [output_file] [--full]")
        print("  binary: Path to binary to disassemble")
        print("  output_file: Optional output file (default: stdout)")
        print("  --full: Analyze all functions (default: main only)")
        sys.exit(1)
    
    binary_path = sys.argv[1]
    output_file = sys.argv[2] if len(sys.argv) > 2 and not sys.argv[2].startswith('--') else None
    focus_main = '--full' not in sys.argv
    
    success = disassemble_with_angr(binary_path, output_file, focus_main)
    
    if not success:
        sys.exit(1)

if __name__ == "__main__":
    main()