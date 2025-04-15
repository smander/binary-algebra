import sys
import subprocess
import os
import datetime
import argparse
import json
import tempfile
import shutil
from pathlib import Path


def install(package):
    """Install a Python package if not already installed."""
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", package])
    except subprocess.CalledProcessError:
        print(f"Failed to install {package}. If using macOS or a protected environment:")
        print("1. Create a virtual environment: python3 -m venv venv")
        print("2. Activate it: source venv/bin/activate")
        print(f"3. Install the package: pip install {package}")
        print("Then try running this script again within the virtual environment.")
        sys.exit(1)


def check_dependencies(quiet=False):
    """
    Check if required dependencies are installed.

    Args:
        quiet: If True, don't print messages about installing

    Returns:
        True if all dependencies are available, False otherwise
    """
    # Check for angr
    try:
        import angr
        return True
    except ImportError:
        if not quiet:
            print("angr not found.")
            print("\nTo install dependencies, create and use a virtual environment:")
            print("  python3 -m venv venv")
            print("  source venv/bin/activate")
            print("  pip install angr")
            print("\nOr if using objdump only, run with --objdump flag.")
        return False


def is_objdump_available():
    """Check if objdump is available on the system."""
    try:
        subprocess.run(["objdump", "--version"], capture_output=True, check=True)
        return True
    except (subprocess.SubprocessError, FileNotFoundError):
        return False


def parse_instructions(input_data):
    instructions = []
    lines = input_data.strip().split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Splitting "address: mnemonic operands"
        parts = line.split(':', 1)
        if len(parts) != 2:
            continue

        address = parts[0].strip()
        rest = parts[1].strip()

        rest_parts = rest.split(None, 1)
        mnemonic = rest_parts[0].strip()
        operands = rest_parts[1].strip() if len(rest_parts) > 1 else ""

        instructions.append({
            "address": address,
            "mnemonic": mnemonic,
            "operands": operands
        })
    return instructions


def is_dynamic_operand(operand):
    """
    Determine if an operand is dynamic (depends on runtime values).

    Args:
        operand: The operand string to check

    Returns:
        True if the operand is dynamic, False if it's a static address
    """
    # Direct addresses are not dynamic
    if operand.startswith("0x") or all(c in "0123456789abcdef" for c in operand.split()[0]):
        return False

    # If it contains "ptr" and no brackets, it might be a direct symbol
    # But if it has both "ptr" and brackets, let the bracket logic handle it
    if "ptr" in operand and "[" not in operand:
        return True

    # Register list for detecting register references
    register_names = [
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
        "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
        "rip", "eip", "ip",
        # 32-bit extended registers
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
        # 16-bit extended registers
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
        # 8-bit extended registers
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
        # Segment registers
        "cs", "ds", "es", "fs", "gs", "ss"
    ]

    # If it contains brackets (memory reference) we need to check inside
    if "[" in operand and "]" in operand:
        # Extract what's inside the brackets
        inside_brackets = operand[operand.find("[") + 1:operand.find("]")]

        # Check for register references
        for reg in register_names:
            if reg in inside_brackets:
                return True

        # Check for operators that would make it dynamic
        operators = ["+", "-", "*", "×", "·"]
        has_operator = False

        for op in operators:
            if op in inside_brackets:
                has_operator = True
                break

        if has_operator:
            # If it has an operator, check if both sides are numeric constants
            # Example: [0x401000+0x10] - this is still static
            parts = None
            for op in operators:
                if op in inside_brackets:
                    parts = inside_brackets.split(op, 1)
                    break

            if parts and len(parts) == 2:
                left = parts[0].strip()
                right = parts[1].strip()

                left_numeric = left.startswith("0x") or left.isdigit()
                right_numeric = right.startswith("0x") or right.isdigit()

                # If both sides are numeric, it's a static reference
                if left_numeric and right_numeric:
                    return False

            # Otherwise, it's dynamic (e.g. [base+index])
            return True

        # If no operators and no registers, it might be a static memory reference
        # Check if it's a pure number or hex address
        if inside_brackets.startswith("0x") or inside_brackets.isdigit():
            return False

        # If we get here, it's probably a symbol or other construct
        # Default to treating it as dynamic
        return True

    # Labels, function names and other symbols without ptr or brackets
    # are typically static references (not dynamic)
    return False


def generate_behavior_algebra(input_data, output_path):
    instructions = parse_instructions(input_data)

    # Create a set of all jump target addresses to identify behavior entry points
    jump_targets = set()
    for instr in instructions:
        mnem = instr["mnemonic"]
        if mnem.startswith("j") or mnem == "call":
            # Extract target address from operands
            operands = instr["operands"]
            if operands and not is_dynamic_operand(operands):
                # Only add direct addresses, not dynamic references
                try:
                    # Try to extract a hex address from the operands
                    if "0x" in operands:
                        parts = operands.split("0x", 1)
                        addr_part = "0x" + parts[1].split()[0].rstrip(",")
                        # Convert to standardized hex format without 0x prefix
                        addr_int = int(addr_part, 16)
                        jump_targets.add(f"{addr_int:x}")
                    else:
                        # Direct address without 0x prefix
                        possible_addr = operands.split()[0].rstrip(",")
                        if all(c in "0123456789abcdef" for c in possible_addr):
                            jump_targets.add(possible_addr)
                except (ValueError, IndexError):
                    # If we can't parse the address, just continue
                    pass

    # Ensure directory exists
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

    # Define a special placeholder for dynamic/unknown behaviors
    DYNAMIC_BEHAVIOR = "B(DYNAMIC)"

    # Add a list to collect all the dynamic behaviors we need to define
    dynamic_behaviors = set()

    with open(output_path, "w") as f:
        i = 0
        # Keep track of processed addresses to avoid infinite loops
        processed_addresses = set()

        while i < len(instructions):
            current = instructions[i]
            addr = current["address"]
            mnem = current["mnemonic"]

            # Skip if we've already processed this instruction (prevents infinite loops)
            if addr in processed_addresses:
                i += 1
                continue

            # Add this address to the processed set
            processed_addresses.add(addr)

            # Handle return instructions - they terminate the current behavior
            if mnem == "ret" or mnem == "return":
                f.write(f"B({addr}) = ret({addr}),\n")
                i += 1
                continue

            # Process call instructions
            elif mnem == "call":
                destination = current["operands"]

                # Check if this is a dynamic/indirect call
                is_dynamic = is_dynamic_operand(destination)

                if is_dynamic:
                    # For dynamic calls, use our special placeholder
                    # Record the dynamic call for later definition
                    dynamic_behaviors.add(f"call({addr}):{destination}")

                    # Next instruction after call
                    next_idx = i + 1
                    if next_idx < len(instructions):
                        addr_next = instructions[next_idx]["address"]
                        f.write(f"B({addr}) = {DYNAMIC_BEHAVIOR}; B({addr_next}),\n")
                    else:
                        # If this is the last instruction, just show the call without continuation
                        f.write(f"B({addr}) = {DYNAMIC_BEHAVIOR},\n")
                else:
                    # Regular direct call with static address
                    # Get clean destination address
                    clean_dest = destination
                    if "0x" in destination:
                        parts = destination.split("0x", 1)
                        clean_dest = "0x" + parts[1].split()[0].rstrip(",")

                    # Next instruction after call
                    next_idx = i + 1
                    if next_idx < len(instructions):
                        addr_next = instructions[next_idx]["address"]
                        f.write(f"B({addr}) = B({clean_dest}); B({addr_next}),\n")
                    else:
                        # If this is the last instruction, just show the call without continuation
                        f.write(f"B({addr}) = B({clean_dest}),\n")
                i += 1

            # Process jump instructions (mnemonics starting with 'j')
            elif mnem.startswith("j"):
                destination = current["operands"]

                # Check if this is a dynamic/indirect jump
                is_dynamic = is_dynamic_operand(destination)

                if is_dynamic:
                    # For dynamic jumps, use our special placeholder
                    # Record the dynamic jump for later definition
                    dynamic_behaviors.add(f"{mnem}({addr}):{destination}")

                    # For conditional jumps, include fallthrough
                    if mnem != "jmp":
                        next_idx = i + 1
                        if next_idx < len(instructions):
                            addr_next = instructions[next_idx]["address"]
                            f.write(
                                f"B({addr}) = {mnem}({addr}).{DYNAMIC_BEHAVIOR} + !{mnem}({addr}).B({addr_next}),\n")
                        else:
                            fallthrough_addr = f"{int(addr, 16) + 1:x}"
                            f.write(
                                f"B({addr}) = {mnem}({addr}).{DYNAMIC_BEHAVIOR} + !{mnem}({addr}).B({fallthrough_addr}),\n")
                    else:
                        # Unconditional jumps have no fallthrough
                        f.write(f"B({addr}) = {DYNAMIC_BEHAVIOR},\n")
                else:
                    # Regular direct jump with static address
                    # Clean destination address
                    clean_dest = destination
                    if "0x" in destination:
                        parts = destination.split("0x", 1)
                        clean_dest = "0x" + parts[1].split()[0].rstrip(",")

                    # Next instruction (fallthrough) address
                    next_idx = i + 1
                    if next_idx < len(instructions):
                        addr_next = instructions[next_idx]["address"]
                        # Check if this is a conditional or unconditional jump
                        if mnem == "jmp":
                            # Unconditional jump - no fallthrough
                            f.write(f"B({addr}) = B({clean_dest}),\n")
                        else:
                            # Conditional jump - has fallthrough
                            f.write(f"B({addr}) = {mnem}({addr}).B({clean_dest}) + !{mnem}({addr}).B({addr_next}),\n")
                    else:
                        # If this is the last instruction
                        if mnem == "jmp":
                            f.write(f"B({addr}) = B({clean_dest}),\n")
                        else:
                            # Use addr+1 as fallthrough for conditional jumps
                            fallthrough_addr = f"{int(addr, 16) + 1:x}"
                            f.write(
                                f"B({addr}) = {mnem}({addr}).B({clean_dest}) + !{mnem}({addr}).B({fallthrough_addr}),\n")
                i += 1

            # Non-control flow instructions - collect sequences until a control flow instruction
            else:
                start_addr = addr
                seq = []

                # Track the initial value of i to prevent infinite loops
                initial_i = i

                # Collect instructions until we hit a control flow instruction or a jump target
                while i < len(instructions) and not (
                        instructions[i]["mnemonic"] == "call" or
                        instructions[i]["mnemonic"].startswith("j") or
                        instructions[i]["mnemonic"] == "ret" or
                        instructions[i]["mnemonic"] == "return" or
                        (i + 1 < len(instructions) and instructions[i + 1]["address"] in jump_targets)
                ):
                    seq.append(f"{instructions[i]['mnemonic']}({instructions[i]['address']})")
                    i += 1

                # If we didn't advance, force an increment to avoid infinite loop
                if i == initial_i:
                    # Safety increment to prevent infinite loop
                    i += 1
                    # Skip writing this behavior if we couldn't collect any instructions
                    continue

                if seq:
                    # If we've reached the end of the sequence
                    if i < len(instructions):
                        next_cf_addr = instructions[i]["address"]
                        f.write(f"B({start_addr}) = {'.'.join(seq)}.B({next_cf_addr}),\n")
                    else:
                        # Last sequence, no following instruction
                        last_instr = instructions[i - 1]
                        # For the last instruction, we don't know what comes next
                        # Could add a special termination behavior or use addr+1
                        fallthrough_addr = f"{int(last_instr['address'], 16) + 1:x}"
                        f.write(f"B({start_addr}) = {'.'.join(seq)}.B({fallthrough_addr}),\n")

        # Add the definition for the dynamic behavior placeholder at the end
        f.write(f"\n# Dynamic (indirect) control flows:\n")
        f.write(f"{DYNAMIC_BEHAVIOR} = nop(DYNAMIC),\n")

        # Optionally, add detailed comments about each observed dynamic call/jump
        if dynamic_behaviors:
            f.write(f"\n# Observed dynamic control transfers:\n")
            for db in sorted(dynamic_behaviors):
                f.write(f"# {db}\n")

def disassemble_binary(binary_path, use_objdump=False):
    """
    Disassemble a binary file using angr or objdump.

    Args:
        binary_path: Path to the binary file
        use_objdump: If True, use objdump instead of angr

    Returns:
        String containing disassembled instructions
    """
    if use_objdump or not check_dependencies(quiet=True):
        if not is_objdump_available():
            print("ERROR: Neither angr nor objdump is available.")
            print("Please install either angr (Python package) or binutils (for objdump).")
            sys.exit(1)
        return disassemble_with_objdump(binary_path)
    else:
        return disassemble_with_angr(binary_path)


def disassemble_with_angr(binary_path):
    """Disassemble a binary file using angr."""
    import angr

    proj = angr.Project(binary_path, auto_load_libs=True)
    cfg = proj.analyses.CFGFast(resolve_indirect_jumps=True, normalize=True)

    lines = []
    for func in cfg.functions.values():
        for block in func.blocks:
            for insn in block.capstone.insns:
                # insn is a Capstone instruction object
                address_str = f"{insn.address:x}"
                mnemonic = insn.mnemonic
                op_str = insn.op_str
                lines.append(f"{address_str}: {mnemonic} {op_str}")

    # Sort lines by numeric address, just to keep everything in ascending order
    def addr_int(line):
        addr_hex = line.split(":")[0]
        return int(addr_hex, 16)

    lines.sort(key=addr_int)

    return "\n".join(lines)


def disassemble_with_objdump(binary_path):
    """Disassemble a binary file using objdump."""
    try:
        # Run objdump command to disassemble the binary
        cmd = ["objdump", "-d", binary_path]
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)

        # Parse objdump output and convert to our format
        lines = []
        for line in result.stdout.splitlines():
            line = line.strip()
            if not line or ':' not in line:
                continue

            # Check if line has the format "<address>: <bytes> <mnemonic> <operands>"
            parts = line.split(':')
            if len(parts) != 2:
                continue

            try:
                address_part = parts[0].strip()
                if not all(c in "0123456789abcdef" for c in address_part):
                    continue

                # Convert address to hexadecimal without 0x prefix
                address = int(address_part, 16)
                address_str = f"{address:x}"

                # Extract mnemonic and operands
                instruction_part = parts[1].strip()
                instruction_parts = instruction_part.split()

                # Skip byte codes and get to the instruction
                # Find where the instruction starts after the hex bytes
                instruction_idx = None
                for i, part in enumerate(instruction_parts):
                    if not all(c in "0123456789abcdef" for c in part):
                        instruction_idx = i
                        break

                if instruction_idx is not None:
                    instr_parts = instruction_parts[instruction_idx:]
                    if len(instr_parts) >= 1:
                        mnemonic = instr_parts[0].strip()
                        operands = " ".join(instr_parts[1:]).strip() if len(instr_parts) > 1 else ""
                        lines.append(f"{address_str}: {mnemonic} {operands}")
            except (ValueError, IndexError):
                continue

        return "\n".join(lines)
    except subprocess.CalledProcessError as e:
        print(f"Error running objdump: {e}")
        print(f"objdump stderr: {e.stderr}")
        return ""
    except FileNotFoundError:
        print("objdump not found. Please install binutils.")
        return ""


def get_angr_cfg(binary_path):
    """Get the CFG from angr."""
    if not check_dependencies(quiet=True):
        print("ERROR: angr is required for CFG export but not installed.")
        print("Please install angr in a virtual environment:")
        print("  python3 -m venv venv")
        print("  source venv/bin/activate")
        print("  pip install angr")
        sys.exit(1)

    import angr

    proj = angr.Project(binary_path, auto_load_libs=True)
    cfg = proj.analyses.CFGFast(resolve_indirect_jumps=True, normalize=True)

    # Create a simple wrapper to match the expected interface
    class CFGWrapper:
        def __init__(self, cfg, project):
            self.cfg = cfg
            self.project = project

    return CFGWrapper(cfg, proj)


def export_cfg_json(cfg_analysis, output_path, highlight_addrs=None):
    """
    Export CFG to JSON format.

    Args:
        cfg_analysis: The CFG analysis object
        output_path: Path to save the JSON file
        highlight_addrs: Optional set of addresses to highlight in the CFG

    Returns:
        Path to the output file or False on failure
    """
    # Ensure directory exists
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

    try:
        # Create set of highlighted addresses
        highlighted_addrs = set()
        if highlight_addrs:
            highlighted_addrs = set(highlight_addrs)

        cfg = cfg_analysis.cfg

        # JSON format export for CFG
        cfg_data = {
            "nodes": [],
            "edges": [],
            "metadata": {
                "total_nodes": len(cfg.graph.nodes()),
                "total_edges": len(cfg.graph.edges()),
                "highlighted_addresses": list(map(hex, highlighted_addrs))
            }
        }

        for node in cfg.graph.nodes():
            node_data = {
                "address": hex(node.addr),
                "instructions": [],
                "is_highlighted": False
            }

            try:
                block = cfg_analysis.project.factory.block(node.addr)

                for insn in block.capstone.insns:
                    is_highlighted = insn.address in highlighted_addrs
                    node_data["is_highlighted"] |= is_highlighted

                    node_data["instructions"].append({
                        "address": hex(insn.address),
                        "mnemonic": insn.mnemonic,
                        "operands": insn.op_str,
                        "bytes": insn.bytes.hex(),
                        "is_highlighted": is_highlighted,
                        "is_control_flow": insn.mnemonic in (
                            'call', 'jmp', 'je', 'jne', 'jg', 'jl', 'jge', 'jle', 'ja', 'jb', 'jae', 'jbe')
                    })
            except Exception as e:
                print(f"Error getting instructions for block at {hex(node.addr)}: {e}")

            cfg_data["nodes"].append(node_data)

        for src, dst in cfg.graph.edges():
            # Determine edge type
            edge_type = "sequential"
            try:
                src_block = cfg_analysis.project.factory.block(src.addr)
                last_insn = src_block.capstone.insns[-1]
                if last_insn.mnemonic == 'jmp':
                    edge_type = "unconditional_jump"
                elif last_insn.mnemonic.startswith('j'):
                    edge_type = "conditional_jump"
                elif last_insn.mnemonic == 'call':
                    edge_type = "call"
            except:
                pass

            cfg_data["edges"].append({
                "source": hex(src.addr),
                "target": hex(dst.addr),
                "type": edge_type
            })

        with open(output_path, 'w') as f:
            json.dump(cfg_data, f, indent=2)

        print(f"CFG exported to {output_path} in JSON format.")
        return output_path

    except Exception as e:
        print(f"Error exporting CFG: {e}")
        import traceback
        traceback.print_exc()
        return False


def generate_output_filename(prefix="behavior_algebra", extension="txt"):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"{prefix}_{timestamp}.{extension}"

def process_binary(binary_path, output_path=None, output_format="txt", use_objdump=False):
    """
    Process a binary file to generate behavior algebra and optionally export CFG in JSON.
    Always generates behavior algebra, and additionally generates the requested format if different.

    Args:
        binary_path: Path to the binary file
        output_path: Path to save the output file (optional)
        output_format: Format of the output (txt or json)
        use_objdump: If True, use objdump instead of angr for disassembly

    Returns:
        Path to the output file in the requested format
    """

    # Create export directory
    export_dir = "export"
    os.makedirs(export_dir, exist_ok=True)

    try:
        # Get the disassembly
        assembly_text = disassemble_binary(binary_path, use_objdump=use_objdump)

        # Always generate behavior algebra
        behavior_algebra_path = os.path.join(export_dir,
                                             generate_output_filename(prefix="behavior_algebra", extension="txt"))
        generate_behavior_algebra(assembly_text, behavior_algebra_path)
        print(f"Behavior algebra written to: {behavior_algebra_path}")

        # If the requested format is json, generate that too
        if output_format.lower() == "json":
            # For CFG export, we always need angr
            cfg_analysis = get_angr_cfg(binary_path)

            # Use specified output path or generate one
            cfg_path = output_path if output_path else os.path.join(export_dir, generate_output_filename(prefix="cfg",
                                                                                                         extension="json"))
            result = export_cfg_json(cfg_analysis, cfg_path)
            return result
        else:
            # If txt format was requested, we already created it
            return behavior_algebra_path if not output_path else output_path

    except Exception as e:
        print(f"ERROR: {str(e)}")
        import traceback
        traceback.print_exc()
        return None


def print_help():
    """Print detailed help information."""
    print("Behavior Algebra Disassembler")
    print("=============================")
    print("\nThis tool disassembles binary files and generates behavior algebra expressions.")
    print("\nUsage:")
    print("  python disassembler.py BINARY_PATH [options]")
    print("\nOptions:")
    print("  --output, -o PATH    Output file path")
    print("  --format, -f FORMAT  Output format (txt=behavior algebra, json=CFG in JSON)")
    print("  --objdump            Use objdump instead of angr for disassembly")
    print("  --highlight ADDRS    Comma-separated list of addresses to highlight in CFG")
    print("  --help-detailed      Show this help message")
    print("\nExamples:")
    print("  # Basic usage with angr")
    print("  python disassembler.py /path/to/binary")
    print("\n  # Use objdump")
    print("  python disassembler.py /path/to/binary --objdump")
    print("\n  # Export CFG in JSON format")
    print("  python disassembler.py /path/to/binary --format json")
    print("\n  # Create example binary and analyze it")
    print("  python disassembler.py example")
    print("\nNote:")
    print("  - CFG generation requires angr to be installed (objdump is not enough)")
    print("  - To install dependencies in a virtual environment:")
    print("    python3 -m venv venv")
    print("    source venv/bin/activate")
    print("    pip install angr")


def main():
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description="Disassemble binaries and generate behavior algebra")
    parser.add_argument("binary_path", help="Path to the binary file to disassemble or 'example' to create an example")
    parser.add_argument("--output", "-o", help="Output path for the result file")
    parser.add_argument("--format", "-f", choices=["txt", "json"], default="txt",
                        help="Output format (txt=behavior algebra, json=CFG in JSON)")
    parser.add_argument("--objdump", action="store_true", help="Use objdump instead of angr for disassembly")
    parser.add_argument("--highlight", help="Comma-separated list of addresses to highlight in CFG (hex format)")
    parser.add_argument("--help-detailed", action="store_true", help="Show detailed help information")

    # If no arguments, print help
    if len(sys.argv) == 1:
        parser.print_help()
        return 0

    # Parse arguments
    args = parser.parse_args()

    # Show detailed help if requested
    if args.help_detailed:
        print_help()
        return 0

    try:
        # Check if format is CFG-related and objdump was specified
        if args.format == "json" and args.objdump:
            print("WARNING: CFG export requires angr. Ignoring --objdump flag.")

        # Process highlight addresses if provided
        highlight_addrs = None
        if args.highlight:
            highlight_addrs = [int(addr, 16) for addr in args.highlight.split(",")]

        # Process the binary - always generates behavior algebra
        if args.format == "json":
            # First generate behavior algebra
            disassembly = disassemble_binary(args.binary_path, use_objdump=args.objdump)
            behavior_path = args.output.replace(".json", ".txt") if args.output else os.path.join("export",
                                                                                                  generate_output_filename())
            generate_behavior_algebra(disassembly, behavior_path)
            print(f"Behavior algebra written to: {behavior_path}")

            # Then generate CFG JSON
            output_file = export_cfg_json(get_angr_cfg(args.binary_path), args.output or None,
                                          highlight_addrs=highlight_addrs)
        else:
            # Process for txt format (behavior algebra)
            output_file = process_binary(args.binary_path, args.output, args.format, args.objdump)

        if output_file:
            print(f"SUCCESS: Output saved to {output_file}")
            return 0
        else:
            print("ERROR: Failed to process binary")
            return 1
    except Exception as e:
        print(f"Error processing binary: {e}", file=sys.stderr)
        import traceback
        traceback.print_exc()
        return 1

if __name__ == "__main__":
    sys.exit(main())