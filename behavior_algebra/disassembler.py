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


def generate_behavior_algebra(input_data, output_path):
    instructions = parse_instructions(input_data)

    # Ensure directory exists
    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)

    with open(output_path, "w") as f:
        i = 0
        while i < len(instructions):
            current = instructions[i]
            addr = current["address"]
            mnem = current["mnemonic"]

            # Skip return instructions
            if mnem == "return":
                i += 1
                continue

            # Calculate next valid instruction (skip returns)
            next_idx = i + 1
            while next_idx < len(instructions) and instructions[next_idx]["mnemonic"] == "return":
                next_idx += 1

            next_instr = instructions[next_idx] if next_idx < len(instructions) else None
            addr_next = next_instr["address"] if next_instr else None

            # Process call instructions
            if mnem == "call":
                destination = current["operands"]
                f.write(f"B({addr}) = B({destination}); B({addr_next}),\n")
                i += 1

            # Process jump instructions (mnemonics starting with 'j')
            elif mnem.startswith("j"):
                destination = current["operands"]
                if next_instr:
                    f.write(f"B({addr}) = {mnem}({addr}). B({destination}) + !{mnem}({addr}).B({addr_next}),\n")
                else:
                    # If this is the last instruction, use addr+1 as fallthrough
                    fallthrough_addr = f"{int(addr, 16) + 1:x}"
                    f.write(f"B({addr}) = {mnem}({addr}). B({destination}) + !{mnem}({addr}).B({fallthrough_addr}),\n")
                i += 1

            # Non-control flow instructions
            else:
                start_addr = addr
                seq = []
                while i < len(instructions) and not (
                        instructions[i]["mnemonic"] == "call" or
                        instructions[i]["mnemonic"].startswith("j") or
                        instructions[i]["mnemonic"] == "return"
                ):
                    seq.append(f"{instructions[i]['mnemonic']}({instructions[i]['address']})")
                    i += 1

                if seq:
                    # Next CF instruction
                    if i < len(instructions):
                        next_cf_addr = instructions[i]["address"]
                        f.write(f"B({start_addr}) = {'.'.join(seq)}.B({next_cf_addr}),\n")
                    else:
                        # Last sequence, no following instruction
                        last_instr = instructions[i - 1]
                        fallthrough_addr = f"{int(last_instr['address'], 16) + 1:x}"
                        f.write(f"B({start_addr}) = {'.'.join(seq)}.B({fallthrough_addr}),\n")


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


def create_example_binary(source_file="example.c", binary_file="example"):
    """Create a simple example binary for testing."""
    with open(source_file, "w") as f:
        f.write("""
        #include <stdio.h>

        int factorial(int n) {
            if (n <= 1) return 1;
            return n * factorial(n-1);
        }

        int main() {
            int n = 5;
            printf("Factorial of %d is %d\\n", n, factorial(n));
            return 0;
        }
        """)

    try:
        subprocess.run(["gcc", "-o", binary_file, source_file], check=True)
        print(f"Created example binary: {binary_file}")
        return binary_file
    except subprocess.CalledProcessError:
        print("Failed to compile example binary. Make sure gcc is installed.")
        return None
    except FileNotFoundError:
        print("gcc not found. Please install a C compiler.")
        return None


def process_binary(binary_path, output_path=None, output_format="txt", use_objdump=False):
    """
    Process a binary file to generate behavior algebra or export CFG in JSON.

    Args:
        binary_path: Path to the binary file
        output_path: Path to save the output file (optional)
        output_format: Format of the output (txt or json)
        use_objdump: If True, use objdump instead of angr for disassembly

    Returns:
        Path to the output file
    """
    # Create example binary if requested
    if binary_path.lower() == "example":
        created_binary = create_example_binary()
        if created_binary:
            binary_path = created_binary
        else:
            return None

    # If no output path is specified, create one
    if output_path is None:
        # Create the export directory path
        export_dir = "export"
        os.makedirs(export_dir, exist_ok=True)

        # Generate a new filename
        extension = "json" if output_format.lower() == "json" else "txt"
        prefix = "cfg" if output_format.lower() == "json" else "behavior_algebra"
        filename = generate_output_filename(prefix=prefix, extension=extension)
        output_path = os.path.join(export_dir, filename)

    try:
        # Special case for CFG in JSON format which needs angr
        if output_format.lower() == "json":
            # For CFG export, we always need angr
            cfg_analysis = get_angr_cfg(binary_path)

            # Export the CFG in JSON format
            return export_cfg_json(cfg_analysis, output_path)

        # Normal disassembly and behavior algebra generation
        assembly_text = disassemble_binary(binary_path, use_objdump=use_objdump)
        generate_behavior_algebra(assembly_text, output_path)

        print(f"Behavior algebra written to: {output_path}")
        return output_path
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

        # Process the binary
        if args.format == "json":
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