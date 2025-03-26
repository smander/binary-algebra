import sys
import subprocess
import os
import datetime
import argparse


def install(package):
    """Install a Python package if not already installed."""
    subprocess.check_call([sys.executable, "-m", "pip", "install", package])

def check_dependencies():
    """Check and install required dependencies."""
    # List required packages
    required_packages = ["angr"]  # claripy is bundled with angr

    # Check and install if missing
    for package in required_packages:
        try:
            __import__(package)
        except ImportError:
            print(f"{package} not found. Installing...")
            install(package)


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
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

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


def disassemble_binary(binary_path):
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


def generate_output_filename():
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"behavior_algebra_{timestamp}.txt"


def process_binary(binary_path, output_path=None):

    check_dependencies()

    # If no output path is specified, create one
    if output_path is None:
        # Create the export directory path
        export_dir = "export"
        os.makedirs(export_dir, exist_ok=True)

        # Generate a new filename
        filename = generate_output_filename()
        output_path = os.path.join(export_dir, filename)
    else:
        # Ensure the directory for output_path exists
        os.makedirs(os.path.dirname(output_path or '.'), exist_ok=True)

    try:
        assembly_text = disassemble_binary(binary_path)
        generate_behavior_algebra(assembly_text, output_path)
        print(f"Behavior algebra written to: {output_path}")
        return output_path
    except Exception as e:
        print(f"ERROR: {str(e)}")
        raise


def main():
    """Command-line entry point."""
    parser = argparse.ArgumentParser(description="Disassemble binaries and generate behavior algebra")
    parser.add_argument("binary_path", help="Path to the binary file to disassemble")
    parser.add_argument("--output", "-o", help="Output path for the behavior algebra file")

    args = parser.parse_args()

    try:
        output_file = process_binary(args.binary_path, args.output)
        return 0
    except Exception as e:
        print(f"Error processing binary: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())