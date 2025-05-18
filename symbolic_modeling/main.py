#!/usr/bin/env python3
import argparse
import sys
import subprocess
from instruction_parser import parse_trace_file
from semantics_parser import parse_semantics_file
from symbolic_execution import execute_trace
from trace_recorder import save_trace


def check_and_install():
    """Check if z3-solver is installed and install it if necessary"""
    # First check if z3 is already installed
    try:
        # Attempt to import z3 module
        import z3
        print("Z3 solver is already installed.")
        return True
    except ImportError:
        print("Z3 solver not found. Attempting to install...")
        try:
            # Try to install z3-solver using pip
            subprocess.check_call([sys.executable, "-m", "pip", "install", "z3-solver"])

            # Try to import again to verify installation
            try:
                import z3
                print("Z3 solver installed successfully!")
                return True
            except ImportError:
                print("Z3 installation appeared to succeed but module still cannot be imported.")
                print("Please try installing manually with: pip install z3-solver")
                return False

        except subprocess.CalledProcessError:
            print("Failed to install Z3 solver.")
            print("Please install manually with: pip install z3-solver")
            return False


# Check and install z3 before importing other modules
if not check_and_install():
    sys.exit(1)


def main():
    parser = argparse.ArgumentParser(description='Symbolic Modeling of Intel x86 Instructions')
    parser.add_argument('trace_file', help='Path to the trace file')
    parser.add_argument('semantics_file', help='Path to the semantics file')
    parser.add_argument('--output', default='trace_result.json', help='Output file for the SAT trace')
    parser.add_argument('--solver', default='z3', choices=['z3', 'cvc5'], help='SMT solver to use')
    parser.add_argument('--verbose', '-v', action='store_true', help='Enable verbose output')
    parser.add_argument('--symbolic-hex', '-s', action='store_true', help='Use symbolic hex representation for output')
    parser.add_argument('--test', action='store_true', help='Run tests instead of processing files')
    args = parser.parse_args()

    try:
        # Verify Z3 is actually importable
        try:
            import z3
        except ImportError:
            print("ERROR: Z3 solver could not be imported despite installation check.")
            print("Please ensure Z3 is properly installed with: pip install z3-solver")
            return 1

        # Parse input files
        print(f"Parsing trace file: {args.trace_file}")
        trace = parse_trace_file(args.trace_file)
        print(f"Found {len(trace)} instructions")

        print(f"Parsing semantics file: {args.semantics_file}")
        semantics = parse_semantics_file(args.semantics_file)
        print(f"Loaded semantics for {len(semantics)} instructions")

        # Execute trace symbolically
        print("Starting symbolic execution...")
        trace_record = execute_trace(trace, semantics, args.solver, verbose=args.verbose,
                                     use_symbolic_hex=args.symbolic_hex)

        # Save results
        if trace_record:
            save_trace(trace_record, args.output)
            print(f"SAT trace saved to {args.output}")
            return 0
        else:
            print("Trace is UNSAT - no feasible execution")
            return 1
    except ModuleNotFoundError as mnf:
        if 'z3' in str(mnf):
            print("ERROR: Z3 solver module not found during execution.")
            print("This may be due to installation issues or Python path problems.")
            print("Try installing Z3 manually with: pip install z3-solver")
        else:
            print(f"ERROR: Module not found - {mnf}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 2


if __name__ == "__main__":
    sys.exit(main())