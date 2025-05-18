from symbolic_environment import SymbolicEnvironment
from solver_integration import SMTSolver
from trace_recorder import TraceRecord
from constraint_generator import generate_constraint, parse_operand
from postconditions import POSTCONDITION_MAP

"""
Symbolic execution engine for x86 instructions
"""

from symbolic_environment import SymbolicEnvironment
from solver_integration import SMTSolver
from trace_recorder import TraceRecord
from constraint_generator import generate_constraint, parse_operand
from postconditions import POSTCONDITION_MAP


def apply_postcondition(instruction, semantics, env):
    """
    Apply the postcondition for an instruction based on the semantics file

    Args:
        instruction: Instruction object
        semantics: InstructionSemantics object
        env: Symbolic environment

    Returns:
        bool: True if postcondition was applied, False otherwise
    """
    # Check if semantics has a postcondition
    if not semantics.postcondition:
        return False

    try:
        # Parse the postcondition to extract the function name and arguments
        postcondition = semantics.postcondition.strip()

        # Check for function call format like "DST = sym_copy(SRC,DST)"
        if '=' in postcondition:
            # Split the assignment
            dest, func_call = postcondition.split('=', 1)
            dest = dest.strip()
            func_call = func_call.strip()
        else:
            # No assignment, just a function call
            func_call = postcondition

        # Extract function name and arguments
        if '(' in func_call and ')' in func_call:
            func_name = func_call[:func_call.index('(')].strip()
            args_str = func_call[func_call.index('(') + 1:func_call.rindex(')')].strip()
            arg_names = [arg.strip() for arg in args_str.split(',')] if args_str else []

            # Look up the function in POSTCONDITION_MAP
            if func_name in POSTCONDITION_MAP:
                postcondition_func = POSTCONDITION_MAP[func_name]

                # Map semantic parameter names to actual instruction operands
                if func_name == 'sym_copy' and len(arg_names) == 2 and len(instruction.operands) >= 2:
                    # Handle sym_copy specially since it's commonly used
                    # Usually called as sym_copy(SRC,DST) in semantics but needs (env, dest, source) in code
                    postcondition_func(env, instruction.operands[0], instruction.operands[1])
                    return True
                elif len(instruction.operands) == 0:
                    # No operands, just call the function with env
                    postcondition_func(env)
                    return True
                elif len(instruction.operands) == 1:
                    # One operand
                    postcondition_func(env, instruction.operands[0])
                    return True
                elif len(instruction.operands) >= 2:
                    # Two or more operands
                    postcondition_func(env, instruction.operands[0], instruction.operands[1])
                    return True
    except Exception as e:
        print(f"Error applying postcondition for {instruction.opcode}: {e}")

    return False


def execute_trace(trace, semantics, solver_type='z3', verbose=False, use_symbolic_hex=True):
    """
    Symbolically execute a trace of instructions

    Args:
        trace: List of Instruction objects
        semantics: Dictionary mapping opcodes to InstructionSemantics
        solver_type: Type of SMT solver to use ('z3' or 'cvc5')
        verbose: Enable verbose output
        use_symbolic_hex: Use symbolic hex representation for output

    Returns:
        TraceRecord: Record of execution or None if trace is UNSAT
    """
    # Initialize symbolic environment
    env = SymbolicEnvironment()

    # Initialize solver
    solver = SMTSolver(solver_type)

    # Initialize trace record
    trace_record = TraceRecord()

    if verbose:
        print("Initial symbolic state:")
        if use_symbolic_hex:
            print(env.get_symbolic_hex_str())
        else:
            print(env.get_state_str())

    # Process each instruction
    for instruction in trace:
        if verbose:
            print(f"\nProcessing instruction: {instruction}")

        # Get semantics for this instruction - try multiple case variations
        opcode = instruction.opcode.lower()
        instr_sem = semantics.get(opcode) or semantics.get(opcode.upper()) or semantics.get(opcode.capitalize())

        if not instr_sem:
            print(f"Warning: No semantics found for {instruction.opcode}")
            # Use default semantics (precondition = 1)
            continue

        # Generate constraint from precondition
        constraint = generate_constraint(instruction, instr_sem, env)

        # Add to environment
        env.add_constraint(constraint)

        # Check satisfiability
        if env.is_satisfiable(solver):
            if verbose:
                print(f"Constraint is SAT")

            # Record SAT state
            trace_record.add_step(instruction, env)

            # Apply postcondition
            post_applied = apply_postcondition(instruction, instr_sem, env)
            if verbose and post_applied:
                print(f"Applied postcondition for {instruction.opcode}")

            # Continue to next instruction with updated environment
        else:
            # UNSAT trace
            print(f"UNSAT at instruction: {instruction}")
            return None

    # Entire trace is SAT
    trace_record.set_final_state(env)
    if verbose:
        print("\nFinal symbolic state:")
        if use_symbolic_hex:
            print(env.get_symbolic_hex_str())
        else:
            print(env.get_state_str())

    return trace_record