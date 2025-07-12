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
import re


def execute_bin_operation(expression, env):
    """
    Dynamically execute any BIN_* operation from the expression
    
    Args:
        expression: String like "BIN_COPY(SRC,DST)" or "BIN_ADD(DST,SRC)"
        env: Symbolic environment
    """
    # Find BIN_* function call using regex
    match = re.search(r'(BIN_\w+)\s*\(\s*([^)]+)\s*\)', expression)
    if not match:
        return
        
    func_name = match.group(1)
    args_str = match.group(2)
    args = [arg.strip() for arg in args_str.split(',')]
    
    # Dynamically import and call the function
    try:
        import postconditions
        if hasattr(postconditions, func_name):
            bin_func = getattr(postconditions, func_name)
            if len(args) >= 2:
                bin_func(env, args[0], args[1])
            elif len(args) == 1:
                bin_func(env, args[0])
    except Exception as e:
        print(f"Error executing {func_name}: {e}")


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
        print(f"No postcondition for {instruction.opcode}")
        return False

    try:
        # Parse and execute the postcondition from semantics file
        postcondition = semantics.postcondition.strip()
        
        if not postcondition:
            return True  # Empty postcondition is valid (like for jumps)
            
        # Handle assignment: DST = BIN_COPY(SRC,DST)
        if '=' in postcondition:
            left, right = postcondition.split('=', 1)
            dest = left.strip()
            expression = right.strip()
            
            # Map semantic operands to actual instruction operands
            operand_map = {}
            if semantics.operands and len(instruction.operands) >= len(semantics.operands):
                for i, sem_op in enumerate(semantics.operands):
                    operand_map[sem_op] = instruction.operands[i]
            
            # Replace semantic operands with actual operands
            for sem_op, actual_op in operand_map.items():
                dest = dest.replace(sem_op, actual_op)
                expression = expression.replace(sem_op, actual_op)
            
            # Execute the operation dynamically
            execute_bin_operation(expression, env)
        
        return True
    except Exception as e:
        print(f"Error applying postcondition for {instruction.opcode}: {e}")
        import traceback
        traceback.print_exc()
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
            if verbose:
                if post_applied:
                    print(f"Applied postcondition for {instruction.opcode}")
                else:
                    print(f"No postcondition applied for {instruction.opcode}")

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