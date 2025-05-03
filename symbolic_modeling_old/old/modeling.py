import re

class SymbolicValue:

    def __init__(self, value=None, symbolic=True, size=1, name=None):
        self.value = value  # Concrete value, if available
        self.symbolic = symbolic  # True if value is symbolic
        self.size = size  # Size in bytes
        self.name = name  # Symbolic variable name

    def __str__(self):
        if not self.symbolic and self.value is not None:
            return str(self.value)
        return f"${self.name}" if self.name else "$sym"


def parse_template(template_str):
    """Parse template string to extract parts and constraints"""
    template_parts = []
    constraints = {}

    # Split by lines and semicolons
    lines = template_str.strip().split('\n')
    for line in lines:
        line = line.strip()
        if not line:
            continue

        if ';' in line:
            # Multiple parts on one line
            parts = line.split(';')
            for part in parts:
                part = part.strip()
                if not part:
                    continue

                if ':' in part:
                    # This is a constraint
                    label, constraint = part.split(':', 1)
                    label = label.strip()
                    constraint = constraint.strip()
                    constraints[label] = constraint
                else:
                    # This is a template part
                    template_parts.append(part)
        elif ':' in line:
            # This is a constraint
            label, constraint = line.split(':', 1)
            label = label.strip()
            constraint = constraint.strip()
            constraints[label] = constraint
        else:
            # This is a template part
            template_parts.append(line)

    return template_parts, constraints


def check_constraint(env, constraint):
    """Check if a constraint is satisfiable"""
    # Parse memory constraints (e.g., "Mem(i) != 0")
    if "Mem(" in constraint and ")" in constraint:
        index_str = constraint[constraint.find("(") + 1:constraint.find(")")]

        # Extract operator and value
        if "!=" in constraint:
            op = "!="
            parts = constraint.split("!=", 1)
        elif "==" in constraint:
            op = "=="
            parts = constraint.split("==", 1)
        else:
            return True  # Unknown operator

        value_str = parts[1].strip()
        try:
            value = int(value_str)
        except:
            return True  # Non-numeric value

        # Handle symbolic or concrete index
        if index_str == 'i':
            # Symbolic index
            env.constraints.append(constraint)
            return True
        else:
            try:
                addr = int(index_str)
                # Check memory at address
                mem_val = env.get_memory(addr)

                if not mem_val.symbolic:
                    # Concrete memory value
                    if op == "!=":
                        return mem_val.value != value
                    elif op == "==":
                        return mem_val.value == value

                # Memory is symbolic - add constraint
                env.constraints.append(constraint)
                return True
            except:
                return True  # Invalid index

    # Parse flag constraints (e.g., "FLAGS[0] == 0")
    elif "FLAGS[" in constraint and "]" in constraint:
        index_str = constraint[constraint.find("[") + 1:constraint.find("]")]

        # Extract operator and value
        if "!=" in constraint:
            op = "!="
            parts = constraint.split("!=", 1)
        elif "==" in constraint:
            op = "=="
            parts = constraint.split("==", 1)
        else:
            return True  # Unknown operator

        value_str = parts[1].strip()
        try:
            value = int(value_str)
        except:
            return True  # Non-numeric value

        try:
            index = int(index_str)
            # Map index to flag name
            flag_names = ['CF', 'PF', 'AF', 'ZF', 'SF', 'OF']

            if index < len(flag_names):
                flag_name = flag_names[index]
                flag_val = env.get_flag(flag_name)

                if flag_val and not flag_val.symbolic:
                    # Concrete flag value
                    if op == "!=":
                        return flag_val.value != value
                    elif op == "==":
                        return flag_val.value == value

            # Flag is symbolic or invalid index - add constraint
            env.constraints.append(constraint)
            return True
        except:
            return True  # Invalid index

    return True  # Unknown constraint format


def execute_instruction(env, instruction):
    """Execute instruction symbolically"""
    mnemonic = instruction['name'].lower()

    if mnemonic == 'add':
        print("Performing symbolic addition")
        env.sym_add_reg_reg('RAX', 'RBX')
    elif mnemonic == 'sub':
        print("Performing symbolic subtraction")
        env.sym_sub_reg_reg('RAX', 'RBX')
    elif mnemonic == 'imul' or mnemonic == 'imul':
        print("Performing symbolic multiplication")
        env.sym_mul_reg_reg('RAX', 'RBX')
    elif mnemonic == 'div' or mnemonic == 'idiv':
        print("Performing symbolic division")
        env.sym_div_reg_reg('RAX', 'RBX')
    elif mnemonic == 'mov':
        print("Performing symbolic move")
        env.sym_copy_reg_reg('RAX', 'RBX')
    elif mnemonic == 'xor':
        print("Simulating XOR (setting register to 0)")
        env.set_register('RAX', 0)
    else:
        print(f"Skipping unimplemented operation: {mnemonic}")


    return env


def SymModStep(env, instruction):
    """Perform one step of symbolic modeling"""
    return execute_instruction(env, instruction)


def SymMod(trace, template):
    """Symbolic modeling of instruction trace according to template"""
    # Parse template and constraints
    template_parts, constraints = parse_template(template)

    # Initialize symbolic environment
    env = SymbolicEnvironment()

    # Process each instruction in trace
    for i, instruction in enumerate(trace):
        # Check if instruction is part of template
        for part in template_parts:
            if '.' in part:
                label, _ = part.split('.')
                if label.startswith('a') and label[1:].isdigit():
                    template_index = int(label[1:]) - 1  # Convert a1 to index 0

                    if i == template_index and label in constraints:
                        # Apply constraint
                        constraint = constraints[label]
                        if not check_constraint(env, constraint):
                            print(f"Constraint not satisfiable: {constraint}")
                            return None

        # Execute instruction symbolically
        env = SymModStep(env, instruction)

    return env


def parse_behavior_file(content):
    """
    A simple parser that extracts instructions from the behavior file.
    It searches for patterns like: mnemonic(address)
    and returns a list of instruction dictionaries.
    """
    pattern = r'(\w+)\((0x[0-9A-Fa-f]+|\d+)\)'
    instructions = []
    for match in re.finditer(pattern, content):
        name, address = match.groups()
        # Skip labels or non-instruction symbols (e.g. "B")
        if name.upper() == "B":
            continue
        instructions.append({'name': name, 'address': address})
    return instructions


def main():
    """Main function to test hybrid symbolic modeling using files"""

    # Read the behavior (trace) file
    try:
        with open('behavior_algebra_20250326_194917.txt', 'r') as f:
            behavior_content = f.read()
    except IOError as e:
        print("Error reading behavior file:", e)
        return

    # Read the template file
    try:
        with open('template.txt', 'r') as f:
            template = f.read()
    except IOError as e:
        print("Error reading template file:", e)
        return

    # Parse the behavior file into a trace (list of instruction dictionaries)
    test_trace = parse_behavior_file(behavior_content)
    if not test_trace:
        print("No valid instructions found in behavior file.")
        return

    print("Running SymMod with instructions from file...")
    final_env = SymMod(test_trace, template)

    if final_env:
        print("Symbolic modeling completed successfully!")
        final_env.print_state()
    else:
        print("Symbolic modeling failed - constraints not satisfiable.")


if __name__ == "__main__":
    main()
