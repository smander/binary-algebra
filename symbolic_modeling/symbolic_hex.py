import re

def parse_symbolic_hex(sym_hex_str: str):
    """
    Returns:
    - total_expression: text representation of a sum in the form:
        X = <term1> + <term2> + ... + <termN>
    - constraints: list of constraints for variables x_i (e.g., "0 <= x1 < 16^2")

    sym_hex_str: string like "0x12$$8e$$7$$" or "12$fe$"
    """
    # 1. Remove possible "0x" prefix
    if sym_hex_str.lower().startswith("0x"):
        sym_hex_str = sym_hex_str[2:]

    # 2. Split into fragments:
    #    - "concrete" hexadecimal (without $)
    #    - "symbolic" (one or more consecutive $)
    # Using regular expression:
    #    [0-9a-fA-F]+  - sequence of regular hexadecimal digits
    #    \$+          - sequence of $ symbols
    tokens = re.findall(r'[0-9a-fA-F]+|\$+', sym_hex_str)

    # 3. Count the total number of *nibbles* (4-bit digits)
    total_nibbles = 0
    for t in tokens:
        if '$' in t:
            # m times '$' -> m nibbles
            total_nibbles += len(t)
        else:
            # regular hexadecimal fragment -> string length in nibbles
            total_nibbles += len(t)

    # 4. Form expression X as a sum
    expression_parts = []
    constraints = []
    var_index = 1  # Counter for x1, x2, x3, ...

    current_pos = 0  # count how many nibbles already "passed" left to right

    for t in tokens:
        length = len(t)  # number of nibbles (or $ symbols)

        # Calculate the position power for this token
        power = total_nibbles - (current_pos + length)

        if '$' in t:
            # Symbolic fragment of length m = length
            var_name = f"x{var_index}"
            var_index += 1

            # Add to expression: var_name * (16^power)
            part_str = f"{var_name}*(16^{power})" if power > 0 else var_name
            expression_parts.append(part_str)

            # Form constraint 0 <= var_name < 16^m
            constraints.append(f"0 <= {var_name} < 16^{length}")

        else:
            # Concrete hexadecimal fragment
            numeric_val_str = f"0x{t}"

            # Add this term with appropriate power of 16
            if power > 0:
                part_str = f"{numeric_val_str}*(16^{power})"
            else:
                part_str = numeric_val_str

            expression_parts.append(part_str)

        current_pos += length

    # 5. Form final string for X
    total_expression = " + ".join(expression_parts)
    total_expression = "X = " + total_expression

    return total_expression, constraints