"""
Minimal test to identify why register values might be null
"""

from modeling import SymbolicValue
from symbolic_environment import SymbolicEnvironment, EnhancedSymbolicEnvironment


def test_register_values():
    """Test if register values become null during basic operations"""

    # Create environment
    env = SymbolicEnvironment()

    # Check initial register values
    print("Initial register values:")
    for reg_name in ['RAX', 'RBX', 'RCX', 'RDX']:
        reg = env.get_register(reg_name)
        print(f"  {reg_name}: {reg.value if reg else 'NULL'}")

    # Set some register values
    print("\nSetting register values...")
    env.set_register('RAX', 42)
    env.set_register('RBX', 123)

    # Check values after setting
    print("Register values after set_register:")
    for reg_name in ['RAX', 'RBX', 'RCX', 'RDX']:
        reg = env.get_register(reg_name)
        print(f"  {reg_name}: {reg.value if reg else 'NULL'}")

    # Test creating a snapshot
    print("\nCreating a snapshot...")

    # Simple snapshot implementation
    class SimpleSnapshot:
        def __init__(self, env):
            self.registers = {}
            for reg_name, sym_val in env.registers.items():
                if sym_val is None:
                    print(f"  WARNING: {reg_name} is None in environment!")
                    continue

                self.registers[reg_name] = {
                    'value': sym_val.value,
                    'symbolic': sym_val.symbolic,
                    'size': sym_val.size,
                    'name': sym_val.name
                }

    snapshot = SimpleSnapshot(env)

    # Check values in snapshot
    print("Register values in snapshot:")
    for reg_name in ['RAX', 'RBX', 'RCX', 'RDX']:
        if reg_name in snapshot.registers:
            reg_info = snapshot.registers[reg_name]
            print(f"  {reg_name}: {reg_info.get('value')}")
        else:
            print(f"  {reg_name}: NOT IN SNAPSHOT")

    # Test a basic operation
    print("\nTesting basic operation (move RBX to RAX)...")
    try:
        env.sym_copy_reg_reg('RAX', 'RBX')
        print("  Operation completed")
    except Exception as e:
        print(f"  ERROR: {e}")

    # Check values after operation
    print("Register values after operation:")
    for reg_name in ['RAX', 'RBX', 'RCX', 'RDX']:
        reg = env.get_register(reg_name)
        print(f"  {reg_name}: {reg.value if reg else 'NULL'}")

    # Create a second snapshot
    print("\nCreating a second snapshot...")
    snapshot2 = SimpleSnapshot(env)

    # Check values in second snapshot
    print("Register values in second snapshot:")
    for reg_name in ['RAX', 'RBX', 'RCX', 'RDX']:
        if reg_name in snapshot2.registers:
            reg_info = snapshot2.registers[reg_name]
            print(f"  {reg_name}: {reg_info.get('value')}")
        else:
            print(f"  {reg_name}: NOT IN SNAPSHOT")

    # Test JSON serialization
    print("\nTesting JSON serialization...")
    import json

    # Create a simplified structure for JSON
    data = {
        'registers': {}
    }

    for reg_name, reg_info in snapshot2.registers.items():
        if reg_name in ['RAX', 'RBX', 'RCX', 'RDX']:
            value = reg_info.get('value')

            if value is None:
                print(f"  WARNING: {reg_name} has None value in snapshot!")
                # Set a default value for serialization
                value = 0

            try:
                # Try to format as hex to catch non-integer values
                data['registers'][reg_name] = f"0x{value:x}"
            except TypeError:
                print(f"  ERROR: {reg_name} value ({value}) is not a number!")
                data['registers'][reg_name] = f"error({value})"

    try:
        # Try to serialize
        json_data = json.dumps(data, indent=2)
        print("  Serialization successful!")
    except Exception as e:
        print(f"  ERROR serializing: {e}")


if __name__ == "__main__":
    test_register_values()