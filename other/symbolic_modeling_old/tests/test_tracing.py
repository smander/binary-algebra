import os
import pytest
from symbolic_modeling.tracing import SymbolicExecutionTracer, trace_specific_sequence

def test_behavior_algebra_trace():
    # Path to the test behavior algebra file
    test_file = os.path.join(os.path.dirname(__file__), '../../behavior_algebra/behavior_algebra_20250326_194917.txt')
    address = None  # Set to a valid address if needed
    tracer = trace_specific_sequence(test_file, address)
    # Basic assertions
    assert tracer is not None
    assert hasattr(tracer, 'snapshots')
    assert len(tracer.snapshots) > 0
    # Check that all registers in all snapshots have valid values
    for snap in tracer.snapshots:
        for reg, info in snap.registers.items():
            assert info['symbolic'] or info['value'] is not None
