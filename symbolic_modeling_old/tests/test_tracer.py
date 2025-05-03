# test_tracer.py
"""
Unit tests for SymbolicExecutionTracer.
"""
import unittest
from symbolic_environment import EnhancedSymbolicEnvironment
from tracer import SymbolicExecutionTracer

class TestSymbolicExecutionTracer(unittest.TestCase):
    def test_trace_instruction(self):
        env = EnhancedSymbolicEnvironment()
        tracer = SymbolicExecutionTracer(env)
        env.set_register('RAX', 1)
        tracer.trace_instruction('INC RAX', step=0)
        self.assertEqual(len(tracer.snapshots), 1)
        self.assertEqual(tracer.snapshots[0].step, 0)
        self.assertIn('RAX', tracer.snapshots[0].registers)

if __name__ == "__main__":
    unittest.main()
