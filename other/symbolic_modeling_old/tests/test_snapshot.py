# test_snapshot.py
"""
Unit tests for SymbolicStateSnapshot.
"""
import unittest
from symbolic_environment import EnhancedSymbolicEnvironment
from snapshot import SymbolicStateSnapshot

class TestSymbolicStateSnapshot(unittest.TestCase):
    def test_snapshot_registers_and_flags(self):
        env = EnhancedSymbolicEnvironment()
        env.set_register('RAX', 42)
        env.set_flag('ZF', 1)
        snap = SymbolicStateSnapshot(env, instruction='MOV RAX, 42', step=0)
        self.assertEqual(snap.registers['RAX'].value, 42)
        self.assertEqual(snap.flags['ZF'].value, 1)
        self.assertEqual(snap.step, 0)
        self.assertEqual(snap.instruction, 'MOV RAX, 42')

    def test_snapshot_memory(self):
        env = EnhancedSymbolicEnvironment()
        env.set_memory(0x1000, 0x55)
        snap = SymbolicStateSnapshot(env)
        self.assertIn('4096', snap.memory)  # 0x1000 == 4096
        self.assertEqual(snap.memory['4096'].value, 0x55)

if __name__ == "__main__":
    unittest.main()
