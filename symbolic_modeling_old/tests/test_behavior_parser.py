# test_behavior_parser.py
"""
Unit tests for behavior_parser.
"""
import unittest
from behavior_parser import parse_behavior_file, extract_sequences_from_text

class TestBehaviorParser(unittest.TestCase):
    def test_parse_behavior_file(self):
        # Create a temporary file
        import tempfile
        with tempfile.NamedTemporaryFile(mode='w+', delete=True) as f:
            f.write('MOV RAX, 1\nconstraint: RAX > 0\nADD RAX, RBX\n')
            f.flush()
            instrs, constraints = parse_behavior_file(f.name)
            self.assertEqual(instrs, ['MOV RAX, 1', 'ADD RAX, RBX'])
            self.assertEqual(constraints, ['RAX > 0'])

    def test_extract_sequences_from_text(self):
        text = 'MOV RAX, 1\nconstraint: RAX > 0\nADD RAX, RBX\n'
        instrs, constraints = extract_sequences_from_text(text)
        self.assertEqual(instrs, ['MOV RAX, 1', 'ADD RAX, RBX'])
        self.assertEqual(constraints, ['RAX > 0'])

if __name__ == "__main__":
    unittest.main()
