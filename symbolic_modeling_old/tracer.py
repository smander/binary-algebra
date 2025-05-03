# tracer.py
"""
Symbolic execution tracer for tracking and logging execution flow and environment states.
"""
from symbolic_environment import EnhancedSymbolicEnvironment
from snapshot import SymbolicStateSnapshot

class SymbolicExecutionTracer:
    """Tracks the symbolic execution and stores snapshots at each step.
    
    Args:
        env (EnhancedSymbolicEnvironment): The symbolic execution environment to trace.
    """
    def __init__(self, env: EnhancedSymbolicEnvironment):
        self.env = env
        self.snapshots = []
        self.instructions = []

    def trace_instruction(self, instruction, step=None):
        """Executes and records a single instruction, saving a snapshot.
        
        Args:
            instruction (str): The instruction to execute and trace.
            step (int, optional): The step index.
        Returns:
            SymbolicStateSnapshot: The snapshot after executing the instruction.
        """
        # Optionally execute the instruction in the environment
        if hasattr(self.env, 'execute_instruction'):
            self.env.execute_instruction(instruction)
        # Take a snapshot after execution
        snapshot = SymbolicStateSnapshot(self.env, instruction=instruction, step=step)
        self.snapshots.append(snapshot)
        self.instructions.append(instruction)
        return snapshot

    def get_snapshots(self):
        """Return all collected snapshots."""
        return self.snapshots

    def print_trace(self, limit=10):
        """Print the first `limit` snapshots in a readable format."""
        for i, snapshot in enumerate(self.snapshots[:limit]):
            print(f"--- Step {i} ---")
            print(snapshot)
            print()
        if len(self.snapshots) > limit:
            print(f"... {len(self.snapshots) - limit} more steps not shown ...")
