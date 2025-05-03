import json
from datetime import datetime


class TraceRecord:
    def __init__(self):
        self.trace_info = {
            "timestamp": datetime.now().isoformat(),
            "steps": [],
            "final_state": None
        }

    def add_step(self, instruction, env):
        """
        Record instruction and environment state

        Args:
            instruction: Instruction object
            env: Symbolic environment
        """
        step = {
            "address": instruction.address,
            "instruction": str(instruction),
            "registers": self._serialize_registers(env.registers),
            "flags": self._serialize_flags(env.flags),
            "constraints_count": len(env.constraints)
        }
        self.trace_info["steps"].append(step)

    def set_final_state(self, env):
        """
        Set final state of the execution

        Args:
            env: Final symbolic environment
        """
        self.trace_info["final_state"] = {
            "registers": self._serialize_registers(env.registers),
            "flags": self._serialize_flags(env.flags),
            "memory": self._serialize_memory(env.memory),
            "total_constraints": len(env.constraints)
        }

    def _serialize_registers(self, registers):
        """Convert register values to serializable format"""
        return {k: str(v) for k, v in registers.items()}

    def _serialize_flags(self, flags):
        """Convert flag values to serializable format"""
        return {k: str(v) for k, v in flags.items()}

    def _serialize_memory(self, memory):
        """Convert memory values to serializable format"""
        return {str(k): str(v) for k, v in memory.items()}


def save_trace(trace_record, filename):
    """
    Save trace record to file

    Args:
        trace_record: TraceRecord object
        filename: Output filename
    """
    with open(filename, 'w') as f:
        json.dump(trace_record.trace_info, f, indent=2)