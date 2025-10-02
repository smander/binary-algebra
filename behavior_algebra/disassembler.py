from __future__ import annotations

import argparse
import json
import subprocess
import sys
import warnings
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence, Set, Tuple, Union


class DyninstUnavailableError(RuntimeError):
    """Raised when Dyninst bindings are not available for disassembly."""


@dataclass
class OperandInfo:
    """Detailed operand information from Dyninst."""
    type: str  # "register", "immediate", "memory", "displacement"
    value: str  # operand text representation
    size: int = 0  # operand size in bits
    is_read: bool = True
    is_written: bool = False
    base_register: Optional[str] = None  # for memory operands
    index_register: Optional[str] = None  # for memory operands
    scale: int = 1  # for memory operands
    displacement: int = 0  # for memory operands


@dataclass
class InstructionRecord:
    """Comprehensive instruction representation with enhanced metadata."""

    address: str
    mnemonic: str
    operands: str = ""
    bytes: str = ""
    
    # Enhanced Dyninst metadata
    size: int = 0
    architecture: str = ""
    category: str = ""  # "arithmetic", "control", "memory", "logic", etc.
    registers_read: List[str] = field(default_factory=list)
    registers_written: List[str] = field(default_factory=list)
    operand_details: List[OperandInfo] = field(default_factory=list)
    
    # Control flow analysis
    is_call: bool = False
    is_jump: bool = False
    is_conditional: bool = False
    is_return: bool = False
    target_address: Optional[str] = None
    
    # Memory access info
    reads_memory: bool = False
    writes_memory: bool = False
    memory_size: int = 0

    def to_text(self) -> str:
        operands = f" {self.operands}" if self.operands else ""
        return f"{self.address}: {self.mnemonic}{operands}"
    
    def to_basic(self) -> 'InstructionRecord':
        """Convert to basic instruction record for backward compatibility."""
        return InstructionRecord(
            address=self.address,
            mnemonic=self.mnemonic,
            operands=self.operands,
            bytes=self.bytes
        )


@dataclass 
class FunctionInfo:
    """Function-level metadata from Dyninst ParseAPI."""
    name: str
    start_address: str
    end_address: str
    size: int
    blocks: List[str] = field(default_factory=list)
    calls_to: List[str] = field(default_factory=list) 
    called_by: List[str] = field(default_factory=list)
    is_exported: bool = False
    is_imported: bool = False


@dataclass
class LoopInfo:
    """Loop structure information."""
    header_address: str
    back_edge_sources: List[str] = field(default_factory=list)
    loop_blocks: List[str] = field(default_factory=list)
    nesting_level: int = 0


InstructionInput = Union[InstructionRecord, Dict[str, Any]]

_DYNAMIC_OPERATORS = ["+", "-", "*", "×", "·"]
_CONTROL_FLOW_PREFIXES = ("j",)
_CONTROL_FLOW_TERMINATORS = {"ret", "return"}
_CALL_MNEMONIC = "call"
_UNCONDITIONAL_JUMP = "jmp"


class DyninstDisassembler:
    """High-level interface for Dyninst-backed disassembly and exports."""

    def __init__(
        self,
        binary_path: Union[str, Path],
        *,
        behavior_algebra: bool = True,
        cfg_json: bool = False,
        highlight_addrs: Optional[Iterable[Union[int, str]]] = None,
        output_dir: Optional[Union[str, Path]] = None,
        instruction_provider: Optional[Callable[[Path], Iterable[InstructionInput]]] = None,
        cfg_provider: Optional[Callable[[Path, Sequence[InstructionRecord]], Dict[str, Any]]] = None,
        fallback_to_objdump: bool = False,
    ) -> None:
        self.binary_path = Path(binary_path)
        self.behavior_algebra_enabled = behavior_algebra
        self.cfg_enabled = cfg_json
        self.output_dir = Path(output_dir) if output_dir else None
        self._instruction_provider = instruction_provider
        self._cfg_provider = cfg_provider
        self._fallback_to_objdump = fallback_to_objdump

        self.highlight_addrs: Set[int] = set()
        if highlight_addrs:
            for addr in highlight_addrs:
                self.highlight_addrs.add(_as_int_address(addr))

        self._instructions: Optional[List[InstructionRecord]] = None
        self._behavior_algebra_text: Optional[str] = None
        self._cfg_json: Optional[Dict[str, Any]] = None
        
        # Enhanced metadata caches
        self._functions: Optional[List[FunctionInfo]] = None
        self._loops: Optional[List[LoopInfo]] = None
        self._architecture: Optional[str] = None
        self._enhanced_mode: bool = True  # Use enhanced instruction extraction by default

    @property
    def instructions(self) -> List[InstructionRecord]:
        if self._instructions is None:
            self._instructions = self._load_instructions()
        return self._instructions

    @property
    def disassembly_text(self) -> str:
        return "\n".join(instr.to_text() for instr in self.instructions)

    @property
    def behavior_algebra(self) -> Optional[str]:
        if not self.behavior_algebra_enabled:
            return None
        if self._behavior_algebra_text is None:
            self._behavior_algebra_text = _build_behavior_algebra(self.instructions)
        return self._behavior_algebra_text

    @property
    def cfg(self) -> Optional[Dict[str, Any]]:
        if not self.cfg_enabled:
            return None
        if self._cfg_json is None:
            if self._cfg_provider:
                self._cfg_json = self._cfg_provider(self.binary_path, self.instructions)
            else:
                self._cfg_json = build_cfg_from_instructions(self.instructions, self.highlight_addrs)
        return self._cfg_json
    
    @property
    def functions(self) -> List[FunctionInfo]:
        """Get function-level analysis from Dyninst."""
        if self._functions is None:
            self._functions = self._extract_functions()
        return self._functions
    
    @property
    def loops(self) -> List[LoopInfo]:
        """Get loop structure information."""
        if self._loops is None:
            self._loops = self._extract_loops()
        return self._loops
    
    @property
    def architecture(self) -> str:
        """Get target architecture information."""
        if self._architecture is None:
            self._architecture = self._detect_architecture()
        return self._architecture

    def run(
        self,
        *,
        behavior_algebra_path: Optional[Union[str, Path]] = None,
        cfg_path: Optional[Union[str, Path]] = None,
    ) -> Dict[str, Path]:
        results: Dict[str, Path] = {}

        _ = self.instructions  # Force disassembly early

        if self.behavior_algebra_enabled:
            path = self.export_behavior_algebra(behavior_algebra_path)
            results["behavior_algebra"] = path

        if self.cfg_enabled:
            path = self.export_cfg_json(cfg_path)
            results["cfg_json"] = path

        return results

    def export_behavior_algebra(self, output_path: Optional[Union[str, Path]] = None) -> Path:
        if not self.behavior_algebra_enabled:
            raise ValueError("Behavior algebra generation is disabled.")
        algebra = self.behavior_algebra
        if algebra is None:
            raise DyninstUnavailableError("Behavior algebra data is unavailable.")

        path = self._resolve_output_path(output_path, suffix="behavior_algebra.txt")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(algebra)
        return path

    def export_cfg_json(self, output_path: Optional[Union[str, Path]] = None) -> Path:
        if not self.cfg_enabled:
            raise ValueError("CFG export is disabled.")
        cfg_data = self.cfg
        if cfg_data is None:
            raise DyninstUnavailableError("CFG data is unavailable.")

        path = self._resolve_output_path(output_path, suffix="cfg.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cfg_data, indent=2))
        return path
    
    def export_enhanced_cfg_json(self, output_path: Optional[Union[str, Path]] = None) -> Path:
        """Export enhanced CFG with comprehensive metadata."""
        enhanced_cfg = self._build_enhanced_cfg()
        
        path = self._resolve_output_path(output_path, suffix="enhanced_cfg.json")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(enhanced_cfg, indent=2))
        return path

    def _resolve_output_path(self, explicit: Optional[Union[str, Path]], *, suffix: str) -> Path:
        if explicit:
            return Path(explicit)
        base_dir = self.output_dir if self.output_dir else self.binary_path.parent
        return base_dir / f"{self.binary_path.stem}_{suffix}"

    def _load_instructions(self) -> List[InstructionRecord]:
        if self._instruction_provider:
            raw = self._instruction_provider(self.binary_path)
            return _normalize_instructions(raw)

        if self._enhanced_mode:
            try:
                return self._load_enhanced_with_dyninst()
            except DyninstUnavailableError as exc:
                if not self._fallback_to_objdump:
                    raise
                warnings.warn(
                    f"Dyninst unavailable ({exc}); falling back to objdump with enhanced heuristics.",
                    RuntimeWarning,
                    stacklevel=2,
                )
                return self._load_enhanced_with_objdump()
        else:
            # Legacy mode for backward compatibility
            try:
                return self._load_with_dyninst()
            except DyninstUnavailableError as exc:
                if not self._fallback_to_objdump:
                    raise
                warnings.warn(
                    f"Dyninst unavailable ({exc}); falling back to objdump disassembly.",
                    RuntimeWarning,
                    stacklevel=2,
                )
                raw = self._load_with_objdump()
                return _normalize_instructions(raw)

    def _load_with_dyninst(self) -> List[InstructionRecord]:
        try:
            from dyninst import InstructionAPI, ParseAPI
        except ImportError as exc:
            raise DyninstUnavailableError("Dyninst Python bindings could not be imported.") from exc

        parse_fn = getattr(ParseAPI, "parse", None)
        if parse_fn is None:
            raise DyninstUnavailableError("Dyninst ParseAPI.parse is not available.")

        binary = parse_fn(str(self.binary_path))

        decoder = None
        decoder_cls = getattr(InstructionAPI, "InstructionDecoder", None)
        if decoder_cls is not None:
            arch = _call_optional(binary, ("getArch", "arch", "architecture"))
            if arch is not None:
                try:
                    decoder = decoder_cls(arch, True)
                except Exception:
                    decoder = None

        instructions: List[InstructionRecord] = []

        for func in _iter_dyninst_collection(binary, ("functions", "getFuncs", "funcs")):
            for block in _iter_dyninst_collection(func, ("blocks", "getBasicBlocks", "getBlocks", "children")):
                for inst in _iter_dyninst_collection(block, ("instructions", "getInstructions", "insns", "__iter__")):
                    record = _instruction_from_dyninst(inst, decoder)
                    if record is not None:
                        instructions.append(record)

        if not instructions:
            raise DyninstUnavailableError("Dyninst did not return any instructions for the binary.")

        instructions.sort(key=lambda rec: int(rec.address, 16))
        return instructions

    def _load_with_objdump(self) -> List[InstructionRecord]:
        cmd = ["objdump", "-d", str(self.binary_path)]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        except FileNotFoundError as exc:
            raise DyninstUnavailableError("objdump is not available on this system.") from exc
        except subprocess.CalledProcessError as exc:
            raise DyninstUnavailableError(f"objdump failed: {exc}") from exc

        instructions: List[InstructionRecord] = []
        for line in result.stdout.splitlines():
            stripped = line.strip()
            if not stripped or ":" not in stripped:
                continue

            parts = stripped.split(":", 1)
            address_text = parts[0].strip()
            try:
                address = int(address_text, 16)
            except ValueError:
                continue

            rest = parts[1].strip()
            segments = rest.split()
            mnemonic_idx = None
            for idx, segment in enumerate(segments):
                if not _is_hex_like(segment):
                    mnemonic_idx = idx
                    break
            if mnemonic_idx is None:
                continue

            mnemonic = segments[mnemonic_idx]
            operand_text = " ".join(segments[mnemonic_idx + 1:]).strip()
            instructions.append(
                InstructionRecord(
                    address=f"{address:x}",
                    mnemonic=mnemonic,
                    operands=operand_text,
                    bytes="",
                )
            )

        if not instructions:
            raise DyninstUnavailableError("objdump did not return any instructions.")

        return instructions

    def _load_enhanced_with_dyninst(self) -> List[InstructionRecord]:
        """Load enhanced instructions using full Dyninst capabilities."""
        try:
            from dyninst import InstructionAPI, ParseAPI
        except ImportError as exc:
            raise DyninstUnavailableError("Dyninst Python bindings could not be imported.") from exc

        parse_fn = getattr(ParseAPI, "parse", None)
        if parse_fn is None:
            raise DyninstUnavailableError("Dyninst ParseAPI.parse is not available.")

        binary = parse_fn(str(self.binary_path))

        # Get architecture information
        self._architecture = self._extract_architecture_from_binary(binary)

        # Create instruction decoder
        decoder = None
        decoder_cls = getattr(InstructionAPI, "InstructionDecoder", None)
        if decoder_cls is not None:
            arch = _call_optional(binary, ("getArch", "arch", "architecture"))
            if arch is not None:
                try:
                    decoder = decoder_cls(arch, True)
                except Exception:
                    decoder = None

        enhanced_instructions: List[InstructionRecord] = []

        # Extract functions first for context
        self._functions = self._extract_functions_from_binary(binary)

        # Process all instructions with enhanced metadata
        for func in _iter_dyninst_collection(binary, ("functions", "getFuncs", "funcs")):
            for block in _iter_dyninst_collection(func, ("blocks", "getBasicBlocks", "getBlocks", "children")):
                for inst in _iter_dyninst_collection(block, ("instructions", "getInstructions", "insns", "__iter__")):
                    enhanced_record = self._create_enhanced_instruction(inst, decoder, func)
                    if enhanced_record is not None:
                        enhanced_instructions.append(enhanced_record)

        if not enhanced_instructions:
            raise DyninstUnavailableError("Dyninst did not return any instructions for the binary.")

        enhanced_instructions.sort(key=lambda rec: int(rec.address, 16))
        return enhanced_instructions

    def _load_enhanced_with_objdump(self) -> List[InstructionRecord]:
        """Load enhanced instructions using objdump with heuristic analysis."""
        basic_instructions = self._load_with_objdump()
        enhanced_instructions = []
        
        for basic_instr in basic_instructions:
            enhanced_instr = self._enhance_basic_instruction(basic_instr)
            enhanced_instructions.append(enhanced_instr)
            
        return enhanced_instructions

    def _create_enhanced_instruction(self, inst: Any, decoder: Any, func: Any) -> Optional[InstructionRecord]:
        """Create enhanced instruction record from Dyninst instruction object."""
        # Basic instruction info
        address_value = _call_optional(inst, ("getAddress", "address", "addr"))
        if address_value is None:
            return None

        try:
            address = f"{address_value:x}"
        except Exception:
            return None

        # Get instruction text and parse mnemonic/operands
        text = self._get_instruction_text(inst, decoder)
        mnemonic, operands = _split_mnemonic_operands(text) if text else ("", "")

        if not mnemonic:
            mnemonic = _call_optional(inst, ("mnemonic", "getMnemonic")) or ""

        # Get raw bytes
        bytes_blob = _call_optional(inst, ("bytes", "getBytes", "rawBytes"))
        bytes_text = self._format_instruction_bytes(bytes_blob)

        # Enhanced metadata extraction
        size = _call_optional(inst, ("size", "getSize")) or 0
        category = self._get_instruction_category(inst, mnemonic)

        # Register analysis
        registers_read, registers_written = self._analyze_registers(inst)

        # Operand analysis
        operand_details = self._analyze_operands(inst, operands)

        # Control flow analysis
        is_call, is_jump, is_conditional, is_return, target_address = self._analyze_control_flow(inst, mnemonic, operands)

        # Memory access analysis
        reads_memory, writes_memory, memory_size = self._analyze_memory_access(inst, operands)

        return InstructionRecord(
            address=address,
            mnemonic=mnemonic.strip(),
            operands=operands.strip(),
            bytes=bytes_text,
            size=size,
            architecture=self.architecture,
            category=category,
            registers_read=registers_read,
            registers_written=registers_written,
            operand_details=operand_details,
            is_call=is_call,
            is_jump=is_jump,
            is_conditional=is_conditional,
            is_return=is_return,
            target_address=target_address,
            reads_memory=reads_memory,
            writes_memory=writes_memory,
            memory_size=memory_size
        )

    def _enhance_basic_instruction(self, basic_instr) -> InstructionRecord:
        """Convert basic instruction to enhanced format with heuristic analysis."""
        # Analyze what we can from mnemonic and operands
        mnemonic = basic_instr.mnemonic
        operands = basic_instr.operands

        category = self._categorize_instruction_by_mnemonic(mnemonic)
        is_call = mnemonic.startswith("call")
        is_jump = mnemonic.startswith("j") and mnemonic != "je"  # rough heuristic
        is_conditional = mnemonic.startswith("j") and mnemonic not in ["jmp", "jmpq"]
        is_return = mnemonic in ["ret", "retq", "return"]

        # Basic register extraction from operands text
        registers_read, registers_written = self._extract_registers_from_text(operands, mnemonic)

        return InstructionRecord(
            address=basic_instr.address,
            mnemonic=mnemonic,
            operands=operands,
            bytes=basic_instr.bytes,
            size=0,  # Unknown without Dyninst
            architecture=self.architecture,
            category=category,
            registers_read=registers_read,
            registers_written=registers_written,
            operand_details=[],  # Limited without Dyninst
            is_call=is_call,
            is_jump=is_jump,
            is_conditional=is_conditional,
            is_return=is_return,
            target_address=None,
            reads_memory="[" in operands,
            writes_memory=self._instruction_writes_memory(mnemonic, operands),
            memory_size=0
        )

    # Enhanced analysis methods
    def _extract_functions(self) -> List[FunctionInfo]:
        """Extract function information (fallback implementation)."""
        # This is a placeholder - real Dyninst would provide rich function data
        return []

    def _extract_loops(self) -> List[LoopInfo]:
        """Extract loop structure information."""
        # This would use Dyninst's loop analysis
        return []

    def _detect_architecture(self) -> str:
        """Detect architecture from various sources."""
        return "x86-64"  # Default fallback

    def _build_enhanced_cfg(self) -> Dict[str, Any]:
        """Build enhanced CFG with function, loop, and detailed instruction metadata."""
        # Get basic CFG structure
        basic_cfg = self.cfg or {}

        # Enhance with additional metadata
        enhanced_cfg = {
            "metadata": {
                "architecture": self.architecture,
                "binary_path": str(self.binary_path),
                "total_functions": len(self.functions),
                "total_loops": len(self.loops),
                "total_nodes": len(basic_cfg.get("nodes", [])),
                "total_edges": len(basic_cfg.get("edges", [])),
                "highlighted_addresses": basic_cfg.get("metadata", {}).get("highlighted_addresses", []),
                "analysis_features": {
                    "enhanced_instructions": True,
                    "function_analysis": len(self.functions) > 0,
                    "loop_detection": len(self.loops) > 0,
                    "register_analysis": True,
                    "memory_analysis": True
                }
            },
            "functions": [self._function_to_dict(func) for func in self.functions],
            "loops": [self._loop_to_dict(loop) for loop in self.loops],
            "nodes": self._enhance_cfg_nodes(basic_cfg.get("nodes", [])),
            "edges": basic_cfg.get("edges", [])
        }

        return enhanced_cfg

    def _enhance_cfg_nodes(self, basic_nodes: List[Dict]) -> List[Dict]:
        """Enhance CFG nodes with detailed instruction metadata."""
        enhanced_nodes = []
        for node in basic_nodes:
            enhanced_node = node.copy()
            enhanced_instructions = []

            for basic_instr in node.get("instructions", []):
                addr = basic_instr["address"].replace("0x", "")
                # Find matching enhanced instruction
                matching_instr = None
                for instr in self.instructions:
                    if instr.address == addr:
                        matching_instr = instr
                        break

                if matching_instr:
                    enhanced_instructions.append({
                        **basic_instr,
                        "size": matching_instr.size,
                        "category": matching_instr.category,
                        "registers_read": matching_instr.registers_read,
                        "registers_written": matching_instr.registers_written,
                        "is_call": matching_instr.is_call,
                        "is_jump": matching_instr.is_jump,
                        "is_conditional": matching_instr.is_conditional,
                        "is_return": matching_instr.is_return,
                        "reads_memory": matching_instr.reads_memory,
                        "writes_memory": matching_instr.writes_memory,
                        "memory_size": matching_instr.memory_size,
                        "operand_details": [
                            {
                                "type": op.type,
                                "value": op.value,
                                "size": op.size,
                                "is_read": op.is_read,
                                "is_written": op.is_written
                            } for op in matching_instr.operand_details
                        ]
                    })
                else:
                    enhanced_instructions.append(basic_instr)

            enhanced_node["instructions"] = enhanced_instructions
            enhanced_nodes.append(enhanced_node)

        return enhanced_nodes

    # Helper methods for enhanced analysis
    def _categorize_instruction_by_mnemonic(self, mnemonic: str) -> str:
        """Categorize instruction by mnemonic pattern."""
        mnemonic = mnemonic.lower()

        if mnemonic.startswith(("add", "sub", "mul", "div", "inc", "dec", "neg")):
            return "arithmetic"
        elif mnemonic.startswith(("and", "or", "xor", "not", "shl", "shr", "sar", "rol", "ror")):
            return "logic"
        elif mnemonic.startswith(("mov", "lea", "push", "pop")):
            return "data_transfer"
        elif mnemonic.startswith(("cmp", "test")):
            return "comparison"
        elif mnemonic.startswith(("j", "call", "ret")):
            return "control_flow"
        elif mnemonic in ("nop", "hlt"):
            return "system"
        else:
            return "other"

    def _extract_registers_from_text(self, operands: str, mnemonic: str) -> Tuple[List[str], List[str]]:
        """Extract registers from operand text (fallback method)."""
        import re
        reg_pattern = r'%([re]?[abcd]x|[re]?[sb]p|[re]?[sd]i|r[89]|r1[0-5]|[abcd][hl])'
        registers = re.findall(reg_pattern, operands)

        # Simple heuristic: first operand often written to, others read
        if mnemonic.startswith("mov") and "," in operands:
            parts = operands.split(",")
            if len(parts) >= 2:
                return [reg for reg in registers[1:]], [registers[0]] if registers else []

        return registers, []

    def _instruction_writes_memory(self, mnemonic: str, operands: str) -> bool:
        """Check if instruction writes to memory."""
        write_mnemonics = {"mov", "store", "push", "pop"}
        return any(mn in mnemonic.lower() for mn in write_mnemonics) and "[" in operands

    # Placeholder methods for full Dyninst integration
    def _get_instruction_category(self, inst: Any, mnemonic: str) -> str:
        """Determine instruction category from Dyninst metadata."""
        category = _call_optional(inst, ("category", "getCategory"))
        if category:
            return str(category)
        return self._categorize_instruction_by_mnemonic(mnemonic)

    def _analyze_registers(self, inst: Any) -> Tuple[List[str], List[str]]:
        """Analyze registers read and written by instruction."""
        # This would use Dyninst's register analysis
        return [], []

    def _analyze_operands(self, inst: Any, operands: str) -> List[OperandInfo]:
        """Analyze detailed operand information."""
        # This would use Dyninst's operand AST analysis
        return []

    def _analyze_control_flow(self, inst: Any, mnemonic: str, operands: str) -> Tuple[bool, bool, bool, bool, Optional[str]]:
        """Analyze control flow properties of instruction."""
        is_call = mnemonic.startswith("call")
        is_jump = mnemonic.startswith("j") and mnemonic not in ["je", "jne", "jz", "jnz"]  # rough
        is_conditional = mnemonic.startswith("j") and mnemonic not in ["jmp", "jmpq"]
        is_return = mnemonic in ["ret", "retq", "return"]
        target_address = None  # Would extract from Dyninst

        return is_call, is_jump, is_conditional, is_return, target_address

    def _analyze_memory_access(self, inst: Any, operands: str) -> Tuple[bool, bool, int]:
        """Analyze memory access patterns."""
        reads_memory = "[" in operands
        writes_memory = self._instruction_writes_memory("", operands)  # simplified
        memory_size = 0  # Would get from Dyninst

        return reads_memory, writes_memory, memory_size

    def _extract_functions_from_binary(self, binary: Any) -> List[FunctionInfo]:
        """Extract function information from Dyninst binary object."""
        # This would use Dyninst's function analysis
        return []

    def _get_instruction_text(self, inst: Any, decoder: Any) -> Optional[str]:
        """Get instruction text from Dyninst instruction."""
        text = None
        if decoder is not None:
            formatter = getattr(inst, "format", None)
            if callable(formatter):
                try:
                    text = formatter(decoder)
                except Exception:
                    text = None

        if not text:
            for name in ("disassemble", "getDisassembly", "format"):
                method = getattr(inst, name, None)
                if callable(method):
                    try:
                        text = method()
                    except Exception:
                        continue
                    if text:
                        break
        return text

    def _format_instruction_bytes(self, bytes_blob: Any) -> str:
        """Format instruction bytes to hex string."""
        if isinstance(bytes_blob, (bytes, bytearray)):
            return bytes(bytes_blob).hex()
        elif isinstance(bytes_blob, Sequence) and not isinstance(bytes_blob, (str, bytes, bytearray)):
            try:
                return bytes(bytes_blob).hex()
            except Exception:
                return "".join(f"{int(b) & 0xff:02x}" for b in bytes_blob)
        elif bytes_blob:
            return str(bytes_blob)
        return ""

    def _extract_architecture_from_binary(self, binary: Any) -> str:
        """Extract architecture from Dyninst binary."""
        arch = _call_optional(binary, ("getArch", "arch", "architecture"))
        return str(arch) if arch else "unknown"

    def _function_to_dict(self, func: FunctionInfo) -> Dict:
        """Convert function info to dictionary."""
        return {
            "name": func.name,
            "start_address": func.start_address,
            "end_address": func.end_address,
            "size": func.size,
            "blocks": func.blocks,
            "calls_to": func.calls_to,
            "called_by": func.called_by,
            "is_exported": func.is_exported,
            "is_imported": func.is_imported
        }

    def _loop_to_dict(self, loop: LoopInfo) -> Dict:
        """Convert loop info to dictionary."""
        return {
            "header_address": loop.header_address,
            "back_edge_sources": loop.back_edge_sources,
            "loop_blocks": loop.loop_blocks,
            "nesting_level": loop.nesting_level
        }


def _as_int_address(value: Union[int, str]) -> int:
    if isinstance(value, int):
        if value < 0:
            raise ValueError("Address cannot be negative")
        return value

    text = str(value).strip()
    if text.startswith("0x") or text.startswith("0X"):
        return int(text, 16)
    return int(text, 16)


def _format_address(value: Union[int, str]) -> str:
    if isinstance(value, int):
        if value < 0:
            raise ValueError("Address cannot be negative")
        return f"{value:x}"

    text = str(value).strip()
    if text.startswith("0x") or text.startswith("0X"):
        text = text[2:]
    int(text, 16)  # Validate
    return text.lower()


def _normalize_instructions(raw: Iterable[InstructionInput]) -> List[InstructionRecord]:
    normalized: List[InstructionRecord] = []
    for entry in raw:
        if isinstance(entry, InstructionRecord):
            normalized.append(entry)
            continue

        address = _format_address(entry.get("address"))
        mnemonic = str(entry.get("mnemonic", "")).strip()
        operands = str(entry.get("operands", "")).strip()
        bytes_hex = str(entry.get("bytes", "")).strip()
        normalized.append(InstructionRecord(address=address, mnemonic=mnemonic, operands=operands, bytes=bytes_hex))

    normalized.sort(key=lambda rec: int(rec.address, 16))
    return normalized


def _split_mnemonic_operands(text: str) -> Tuple[str, str]:
    stripped = text.strip()
    if not stripped:
        return "", ""
    parts = stripped.split(None, 1)
    mnemonic = parts[0]
    operands = parts[1].strip() if len(parts) > 1 else ""
    return mnemonic, operands


def _is_hex_like(text: str) -> bool:
    try:
        int(text, 16)
        return True
    except ValueError:
        return False


def _instruction_from_dyninst(inst: Any, decoder: Any) -> Optional[InstructionRecord]:
    address_value = _call_optional(inst, ("getAddress", "address", "addr"))
    if address_value is None:
        return None
    try:
        address = _format_address(address_value)
    except Exception:
        return None

    text = None
    if decoder is not None:
        formatter = getattr(inst, "format", None)
        if callable(formatter):
            try:
                text = formatter(decoder)
            except Exception:
                text = None

    if not text:
        for name in ("disassemble", "getDisassembly", "format"):
            method = getattr(inst, name, None)
            if callable(method):
                try:
                    text = method()
                except Exception:
                    continue
                if text:
                    break

    mnemonic = None
    operands = ""
    if text:
        mnemonic, operands = _split_mnemonic_operands(str(text))
    else:
        mnemonic = _call_optional(inst, ("mnemonic", "getMnemonic"))
        operands = _call_optional(inst, ("operands", "getOperands", "op_str")) or ""

    if not mnemonic:
        return None

    bytes_blob = _call_optional(inst, ("bytes", "getBytes", "rawBytes"))
    bytes_text = ""
    if isinstance(bytes_blob, (bytes, bytearray)):
        bytes_text = bytes(bytes_blob).hex()
    elif isinstance(bytes_blob, Sequence) and not isinstance(bytes_blob, (str, bytes, bytearray)):
        try:
            bytes_text = bytes(bytes_blob).hex()
        except Exception:
            bytes_text = "".join(f"{int(b) & 0xff:02x}" for b in bytes_blob)
    elif bytes_blob:
        bytes_text = str(bytes_blob)

    return InstructionRecord(
        address=address,
        mnemonic=str(mnemonic).strip(),
        operands=str(operands).strip(),
        bytes=bytes_text,
    )


def _call_optional(obj: Any, names: Sequence[str]) -> Optional[Any]:
    for name in names:
        if not hasattr(obj, name):
            continue
        attribute = getattr(obj, name)
        try:
            return attribute() if callable(attribute) else attribute
        except TypeError:
            continue
        except Exception:
            return None
    return None


def _iter_dyninst_collection(obj: Any, names: Sequence[str]):
    for name in names:
        if not hasattr(obj, name):
            continue
        attribute = getattr(obj, name)
        try:
            value = attribute() if callable(attribute) else attribute
        except TypeError:
            continue
        except Exception:
            continue
        if value is None:
            continue
        try:
            iterator = iter(value)
        except TypeError:
            yield value
            return
        else:
            for item in iterator:
                yield item
            return
    try:
        iterator = iter(obj)
    except TypeError:
        return
    else:
        for item in iterator:
            yield item


def _is_dynamic_operand(operand: str) -> bool:
    operand = operand.strip()
    if not operand:
        return False

    token = operand.split()[0]
    if token.startswith("0x"):
        return False
    if all(ch in "0123456789abcdef" for ch in token.lower()):
        return False

    if "ptr" in operand and "[" not in operand:
        return True

    registers = {
        "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
        "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
        "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
        "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
        "al", "bl", "cl", "dl", "ah", "bh", "ch", "dh",
        "rip", "eip", "ip",
        "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
        "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w",
        "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b",
        "cs", "ds", "es", "fs", "gs", "ss",
    }

    if "[" in operand and "]" in operand:
        inside = operand[operand.find("[") + 1:operand.find("]")]
        if any(reg in inside for reg in registers):
            return True
        if any(op in inside for op in _DYNAMIC_OPERATORS):
            parts = None
            for op in _DYNAMIC_OPERATORS:
                if op in inside:
                    parts = inside.split(op, 1)
                    break
            if parts and len(parts) == 2:
                left, right = parts[0].strip(), parts[1].strip()
                left_numeric = left.startswith("0x") or left.isdigit()
                right_numeric = right.startswith("0x") or right.isdigit()
                if left_numeric and right_numeric:
                    return False
            return True
        if inside.startswith("0x") or inside.isdigit():
            return False
        return True

    return False


def _extract_static_target(operands: str) -> Optional[str]:
    if not operands:
        return None
    operands = operands.replace(",", " ")
    for token in operands.split():
        token = token.strip()
        if not token:
            continue
        if token.startswith("0x"):
            try:
                return f"0x{int(token, 16):x}"
            except ValueError:
                continue
        if all(ch in "0123456789abcdef" for ch in token.lower()):
            try:
                return f"0x{int(token, 16):x}"
            except ValueError:
                continue
    return None


def _compute_jump_targets(instructions: Sequence[InstructionRecord]) -> Set[str]:
    targets: Set[str] = set()
    for instr in instructions:
        if instr.mnemonic == _CALL_MNEMONIC or instr.mnemonic.startswith(_CONTROL_FLOW_PREFIXES):
            if instr.operands and not _is_dynamic_operand(instr.operands):
                target = _extract_static_target(instr.operands)
                if target:
                    targets.add(target[2:])
    return targets


def _collect_block_starts(instructions: Sequence[InstructionRecord]) -> List[str]:
    if not instructions:
        return []
    jump_targets = _compute_jump_targets(instructions)
    starts: Set[str] = {instructions[0].address}
    for idx, instr in enumerate(instructions):
        if instr.mnemonic.startswith(_CONTROL_FLOW_PREFIXES) or instr.mnemonic in _CONTROL_FLOW_TERMINATORS or instr.mnemonic == _CALL_MNEMONIC:
            if idx + 1 < len(instructions):
                starts.add(instructions[idx + 1].address)
        if instr.mnemonic.startswith(_CONTROL_FLOW_PREFIXES) and instr.operands and not _is_dynamic_operand(instr.operands):
            target = _extract_static_target(instr.operands)
            if target:
                starts.add(target[2:])
    starts.update(jump_targets)
    ordered_starts: List[str] = []
    for instr in instructions:
        if instr.address in starts and instr.address not in ordered_starts:
            ordered_starts.append(instr.address)
    return ordered_starts


def build_cfg_from_instructions(
    instructions: Sequence[InstructionRecord],
    highlight_addrs: Optional[Set[int]] = None,
) -> Dict[str, Any]:
    if not instructions:
        return {"nodes": [], "edges": [], "metadata": {"total_nodes": 0, "total_edges": 0, "highlighted_addresses": []}}

    highlight_set = highlight_addrs or set()
    block_order = _collect_block_starts(instructions)
    blocks: Dict[str, List[InstructionRecord]] = {}
    current_block = None
    block_set = set(block_order)

    for instr in instructions:
        if current_block is None or (instr.address in block_set and instr.address != current_block):
            current_block = instr.address
            blocks.setdefault(current_block, [])
        blocks.setdefault(current_block, []).append(instr)

    ordered_blocks = [addr for addr in block_order if addr in blocks]

    nodes: List[Dict[str, Any]] = []
    edges: List[Dict[str, Any]] = []

    for block_addr in ordered_blocks:
        block_instructions = blocks[block_addr]
        node = {
            "address": f"0x{int(block_addr, 16):x}",
            "instructions": [],
            "is_highlighted": False,
        }
        for instr in block_instructions:
            addr_int = int(instr.address, 16)
            is_highlighted = addr_int in highlight_set
            node["is_highlighted"] = node["is_highlighted"] or is_highlighted
            node["instructions"].append(
                {
                    "address": f"0x{addr_int:x}",
                    "mnemonic": instr.mnemonic,
                    "operands": instr.operands,
                    "bytes": instr.bytes,
                    "is_highlighted": is_highlighted,
                    "is_control_flow": instr.mnemonic in _CONTROL_FLOW_TERMINATORS or instr.mnemonic == _CALL_MNEMONIC or instr.mnemonic.startswith(_CONTROL_FLOW_PREFIXES),
                }
            )
        nodes.append(node)

    block_index = {addr: idx for idx, addr in enumerate(ordered_blocks)}

    for idx, block_addr in enumerate(ordered_blocks):
        block_instructions = blocks[block_addr]
        last_instr = block_instructions[-1]
        source_hex = f"0x{int(block_addr, 16):x}"
        next_block_addr = ordered_blocks[idx + 1] if idx + 1 < len(ordered_blocks) else None

        if last_instr.mnemonic in _CONTROL_FLOW_TERMINATORS:
            continue

        if last_instr.mnemonic == _CALL_MNEMONIC:
            if last_instr.operands and not _is_dynamic_operand(last_instr.operands):
                target = _extract_static_target(last_instr.operands)
                if target:
                    edges.append({"source": source_hex, "target": target, "type": "call"})
            if next_block_addr:
                edges.append({
                    "source": source_hex,
                    "target": f"0x{int(next_block_addr, 16):x}",
                    "type": "sequential",
                })
            continue

        if last_instr.mnemonic.startswith(_CONTROL_FLOW_PREFIXES):
            jump_type = "conditional_jump" if last_instr.mnemonic != _UNCONDITIONAL_JUMP else "unconditional_jump"
            if last_instr.operands and not _is_dynamic_operand(last_instr.operands):
                target = _extract_static_target(last_instr.operands)
                if target:
                    edges.append({"source": source_hex, "target": target, "type": jump_type})
            if last_instr.mnemonic != _UNCONDITIONAL_JUMP and next_block_addr:
                edges.append({
                    "source": source_hex,
                    "target": f"0x{int(next_block_addr, 16):x}",
                    "type": "sequential",
                })
            continue

        if next_block_addr:
            edges.append({
                "source": source_hex,
                "target": f"0x{int(next_block_addr, 16):x}",
                "type": "sequential",
            })

    metadata = {
        "total_nodes": len(nodes),
        "total_edges": len(edges),
        "highlighted_addresses": [f"0x{addr:x}" for addr in sorted(highlight_set)],
    }

    return {"nodes": nodes, "edges": edges, "metadata": metadata}


def _build_behavior_algebra(instructions: Sequence[InstructionRecord]) -> str:
    if not instructions:
        return ""

    jump_targets = _compute_jump_targets(instructions)
    dynamic_behaviors: Set[str] = set()
    processed_addresses: Set[str] = set()
    lines: List[str] = []

    i = 0
    while i < len(instructions):
        current = instructions[i]
        addr = current.address
        mnemonic = current.mnemonic

        if addr in processed_addresses:
            i += 1
            continue

        processed_addresses.add(addr)

        if mnemonic in _CONTROL_FLOW_TERMINATORS:
            lines.append(f"B({addr}) = ret({addr}),")
            i += 1
            continue

        if mnemonic == _CALL_MNEMONIC:
            destination = current.operands
            is_dynamic = _is_dynamic_operand(destination)

            if is_dynamic:
                dynamic_behaviors.add(f"call({addr}):{destination}")
                next_idx = i + 1
                if next_idx < len(instructions):
                    lines.append(
                        f"B({addr}) = B(DYNAMIC); B({instructions[next_idx].address}),"
                    )
                else:
                    lines.append(f"B({addr}) = B(DYNAMIC),")
            else:
                clean_dest = _extract_static_target(destination)
                if clean_dest is None:
                    clean_dest = destination
                next_idx = i + 1
                if next_idx < len(instructions):
                    lines.append(
                        f"B({addr}) = B({clean_dest}); B({instructions[next_idx].address}),"
                    )
                else:
                    lines.append(f"B({addr}) = B({clean_dest}),")
            i += 1
            continue

        if mnemonic.startswith(_CONTROL_FLOW_PREFIXES):
            destination = current.operands
            is_dynamic = _is_dynamic_operand(destination)

            if is_dynamic:
                dynamic_behaviors.add(f"{mnemonic}({addr}):{destination}")
                if mnemonic != _UNCONDITIONAL_JUMP:
                    next_idx = i + 1
                    if next_idx < len(instructions):
                        lines.append(
                            f"B({addr}) = {mnemonic}({addr}).B(DYNAMIC) + !{mnemonic}({addr}).B({instructions[next_idx].address}),"
                        )
                    else:
                        fallthrough = f"{int(addr, 16) + 1:x}"
                        lines.append(
                            f"B({addr}) = {mnemonic}({addr}).B(DYNAMIC) + !{mnemonic}({addr}).B({fallthrough}),"
                        )
                else:
                    lines.append(f"B({addr}) = B(DYNAMIC),")
            else:
                clean_dest = _extract_static_target(destination)
                if clean_dest is None:
                    clean_dest = destination
                next_idx = i + 1
                if next_idx < len(instructions):
                    if mnemonic == _UNCONDITIONAL_JUMP:
                        lines.append(f"B({addr}) = B({clean_dest}),")
                    else:
                        lines.append(
                            f"B({addr}) = {mnemonic}({addr}).B({clean_dest}) + !{mnemonic}({addr}).B({instructions[next_idx].address}),"
                        )
                else:
                    if mnemonic == _UNCONDITIONAL_JUMP:
                        lines.append(f"B({addr}) = B({clean_dest}),")
                    else:
                        fallthrough = f"{int(addr, 16) + 1:x}"
                        lines.append(
                            f"B({addr}) = {mnemonic}({addr}).B({clean_dest}) + !{mnemonic}({addr}).B({fallthrough}),"
                        )
            i += 1
            continue

        start_addr = addr
        seq_parts: List[str] = []
        initial_i = i

        while i < len(instructions):
            current = instructions[i]
            mnemonic = current.mnemonic
            next_is_jump_target = i + 1 < len(instructions) and instructions[i + 1].address in jump_targets
            ends_sequence = (
                mnemonic == _CALL_MNEMONIC
                or mnemonic.startswith(_CONTROL_FLOW_PREFIXES)
                or mnemonic in _CONTROL_FLOW_TERMINATORS
                or next_is_jump_target
            )
            seq_parts.append(f"{mnemonic}({current.address})")
            i += 1
            if ends_sequence:
                break

        if i == initial_i:
            i += 1
            continue

        if i < len(instructions):
            lines.append(
                f"B({start_addr}) = {'.'.join(seq_parts)}.B({instructions[i].address}),"
            )
        else:
            fallthrough = f"{int(instructions[-1].address, 16) + 1:x}"
            lines.append(f"B({start_addr}) = {'.'.join(seq_parts)}.B({fallthrough}),")

    lines.append("\n# Dynamic (indirect) control flows:")
    lines.append("B(DYNAMIC) = nop(DYNAMIC),")

    if dynamic_behaviors:
        lines.append("\n# Observed dynamic control transfers:")
        for entry in sorted(dynamic_behaviors):
            lines.append(f"# {entry}")

    return "\n".join(lines)


def disassemble_binary(binary_path: Union[str, Path]) -> List[InstructionRecord]:
    disassembler = DyninstDisassembler(binary_path)
    return disassembler.instructions


def generate_behavior_algebra(binary_path: Union[str, Path]) -> str:
    disassembler = DyninstDisassembler(binary_path)
    return disassembler.behavior_algebra or ""


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = argparse.ArgumentParser(description="Disassemble binaries with Dyninst and export artifacts.")
    parser.add_argument("binary_path", help="Path to the binary to disassemble")
    parser.add_argument("--output", "-o", help="Output path for main artifact (txt or json based on --format)")
    parser.add_argument("--format", "-f", choices=["txt", "json", "both"], default="txt", help="Artifact format to produce")
    parser.add_argument("--cfg-output", help="Explicit output path for CFG JSON (defaults based on binary name)")
    parser.add_argument("--no-behavior-algebra", action="store_true", help="Disable behavior algebra generation")
    parser.add_argument("--highlight", help="Comma-separated list of hex addresses to highlight in CFG output")
    parser.add_argument("--export-dir", help="Directory where artifacts should be written")
    parser.add_argument("--allow-objdump-fallback", action="store_true", help="Use objdump if Dyninst bindings are unavailable")
    args = parser.parse_args(argv)

    highlight = None
    if args.highlight:
        highlight = [int(token, 16) for token in args.highlight.split(",") if token.strip()]

    behavior_enabled = args.format in {"txt", "both"} and not args.no_behavior_algebra
    cfg_enabled = args.format in {"json", "both"} or args.cfg_output is not None

    disassembler = DyninstDisassembler(
        args.binary_path,
        behavior_algebra=behavior_enabled,
        cfg_json=cfg_enabled,
        highlight_addrs=highlight,
        output_dir=args.export_dir,
        fallback_to_objdump=args.allow_objdump_fallback,
    )

    behavior_output = None
    cfg_output = None

    if behavior_enabled:
        if args.format in {"txt", "both"}:
            behavior_output = args.output

    if cfg_enabled:
        if args.format == "json":
            cfg_output = args.output
        else:
            cfg_output = args.cfg_output

    try:
        results = disassembler.run(behavior_algebra_path=behavior_output, cfg_path=cfg_output)
    except DyninstUnavailableError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except Exception as exc:  # pragma: no cover
        print(f"Unexpected error: {exc}", file=sys.stderr)
        return 1

    for key, path in results.items():
        print(f"Output [{key}]: {path}")

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
