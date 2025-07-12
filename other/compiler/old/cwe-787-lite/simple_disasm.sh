#!/bin/bash

# Simple disassembler using only standard Unix tools
# No Python/angr required - works everywhere

echo "CWE-787 Simple Disassembler (No Python Required)"
echo "================================================"

BINARY="simple_dynamic"
OUTPUT_DIR="disasm_output"

# Check for basic tools
check_tools() {
    echo "Checking available tools..."
    TOOLS_FOUND=0
    
    if command -v gcc >/dev/null 2>&1; then
        echo "✓ gcc compiler"
        TOOLS_FOUND=1
    else
        echo "✗ gcc not found"
    fi
    
    if command -v objdump >/dev/null 2>&1; then
        echo "✓ objdump disassembler"
        TOOLS_FOUND=1
    else
        echo "✗ objdump not found"
    fi
    
    if command -v gdb >/dev/null 2>&1; then
        echo "✓ gdb debugger"
        TOOLS_FOUND=1
    else
        echo "✗ gdb not found"
    fi
    
    if command -v readelf >/dev/null 2>&1; then
        echo "✓ readelf binary analyzer"
        TOOLS_FOUND=1
    else
        echo "✗ readelf not found"
    fi
    
    if command -v xxd >/dev/null 2>&1; then
        echo "✓ xxd hex dump"
        TOOLS_FOUND=1
    elif command -v hexdump >/dev/null 2>&1; then
        echo "✓ hexdump utility"
        TOOLS_FOUND=1
    else
        echo "✗ no hex dump tool found"
    fi
    
    if command -v nm >/dev/null 2>&1; then
        echo "✓ nm symbol reader"
        TOOLS_FOUND=1
    else
        echo "✗ nm not found"
    fi
    
    if [ $TOOLS_FOUND -eq 0 ]; then
        echo ""
        echo "No analysis tools found. Install development tools:"
        echo "  macOS: xcode-select --install"
        echo "  Ubuntu: sudo apt install build-essential gdb binutils"
        echo "  CentOS: sudo yum groupinstall 'Development Tools'"
        return 1
    fi
    
    return 0
}

# Create test binary if needed
create_binary() {
    if [ ! -f "$BINARY" ]; then
        echo ""
        echo "Creating test binary..."
        
        if [ ! -f "simple.c" ]; then
            echo "Creating simple.c..."
            cat > simple.c << 'EOF'
// Simplest possible CWE-787 for analysis
int main() {
    char buf[4];
    buf[4] = 42;  // CWE-787: Out-of-bounds write
    return 0;
}
EOF
        fi
        
        if command -v gcc >/dev/null 2>&1; then
            gcc -O0 -fno-stack-protector simple.c -o $BINARY
            if [ $? -eq 0 ]; then
                echo "✓ Binary created: $BINARY"
                return 0
            else
                echo "✗ Failed to compile"
                return 1
            fi
        else
            echo "✗ No compiler available"
            return 1
        fi
    else
        echo "✓ Using existing binary: $BINARY"
        return 0
    fi
}

# Main disassembly function
disassemble() {
    echo ""
    echo "Disassembling $BINARY..."
    echo "======================="
    
    mkdir -p $OUTPUT_DIR
    
    # File info
    echo "1. Binary Information:"
    echo "---------------------"
    if command -v file >/dev/null 2>&1; then
        file $BINARY
    fi
    ls -lh $BINARY
    echo ""
    
    # objdump disassembly (most common)
    if command -v objdump >/dev/null 2>&1; then
        echo "2. objdump Disassembly:"
        echo "----------------------"
        objdump -d $BINARY > $OUTPUT_DIR/objdump_full.asm
        echo "Full disassembly saved to: $OUTPUT_DIR/objdump_full.asm"
        echo "Lines: $(wc -l < $OUTPUT_DIR/objdump_full.asm)"
        echo ""
        
        echo "Main function:"
        # Try different main function patterns (Linux uses <main>, macOS uses _main)
        objdump -d $BINARY | grep -A 20 -E "(<main>:|_main:)" | tee $OUTPUT_DIR/objdump_main.asm
        echo "Main function saved to: $OUTPUT_DIR/objdump_main.asm"
        echo ""
    fi
    
    # GDB disassembly (more detailed)
    if command -v gdb >/dev/null 2>&1; then
        echo "3. GDB Disassembly (detailed):"
        echo "------------------------------"
        gdb -batch -ex "file $BINARY" -ex "disassemble main" -ex "quit" 2>/dev/null | tee $OUTPUT_DIR/gdb_main.asm
        echo "GDB output saved to: $OUTPUT_DIR/gdb_main.asm"
        echo ""
    fi
    
    # Symbol table
    if command -v nm >/dev/null 2>&1; then
        echo "4. Symbol Table:"
        echo "---------------"
        nm $BINARY | tee $OUTPUT_DIR/symbols.txt
        echo "Symbols saved to: $OUTPUT_DIR/symbols.txt"
        echo ""
    fi
    
    # Binary sections
    if command -v readelf >/dev/null 2>&1; then
        echo "5. Binary Sections:"
        echo "------------------"
        readelf -S $BINARY | tee $OUTPUT_DIR/sections.txt
        echo "Sections saved to: $OUTPUT_DIR/sections.txt"
        echo ""
    fi
    
    # Hex dump of key sections
    if command -v xxd >/dev/null 2>&1; then
        echo "6. Hex Dump (first 512 bytes):"
        echo "------------------------------"
        xxd -l 512 $BINARY | tee $OUTPUT_DIR/hexdump.txt
        echo "Hex dump saved to: $OUTPUT_DIR/hexdump.txt"
        echo ""
    elif command -v hexdump >/dev/null 2>&1; then
        echo "6. Hex Dump (first 512 bytes):"
        echo "------------------------------"
        hexdump -C -n 512 $BINARY | tee $OUTPUT_DIR/hexdump.txt
        echo "Hex dump saved to: $OUTPUT_DIR/hexdump.txt"
        echo ""
    fi
    
    # Strings in binary
    if command -v strings >/dev/null 2>&1; then
        echo "7. Strings in Binary:"
        echo "--------------------"
        strings $BINARY | tee $OUTPUT_DIR/strings.txt
        echo "Strings saved to: $OUTPUT_DIR/strings.txt"
        echo ""
    fi
}

# Summary and instructions
show_summary() {
    echo ""
    echo "Analysis Complete!"
    echo "=================="
    
    echo "Output files:"
    if [ -d "$OUTPUT_DIR" ]; then
        for file in $OUTPUT_DIR/*; do
            if [ -f "$file" ]; then
                echo "  $(basename $file): $(wc -l < $file 2>/dev/null || echo '?') lines"
            fi
        done
    fi
    
    echo ""
    echo "Key files for CWE-787 analysis:"
    echo "==============================="
    echo "• objdump_main.asm - Main function assembly"
    echo "• gdb_main.asm     - Detailed GDB disassembly"
    echo "• hexdump.txt      - Raw binary data"
    echo "• sections.txt     - Binary structure"
    
    echo ""
    echo "Manual commands for future use:"
    echo "==============================="
    echo "Quick disasm:    objdump -d $BINARY"
    echo "Main function:   objdump -d $BINARY | grep -A 20 '_main:'"
    echo "GDB analysis:    gdb $BINARY -ex 'disas main' -ex 'quit'"
    echo "Hex view:        xxd $BINARY | head"
    echo "Binary info:     readelf -h $BINARY"
    
    echo ""
    echo "Look for CWE-787 patterns:"
    echo "=========================="
    echo "• mov instructions with offsets beyond buffer bounds"
    echo "• Array indexing without bounds checking"
    echo "• Stack pointer modifications"
    echo "• Memory access patterns in assembly"
}

# Main execution
main() {
    if ! check_tools; then
        exit 1
    fi
    
    echo ""
    if ! create_binary; then
        exit 1
    fi
    
    disassemble
    show_summary
}

# Run the script
main "$@"