#!/bin/bash

# Shell script wrapper for disassembly with comprehensive checks
echo "CWE-787 Disassembler with Fallbacks"
echo "==================================="

PYTHON_SCRIPT="angr_disasm.py"
BINARY="simple_dynamic"
OUTPUT_DIR="disasm_output"

# Check if Python 3 is available
check_python() {
    if ! command -v python3 >/dev/null 2>&1; then
        echo "Error: python3 not found"
        echo "Install Python 3: https://python.org/downloads/"
        return 1
    fi
    echo "✓ Python 3: $(python3 --version)"
    return 0
}

# Check if pip is available
check_pip() {
    if ! command -v pip3 >/dev/null 2>&1; then
        echo "Warning: pip3 not found"
        echo "Install pip: python3 -m ensurepip --upgrade"
        return 1
    fi
    echo "✓ pip3 available"
    return 0
}

# Check if angr is installed
check_angr() {
    python3 -c "import angr" 2>/dev/null
    if [ $? -ne 0 ]; then
        echo "✗ angr not installed"
        return 1
    fi
    echo "✓ angr available"
    return 0
}

# Install angr automatically
install_angr() {
    echo "Attempting to install angr..."
    
    # Try pip install
    if check_pip; then
        echo "Installing angr via pip3..."
        pip3 install angr
        if [ $? -eq 0 ]; then
            echo "✓ angr installed successfully"
            return 0
        fi
    fi
    
    # Try conda if available
    if command -v conda >/dev/null 2>&1; then
        echo "Trying conda install..."
        conda install -c conda-forge angr -y
        if [ $? -eq 0 ]; then
            echo "✓ angr installed via conda"
            return 0
        fi
    fi
    
    echo "✗ Failed to install angr automatically"
    return 1
}

# Check for alternative disassemblers
check_alternatives() {
    echo ""
    echo "Checking for alternative disassemblers..."
    
    ALTERNATIVES_FOUND=0
    
    if command -v objdump >/dev/null 2>&1; then
        echo "✓ objdump available"
        ALTERNATIVES_FOUND=1
    fi
    
    if command -v gdb >/dev/null 2>&1; then
        echo "✓ gdb available"
        ALTERNATIVES_FOUND=1
    fi
    
    if command -v readelf >/dev/null 2>&1; then
        echo "✓ readelf available"
        ALTERNATIVES_FOUND=1
    fi
    
    if command -v xxd >/dev/null 2>&1; then
        echo "✓ xxd available"
        ALTERNATIVES_FOUND=1
    fi
    
    if command -v hexdump >/dev/null 2>&1; then
        echo "✓ hexdump available"
        ALTERNATIVES_FOUND=1
    fi
    
    return $ALTERNATIVES_FOUND
}

# Fallback disassembly using system tools
fallback_disasm() {
    echo ""
    echo "Using fallback disassemblers..."
    echo "=============================="
    
    if [ ! -f "$BINARY" ]; then
        echo "No binary found, creating one..."
        if [ -f "simple.c" ]; then
            gcc -O0 -fno-stack-protector simple.c -o $BINARY 2>/dev/null
        else
            echo "No source file found either"
            return 1
        fi
    fi
    
    mkdir -p $OUTPUT_DIR
    
    # objdump disassembly
    if command -v objdump >/dev/null 2>&1; then
        echo "1. objdump disassembly:"
        echo "-----------------------"
        objdump -d $BINARY > $OUTPUT_DIR/objdump.asm
        echo "Saved to: $OUTPUT_DIR/objdump.asm"
        echo "Lines: $(wc -l < $OUTPUT_DIR/objdump.asm)"
        echo ""
        echo "Main function preview:"
        objdump -d $BINARY | grep -A 20 "<main>:" || objdump -d $BINARY | head -30
        echo ""
    fi
    
    # GDB disassembly
    if command -v gdb >/dev/null 2>&1; then
        echo "2. GDB disassembly of main:"
        echo "---------------------------"
        echo "disassemble main" | gdb -batch -ex "file $BINARY" -ex "disassemble main" -ex "quit" 2>/dev/null | tee $OUTPUT_DIR/gdb_main.asm
        echo "Saved to: $OUTPUT_DIR/gdb_main.asm"
        echo ""
    fi
    
    # Binary analysis
    if command -v readelf >/dev/null 2>&1; then
        echo "3. Binary sections:"
        echo "-------------------"
        readelf -S $BINARY | tee $OUTPUT_DIR/sections.txt
        echo ""
    fi
    
    # Hex dump of main
    if command -v xxd >/dev/null 2>&1; then
        echo "4. Hex dump (first 256 bytes):"
        echo "-------------------------------"
        xxd -l 256 $BINARY | tee $OUTPUT_DIR/hexdump.txt
        echo ""
    fi
}

# Main execution flow
main() {
    # Step 1: Check basic dependencies
    echo "Step 1: Checking dependencies..."
    echo "================================"
    
    if ! check_python; then
        echo "Cannot proceed without Python 3"
        exit 1
    fi
    
    # Step 2: Try to get angr working
    echo ""
    echo "Step 2: Checking angr..."
    echo "======================="
    
    ANGR_AVAILABLE=0
    if check_angr; then
        ANGR_AVAILABLE=1
    else
        echo ""
        read -p "Try to install angr automatically? (y/n): " -n 1 -r
        echo ""
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            if install_angr && check_angr; then
                ANGR_AVAILABLE=1
            fi
        fi
    fi
    
    # Step 3: Check alternatives if angr not available
    if [ $ANGR_AVAILABLE -eq 0 ]; then
        check_alternatives
        if [ $? -eq 0 ]; then
            echo "No alternative tools found either"
            echo "Install build tools first:"
            echo "  macOS: xcode-select --install"
            echo "  Ubuntu: sudo apt install build-essential gdb"
            exit 1
        fi
    fi
    
    # Step 4: Ensure we have a binary
    echo ""
    echo "Step 3: Preparing binary..."
    echo "=========================="
    
    if [ ! -f "$BINARY" ]; then
        echo "Creating test binary..."
        if [ -f "simple.c" ]; then
            gcc -O0 -fno-stack-protector simple.c -o $BINARY
            if [ $? -ne 0 ]; then
                echo "Failed to compile test binary"
                exit 1
            fi
        else
            echo "No source file found"
            exit 1
        fi
    fi
    
    echo "✓ Binary: $BINARY ($(ls -lh $BINARY | awk '{print $5}'))"
    
    # Step 5: Run analysis
    echo ""
    echo "Step 4: Running analysis..."
    echo "=========================="
    
    if [ $ANGR_AVAILABLE -eq 1 ]; then
        echo "Using angr analysis:"
        echo "-------------------"
        
        # Run different analysis modes
        echo "1. Main function only (minimal output):"
        python3 $PYTHON_SCRIPT $BINARY $OUTPUT_DIR/main_only.asm
        echo ""
        
        echo "2. Full binary analysis:"
        python3 $PYTHON_SCRIPT $BINARY $OUTPUT_DIR/full_binary.asm --full
        echo ""
        
        echo "3. Quick preview:"
        python3 $PYTHON_SCRIPT $BINARY | head -30
        
    else
        echo "Using fallback tools:"
        echo "--------------------"
        fallback_disasm
    fi
    
    # Step 6: Summary
    echo ""
    echo "Step 5: Results summary..."
    echo "========================="
    
    echo "Output files in $OUTPUT_DIR/:"
    ls -la $OUTPUT_DIR/ 2>/dev/null || echo "No output directory created"
    
    echo ""
    echo "File sizes:"
    for file in $OUTPUT_DIR/*.asm $OUTPUT_DIR/*.txt; do
        if [ -f "$file" ]; then
            echo "$(basename $file): $(wc -l < $file) lines"
        fi
    done
    
    echo ""
    echo "Usage for future runs:"
    echo "====================="
    if [ $ANGR_AVAILABLE -eq 1 ]; then
        echo "Angr main only:  python3 $PYTHON_SCRIPT $BINARY"
        echo "Angr full:       python3 $PYTHON_SCRIPT $BINARY output.asm --full"
    fi
    echo "objdump:         objdump -d $BINARY"
    echo "GDB:             gdb $BINARY -ex 'disas main' -ex 'quit'"
}

# Run main function
main "$@"