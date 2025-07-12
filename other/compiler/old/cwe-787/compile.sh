#!/bin/bash

# Compile script for CWE-787 examples targeting Intel x86 architecture
# Educational security vulnerability demonstration

echo "CWE-787 Out-of-bounds Write Examples - Compilation Script"
echo "========================================================="

# Create output directory if it doesn't exist
mkdir -p build

# Compiler settings
CC="gcc"
SOURCE="main.c"
OUTPUT_32="build/cwe787_examples_32bit"
OUTPUT_64="build/cwe787_examples_64bit"

# Compilation flags for vulnerability demonstration
VULN_FLAGS="-fno-stack-protector -z execstack -no-pie -fno-pie"
DEBUG_FLAGS="-g -O0"
WARNING_FLAGS="-Wall -Wextra"

echo "Detecting system architecture and available libraries..."
echo ""

# Function to check if 32-bit compilation is possible
check_32bit_support() {
    # Try a simple 32-bit compilation test
    echo "int main(){return 0;}" | $CC -m32 -x c - -o /tmp/test32 2>/dev/null
    local result=$?
    rm -f /tmp/test32
    return $result
}

# Function to compile 64-bit version
compile_64bit() {
    echo "Compiling 64-bit version..."
    echo "Command: $CC $DEBUG_FLAGS $VULN_FLAGS $WARNING_FLAGS $SOURCE -o $OUTPUT_64"
    
    $CC $DEBUG_FLAGS $VULN_FLAGS $WARNING_FLAGS $SOURCE -o $OUTPUT_64
    
    if [ $? -eq 0 ]; then
        echo "✓ 64-bit compilation successful!"
        file $OUTPUT_64
        return 0
    else
        echo "✗ 64-bit compilation failed!"
        return 1
    fi
}

# Function to compile 32-bit version
compile_32bit() {
    echo "Compiling 32-bit version..."
    echo "Command: $CC -m32 $DEBUG_FLAGS $VULN_FLAGS $WARNING_FLAGS $SOURCE -o $OUTPUT_32"
    
    $CC -m32 $DEBUG_FLAGS $VULN_FLAGS $WARNING_FLAGS $SOURCE -o $OUTPUT_32
    
    if [ $? -eq 0 ]; then
        echo "✓ 32-bit compilation successful!"
        file $OUTPUT_32
        return 0
    else
        echo "✗ 32-bit compilation failed!"
        return 1
    fi
}

# Main compilation logic
echo "Attempting 32-bit compilation first..."
if check_32bit_support; then
    echo "✓ 32-bit libraries detected"
    compile_32bit
    RESULT_32=$?
else
    echo "✗ 32-bit libraries not available"
    echo "To install 32-bit support:"
    echo "  Ubuntu/Debian: sudo apt-get install gcc-multilib libc6-dev-i386"
    echo "  CentOS/RHEL:   sudo yum install glibc-devel.i686"
    echo "  Arch:          sudo pacman -S lib32-glibc"
    echo "  macOS:         32-bit support removed in recent versions"
    RESULT_32=1
fi

echo ""
echo "Attempting 64-bit compilation..."
compile_64bit
RESULT_64=$?

echo ""
echo "Compilation Summary:"
echo "==================="

SUCCESS_COUNT=0
PREFERRED_BINARY=""

if [ $RESULT_32 -eq 0 ]; then
    echo "✓ 32-bit binary: $OUTPUT_32"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    PREFERRED_BINARY=$OUTPUT_32
fi

if [ $RESULT_64 -eq 0 ]; then
    echo "✓ 64-bit binary: $OUTPUT_64"
    SUCCESS_COUNT=$((SUCCESS_COUNT + 1))
    if [ -z "$PREFERRED_BINARY" ]; then
        PREFERRED_BINARY=$OUTPUT_64
    fi
fi

if [ $SUCCESS_COUNT -eq 0 ]; then
    echo "✗ All compilations failed!"
    echo ""
    echo "Troubleshooting:"
    echo "==============="
    echo "1. Install build essentials:"
    echo "   Ubuntu/Debian: sudo apt-get install gcc libc6-dev"
    echo "   macOS: xcode-select --install"
    echo ""
    echo "2. For 32-bit support:"
    echo "   Ubuntu/Debian: sudo apt-get install gcc-multilib libc6-dev-i386"
    echo ""
    echo "3. Try manual compilation:"
    echo "   gcc -g -O0 main.c -o cwe787_examples"
    exit 1
fi

echo ""
echo "Security Analysis of $PREFERRED_BINARY:"
echo "======================================="

# Check for security features (should be disabled for vulnerability demo)
if command -v checksec >/dev/null 2>&1; then
    checksec --file=$PREFERRED_BINARY
else
    echo "Install 'checksec' for detailed security analysis"
    echo "Checking basic protections..."
    
    if readelf -l $PREFERRED_BINARY 2>/dev/null | grep -q "GNU_STACK.*RWE"; then
        echo "✓ Stack is executable (for demonstration)"
    else
        echo "- Stack executable: Unknown"
    fi
    
    if ! readelf -d $PREFERRED_BINARY 2>/dev/null | grep -q "PIE"; then
        echo "✓ PIE disabled (for demonstration)"
    else
        echo "- PIE status: Unknown"
    fi
fi

echo ""
echo "Usage:"
echo "======"
if [ $RESULT_32 -eq 0 ]; then
    echo "Run 32-bit examples: ./$OUTPUT_32"
fi
if [ $RESULT_64 -eq 0 ]; then
    echo "Run 64-bit examples: ./$OUTPUT_64"
fi

echo ""
echo "For debugging:"
echo "gdb ./$PREFERRED_BINARY"
echo "valgrind --tool=memcheck ./$PREFERRED_BINARY"

echo ""
echo "WARNING: These binaries contain intentional vulnerabilities"
echo "for educational purposes. Do not deploy in production!"

echo ""
echo "Additional Analysis Tools:"
echo "========================="
echo "Static Analysis: cppcheck, clang-static-analyzer, splint"
echo "Dynamic Analysis: valgrind, AddressSanitizer (-fsanitize=address)"
echo "Fuzzing: AFL, libFuzzer, honggfuzz"
echo "Debugging: gdb, lldb"
echo "Binary Analysis: objdump, readelf, strings"