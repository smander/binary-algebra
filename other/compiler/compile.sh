#!/bin/bash

# Satellite Communication CWE-787 Compilation Script
# For macOS with appropriate compiler flags

echo "=== Satellite Communication CWE-787 Compilation ==="
echo "Target Platform: macOS"
echo "Target Architecture: Intel x86-64 (for objdump/angr compatibility)"
echo "Compiler: clang (Apple's GCC frontend)"
echo ""

# Create output directory
mkdir -p bin

# Compile flags for vulnerability research
# Force Intel x86-64 architecture for better compatibility with analysis tools
CFLAGS="-g -O0 -fno-stack-protector -D_FORTIFY_SOURCE=0 -Wall -Wextra -arch x86_64"
LDFLAGS="-arch x86_64"

# For AddressSanitizer builds (optional)
ASAN_FLAGS="-fsanitize=address -fsanitize=undefined"

echo "=== Compiling Satellite Ground Station Server ==="
echo "Flags: $CFLAGS"

# Standard vulnerable build
clang $CFLAGS -o bin/satellite_ground_station satellite_ground_station.c $LDFLAGS
if [ $? -eq 0 ]; then
    echo "✓ satellite_ground_station compiled successfully"
else
    echo "✗ satellite_ground_station compilation failed"
    exit 1
fi

echo ""
echo "=== Compiling Satellite Exploit Client ==="

# Standard build
clang $CFLAGS -o bin/satellite_exploit_client satellite_exploit_client.c $LDFLAGS
if [ $? -eq 0 ]; then
    echo "✓ satellite_exploit_client compiled successfully"
else
    echo "✗ satellite_exploit_client compilation failed"
    exit 1
fi

echo ""
echo "=== Optional: AddressSanitizer Builds ==="
echo "These builds will help detect memory errors during execution"

# AddressSanitizer build for detailed crash analysis
clang $CFLAGS $ASAN_FLAGS -o bin/satellite_ground_station_asan satellite_ground_station.c $LDFLAGS
if [ $? -eq 0 ]; then
    echo "✓ satellite_ground_station_asan compiled successfully"
else
    echo "✗ satellite_ground_station_asan compilation failed"
fi

clang $CFLAGS $ASAN_FLAGS -o bin/satellite_exploit_client_asan satellite_exploit_client.c $LDFLAGS
if [ $? -eq 0 ]; then
    echo "✓ satellite_exploit_client_asan compiled successfully"
else
    echo "✗ satellite_exploit_client_asan compilation failed"
fi

echo ""
echo "=== Generating Analysis Files ==="

# Check architecture
echo "Checking compiled architecture..."
file bin/satellite_ground_station

# Generate objdump for analysis (Intel x86-64 compatible)
echo "Generating objdump disassembly..."
objdump -d bin/satellite_ground_station > bin/satellite_ground_station_disasm.txt
objdump -t bin/satellite_ground_station > bin/satellite_ground_station_symbols.txt

if command -v otool &> /dev/null; then
    echo "Generating macOS-specific otool analysis..."
    otool -tv bin/satellite_ground_station > bin/satellite_ground_station_otool.txt
fi

# Generate readelf-style info for compatibility
echo "Generating ELF-style headers..."
otool -h bin/satellite_ground_station > bin/satellite_ground_station_headers.txt

echo ""
echo "=== Compilation Summary ==="
echo "Standard builds:"
echo "  - bin/satellite_ground_station"
echo "  - bin/satellite_exploit_client"
echo ""
echo "AddressSanitizer builds:"
echo "  - bin/satellite_ground_station_asan"
echo "  - bin/satellite_exploit_client_asan"
echo ""
echo "Analysis files:"
echo "  - bin/satellite_ground_station_disasm.txt (objdump disassembly)"
echo "  - bin/satellite_ground_station_symbols.txt (symbol table)"
echo "  - bin/satellite_ground_station_headers.txt (Mach-O headers)"
if command -v otool &> /dev/null; then
    echo "  - bin/satellite_ground_station_otool.txt (macOS otool)"
fi
echo ""

# Set executable permissions
chmod +x bin/satellite_ground_station
chmod +x bin/satellite_exploit_client

if [ -f bin/satellite_ground_station_asan ]; then
    chmod +x bin/satellite_ground_station_asan
fi

if [ -f bin/satellite_exploit_client_asan ]; then
    chmod +x bin/satellite_exploit_client_asan
fi

echo "=== Usage Instructions ==="
echo "1. Run server: ./bin/satellite_ground_station"
echo "2. Run client: ./bin/satellite_exploit_client"
echo ""
echo "For detailed crash analysis:"
echo "1. Run server: ./bin/satellite_ground_station_asan"
echo "2. Run client: ./bin/satellite_exploit_client_asan"
echo ""
echo "=== Compilation Complete ==="