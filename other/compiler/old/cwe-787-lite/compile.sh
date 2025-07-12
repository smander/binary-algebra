#!/bin/bash

echo "Ultra-Minimal CWE-787 Compilation"
echo "================================="

CC="gcc"
SOURCE="minimal.c"
OUTPUT="tiny"

# Try different approaches for minimal size
echo "Method 1: Static linking with size optimization"
$CC -static -Os -s -fno-stack-protector -no-pie $SOURCE -o ${OUTPUT}_static
STATIC_SIZE=$(ls -lh ${OUTPUT}_static 2>/dev/null | awk '{print $5}' || echo "failed")

echo "Method 2: Dynamic linking with aggressive optimization"  
$CC -Os -s -fno-stack-protector -no-pie -Wl,--gc-sections $SOURCE -o ${OUTPUT}_dynamic
DYNAMIC_SIZE=$(ls -lh ${OUTPUT}_dynamic 2>/dev/null | awk '{print $5}' || echo "failed")

echo "Method 3: Minimal flags"
$CC -O2 -s $SOURCE -o ${OUTPUT}_minimal
MINIMAL_SIZE=$(ls -lh ${OUTPUT}_minimal 2>/dev/null | awk '{print $5}' || echo "failed")

echo ""
echo "Size comparison:"
echo "==============="
echo "Static:  $STATIC_SIZE"
echo "Dynamic: $DYNAMIC_SIZE" 
echo "Minimal: $MINIMAL_SIZE"

echo ""
echo "Checking what's making it large..."
if [ -f ${OUTPUT}_dynamic ]; then
    echo "Sections in dynamic binary:"
    size ${OUTPUT}_dynamic
    echo ""
    echo "Dependencies:"
    ldd ${OUTPUT}_dynamic 2>/dev/null || otool -L ${OUTPUT}_dynamic 2>/dev/null || echo "No dependency info available"
fi

echo ""
echo "Test run:"
echo "========="
if [ -f ${OUTPUT}_minimal ]; then
    ./${OUTPUT}_minimal
else
    echo "No binary to test"
fi