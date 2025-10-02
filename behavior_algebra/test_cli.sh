#!/bin/bash

# Comprehensive CLI Test Suite for Behavior Algebra Disassembler
# Tests all major functionality and edge cases

set -e  # Exit on any error

echo "=== BEHAVIOR ALGEBRA DISASSEMBLER CLI TEST SUITE ==="
echo "Starting comprehensive testing..."
echo

# Clean up previous test outputs
rm -f *.txt *.json
rm -rf test_outputs/

# Test data
DEMO_BINARY="data/demo_binary"
TINY_BINARY="data/tiny_minimal"
CASE_BINARY="data/caseSym"

echo "=== BASIC FUNCTIONALITY TESTS ==="

echo "1. Default behavior algebra generation (txt format):"
python3 disassembler.py $DEMO_BINARY --allow-objdump-fallback
echo "✓ Default behavior algebra test passed"
echo

echo "2. JSON CFG export only:"
python3 disassembler.py $DEMO_BINARY --format json --allow-objdump-fallback
echo "✓ JSON CFG export test passed"
echo

echo "3. Both formats simultaneously:"
python3 disassembler.py $DEMO_BINARY --format both --allow-objdump-fallback
echo "✓ Both formats test passed"
echo

echo "4. Custom output paths:"
python3 disassembler.py $TINY_BINARY --format both \
    --output my_algebra.txt --cfg-output my_cfg.json --allow-objdump-fallback
echo "✓ Custom output paths test passed"
echo

echo "5. Export directory specification:"
mkdir -p test_outputs
python3 disassembler.py $TINY_BINARY --format both --export-dir test_outputs --allow-objdump-fallback
echo "✓ Export directory test passed"
echo

echo "6. Disable behavior algebra:"
python3 disassembler.py $DEMO_BINARY --no-behavior-algebra --format json --allow-objdump-fallback
echo "✓ Disable behavior algebra test passed"
echo

echo "7. Address highlighting in CFG:"
python3 disassembler.py $DEMO_BINARY --format json --highlight "1000,1010,1020" \
    --output highlighted.json --allow-objdump-fallback
echo "✓ Address highlighting test passed"
echo

echo "=== ERROR HANDLING TESTS ==="

echo "8. Non-existent binary (should fail gracefully):"
if python3 disassembler.py /nonexistent/binary --allow-objdump-fallback 2>/dev/null; then
    echo "✗ Should have failed for non-existent binary"
    exit 1
else
    echo "✓ Non-existent binary error handling passed"
fi
echo

echo "9. Without objdump fallback (should fail gracefully):"
if python3 disassembler.py $DEMO_BINARY 2>/dev/null; then
    echo "✗ Should have failed without fallback"
    exit 1
else
    echo "✓ No fallback error handling passed"
fi
echo

echo "=== OUTPUT VALIDATION TESTS ==="

echo "10. Validate behavior algebra format:"
if grep -q "B([0-9a-f]*) =" my_algebra.txt; then
    echo "✓ Behavior algebra format validation passed"
else
    echo "✗ Behavior algebra format validation failed"
    exit 1
fi
echo

echo "11. Validate JSON CFG structure:"
python3 -c "
import json
import sys
try:
    with open('my_cfg.json') as f:
        data = json.load(f)
    required_keys = ['nodes', 'edges', 'metadata']
    if all(key in data for key in required_keys):
        print('✓ JSON CFG structure validation passed')
    else:
        print('✗ JSON CFG missing required keys')
        sys.exit(1)
    if len(data['nodes']) > 0 and len(data['edges']) >= 0:
        print('✓ JSON CFG content validation passed')
    else:
        print('✗ JSON CFG content validation failed')
        sys.exit(1)
except Exception as e:
    print(f'✗ JSON CFG validation failed: {e}')
    sys.exit(1)
"
echo

echo "12. Validate address highlighting:"
python3 -c "
import json
import sys
try:
    with open('highlighted.json') as f:
        data = json.load(f)
    highlighted_addrs = data['metadata']['highlighted_addresses']
    if len(highlighted_addrs) == 3:
        print('✓ Address highlighting validation passed')
    else:
        print(f'✗ Expected 3 highlighted addresses, got {len(highlighted_addrs)}')
        sys.exit(1)
except Exception as e:
    print(f'✗ Address highlighting validation failed: {e}')
    sys.exit(1)
"
echo

echo "=== MULTIPLE BINARY COMPATIBILITY TESTS ==="

echo "13. Test multiple binary types:"
for binary in $DEMO_BINARY $TINY_BINARY $CASE_BINARY; do
    if [ -f "$binary" ]; then
        echo "Testing $binary..."
        python3 disassembler.py "$binary" --format txt --allow-objdump-fallback >/dev/null
        echo "✓ $binary processed successfully"
    else
        echo "⚠ $binary not found, skipping"
    fi
done
echo

echo "=== PYTHON API TESTS ==="

echo "14. Class-based API test:"
python3 -c "
import sys
sys.path.insert(0, '.')
from disassembler import DyninstDisassembler

try:
    d = DyninstDisassembler('$DEMO_BINARY', behavior_algebra=True, cfg_json=True, fallback_to_objdump=True)
    assert len(d.instructions) > 0, 'No instructions loaded'
    assert d.behavior_algebra is not None, 'No behavior algebra generated'
    assert d.cfg is not None, 'No CFG generated'
    print('✓ Class-based API test passed')
except Exception as e:
    print(f'✗ Class-based API test failed: {e}')
    sys.exit(1)
"
echo

echo "15. Export methods test:"
python3 -c "
import sys
import os
sys.path.insert(0, '.')
from disassembler import DyninstDisassembler

try:
    d = DyninstDisassembler('$DEMO_BINARY', behavior_algebra=True, cfg_json=True, fallback_to_objdump=True)
    results = d.run(behavior_algebra_path='api_test_algebra.txt', cfg_path='api_test_cfg.json')
    
    assert 'behavior_algebra' in results, 'Behavior algebra not in results'
    assert 'cfg_json' in results, 'CFG JSON not in results'
    assert os.path.exists('api_test_algebra.txt'), 'Behavior algebra file not created'
    assert os.path.exists('api_test_cfg.json'), 'CFG JSON file not created'
    print('✓ Export methods test passed')
except Exception as e:
    print(f'✗ Export methods test failed: {e}')
    sys.exit(1)
"
echo

echo "=== CLI HELP AND USAGE TESTS ==="

echo "16. Help command test:"
if python3 disassembler.py --help | grep -q "Disassemble binaries with Dyninst"; then
    echo "✓ Help command test passed"
else
    echo "✗ Help command test failed"
    exit 1
fi
echo

echo "17. Invalid arguments test:"
if python3 disassembler.py --invalid-arg 2>/dev/null; then
    echo "✗ Should have failed with invalid arguments"
    exit 1
else
    echo "✓ Invalid arguments test passed"
fi
echo

echo "=== PERFORMANCE AND STRESS TESTS ==="

echo "18. Large binary test (if available):"
if [ -f "$CASE_BINARY" ]; then
    echo "Testing large binary processing..."
    time python3 disassembler.py "$CASE_BINARY" --format txt --allow-objdump-fallback >/dev/null
    echo "✓ Large binary test completed"
else
    echo "⚠ Large binary not available, skipping stress test"
fi
echo

echo "=== CLEANUP ==="
echo "19. Cleanup test files:"
rm -f *.txt *.json
rm -rf test_outputs/
echo "✓ Cleanup completed"
echo

echo "=== ALL TESTS COMPLETED SUCCESSFULLY ==="
echo "✓ All $(echo '1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19' | wc -w) tests passed!"
echo "The behavior algebra disassembler is working correctly."