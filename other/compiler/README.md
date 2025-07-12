# Satellite Communication CWE-787 Analysis

## Overview

This project demonstrates CWE-787 vulnerabilities in satellite communication systems using the CCSDS (Consultative Committee for Space Data Systems) protocol - the actual standard used by NASA, ESA, and other space agencies.

## Files

- `satellite_ground_station.c` - Vulnerable server implementing satellite ground station
- `satellite_exploit_client.c` - Client that demonstrates exploitation of vulnerabilities
- `compile.sh` - Compilation script for macOS/Linux
- `README.md` - This documentation

## Compilation

### Quick Start
```bash
./compile.sh
```

### Manual Compilation
```bash
# Standard builds
clang -g -O0 -fno-stack-protector -D_FORTIFY_SOURCE=0 -o satellite_ground_station satellite_ground_station.c
clang -g -O0 -fno-stack-protector -D_FORTIFY_SOURCE=0 -o satellite_exploit_client satellite_exploit_client.c

# AddressSanitizer builds (for detailed crash analysis)
clang -g -O0 -fsanitize=address -fsanitize=undefined -o satellite_ground_station_asan satellite_ground_station.c
clang -g -O0 -fsanitize=address -fsanitize=undefined -o satellite_exploit_client_asan satellite_exploit_client.c
```

## Usage

### Basic Execution
```bash
# Terminal 1: Run server
./bin/satellite_ground_station

# Terminal 2: Run client
./bin/satellite_exploit_client
```

### Analysis with AddressSanitizer
```bash
# Terminal 1: Run server with memory error detection
./bin/satellite_ground_station_asan

# Terminal 2: Run client
./bin/satellite_exploit_client_asan
```

## CWE-787 Vulnerabilities Demonstrated

### 1. Attitude Control Buffer Overflow
- **Location**: `process_attitude_control()` function
- **Vulnerability**: `memcpy()` without bounds checking
- **Impact**: Stack buffer overflow in attitude calculations

### 2. Orbit Maneuver sprintf Overflow
- **Location**: `process_orbit_maneuver()` function
- **Vulnerability**: `sprintf()` without size limits
- **Impact**: Stack buffer overflow in trajectory logging

### 3. Payload Control Multiple Overflows
- **Location**: `process_payload_control()` function
- **Vulnerability**: Multiple `memcpy()` and `strcpy()` calls
- **Impact**: Stack buffer overflows in filter and coordinate buffers

### 4. Data Download sprintf Chain Overflow
- **Location**: `process_data_download()` function
- **Vulnerability**: `sprintf()` with multiple unvalidated inputs
- **Impact**: Stack buffer overflow in download queue

### 5. Array Bounds Violations
- **Location**: Multiple functions
- **Vulnerability**: Using user input as array indices
- **Impact**: Out-of-bounds memory access

## Analysis Tools

### Generated Files
- `bin/satellite_ground_station_disasm.txt` - Objdump disassembly
- `bin/satellite_ground_station_symbols.txt` - Symbol table
- `bin/satellite_ground_station_otool.txt` - macOS otool analysis (if available)

### GDB Analysis
```bash
# Start server in GDB
gdb ./bin/satellite_ground_station

# Set breakpoints on vulnerable functions
(gdb) break process_attitude_control
(gdb) break process_orbit_maneuver
(gdb) break process_payload_control
(gdb) break process_data_download

# Run and analyze
(gdb) run
# In another terminal, run the client
# Back in GDB, examine memory at breakpoints
(gdb) x/32wx $rsp
(gdb) x/16gx $rbp-0x50
```

## Real-World Context

This demonstrates vulnerabilities in:
- **CCSDS Protocol Implementation** - Real satellite communication standard
- **Ground Station Software** - Mission control systems
- **Satellite Command Processing** - Critical spacecraft operations

### Attack Scenarios
1. **Malicious Ground Station** - Rogue operator sends crafted commands
2. **Compromised Ground Network** - Network intrusion leading to command injection
3. **RF Packet Injection** - Over-the-air attack on satellite communications

## Platform Notes

### macOS
- Uses `clang` compiler with `-arch x86_64` flag
- Compiles Intel x86-64 binaries for better tool compatibility
- Generates `otool` analysis files
- AddressSanitizer works natively
- Compatible with objdump and angr analysis tools

### Linux
- Uses `gcc` or `clang`
- Standard objdump analysis
- AddressSanitizer available

### Docker Alternative
If you need consistent cross-platform compilation:
```bash
# Create Dockerfile
FROM ubuntu:latest
RUN apt-get update && apt-get install -y gcc build-essential gdb
COPY . /workspace
WORKDIR /workspace
RUN ./compile.sh
```

## Security Research Notes

**⚠️ WARNING**: This code contains intentional vulnerabilities for educational purposes only.

### Defensive Uses
- Understanding buffer overflow vulnerabilities
- Testing security tools and detection systems
- Developing secure coding practices
- Security research and education

### Mitigation Strategies
1. **Input Validation** - Always validate packet lengths and field sizes
2. **Bounds Checking** - Use safe string functions (`strncpy`, `snprintf`)
3. **Stack Protection** - Enable compiler stack protection
4. **Address Sanitizer** - Use during development and testing
5. **Fuzzing** - Test with malformed inputs

## Expected Behavior

### Normal Operation
- Server starts on port 2023
- Client connects and sends satellite commands
- Server processes commands and sends acknowledgments

### Exploit Demonstration
- Client sends malformed packets with oversized fields
- Server experiences buffer overflows
- Memory corruption leads to crashes or undefined behavior
- AddressSanitizer detects and reports memory errors

## Contributing

This is educational/research code. When modifying:
1. Maintain clear vulnerability documentation
2. Add appropriate security warnings
3. Test with both standard and sanitizer builds
4. Update analysis documentation

## License

Educational use only. Not for production systems.