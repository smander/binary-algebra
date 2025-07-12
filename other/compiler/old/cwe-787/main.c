#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/*
 * CWE-787: Out-of-bounds Write Examples
 */

// Example 1: Classic Array Index Overflow (MITRE Example)
void example1_array_overflow() {
    printf("\n=== Example 1: Array Index Overflow ===\n");
    
    int id_sequence[3];
    id_sequence[0] = 123;
    id_sequence[1] = 234;
    id_sequence[2] = 345;
    
    // VULNERABILITY: Writing beyond array bounds
    printf("Writing to index 3 (out of bounds)...\n");
    id_sequence[3] = 456;  // CWE-787: Out-of-bounds write
    
    printf("Array contents: %d, %d, %d\n", id_sequence[0], id_sequence[1], id_sequence[2]);
    printf("Out-of-bounds value may have corrupted adjacent memory\n");
}

// Example 2: Buffer Overflow with strcpy
void example2_strcpy_overflow() {
    printf("\n=== Example 2: strcpy Buffer Overflow ===\n");
    
    char buffer[10];
    char *source = "This string is definitely longer than 10 characters";
    
    printf("Buffer size: 10 bytes\n");
    printf("Source string length: %zu bytes\n", strlen(source));
    printf("Copying source to buffer...\n");
    
    // VULNERABILITY: No bounds checking
    strcpy(buffer, source);  // CWE-787: Buffer overflow
    
    printf("Buffer (corrupted): %.20s\n", buffer);
}

// Example 3: Unsafe Memory Copy with Negative Size
void example3_memcpy_negative() {
    printf("\n=== Example 3: memcpy with Potential Negative Size ===\n");
    
    char destBuf[100];
    char srcBuf[200];
    
    // Initialize source buffer
    memset(srcBuf, 'A', sizeof(srcBuf) - 1);
    srcBuf[sizeof(srcBuf) - 1] = '\0';
    
    // Simulate function that could return -1
    int chunk_size = -1;  // Simulating error condition
    
    printf("Chunk size: %d\n", chunk_size);
    printf("Attempting memcpy with size calculation...\n");
    
    // VULNERABILITY: If chunk_size is -1, (chunk_size - 1) becomes -2
    // which when cast to size_t becomes a very large positive number
    if (chunk_size > 0) {
        memcpy(destBuf, srcBuf, (size_t)(chunk_size - 1));
    } else {
        printf("Detected negative chunk size - avoiding vulnerability\n");
        // In vulnerable code, this check might be missing:
        // memcpy(destBuf, srcBuf, (size_t)(chunk_size - 1));  // CWE-787
    }
}

// Example 4: Loop-based Buffer Overflow
void example4_loop_overflow() {
    printf("\n=== Example 4: Loop-based Buffer Overflow ===\n");
    
    char buffer[5];
    char input[] = "ABCDEFGHIJ";  // 10 characters
    
    printf("Buffer size: 5 bytes\n");
    printf("Input string: %s (length: %zu)\n", input, strlen(input));
    
    // VULNERABILITY: No bounds checking in loop
    printf("Copying with vulnerable loop...\n");
    for (int i = 0; i <= strlen(input); i++) {  // Note: <= instead of <
        if (i < 5) {
            buffer[i] = input[i];
        } else {
            printf("Would write '%c' at index %d (out of bounds)\n", input[i], i);
            // In vulnerable code: buffer[i] = input[i];  // CWE-787
        }
    }
    
    buffer[4] = '\0';  // Null terminate safely
    printf("Buffer contents: %s\n", buffer);
}

// Example 5: Off-by-One Error
void example5_off_by_one() {
    printf("\n=== Example 5: Off-by-One Error ===\n");
    
    char buffer[10];
    
    printf("Buffer allocated for 10 bytes\n");
    printf("Filling buffer with pattern...\n");
    
    // VULNERABILITY: Loop condition allows writing at index 10
    for (int i = 0; i <= 10; i++) {  // Should be i < 10
        if (i < 10) {
            buffer[i] = '0' + (i % 10);
        } else {
            printf("Would write at index %d (off-by-one error)\n", i);
            // In vulnerable code: buffer[i] = '0' + (i % 10);  // CWE-787
        }
    }
    
    buffer[9] = '\0';
    printf("Buffer contents: %s\n", buffer);
}

// Example 6: Pointer Arithmetic Overflow
void example6_pointer_overflow() {
    printf("\n=== Example 6: Pointer Arithmetic Overflow ===\n");
    
    char buffer[20];
    char *ptr = buffer;
    
    printf("Buffer size: 20 bytes\n");
    printf("Writing data using pointer arithmetic...\n");
    
    // VULNERABILITY: No bounds checking with pointer arithmetic
    for (int i = 0; i < 25; i++) {  // Intentionally goes beyond buffer
        if (ptr + i < buffer + sizeof(buffer)) {
            *(ptr + i) = 'X';
        } else {
            printf("Would write 'X' at offset %d (beyond buffer)\n", i);
            // In vulnerable code: *(ptr + i) = 'X';  // CWE-787
        }
    }
    
    buffer[19] = '\0';
    printf("Buffer contents: %.19s\n", buffer);
}

// Example 7: Format String with sprintf
void example7_sprintf_overflow() {
    printf("\n=== Example 7: sprintf Buffer Overflow ===\n");
    
    char buffer[20];
    char *format = "%s %s %s";
    char *arg1 = "This";
    char *arg2 = "is";
    char *arg3 = "a very long string that exceeds buffer";
    
    printf("Buffer size: 20 bytes\n");
    printf("Total string length would be: %zu bytes\n", 
           strlen(arg1) + strlen(arg2) + strlen(arg3) + 2);
    
    // Safe version with bounds checking
    int result = snprintf(buffer, sizeof(buffer), format, arg1, arg2, arg3);
    
    if (result >= sizeof(buffer)) {
        printf("String truncated - would have caused overflow with sprintf\n");
        printf("Needed %d bytes, had %zu bytes\n", result, sizeof(buffer));
    }
    
    printf("Buffer contents: %s\n", buffer);
    
    // In vulnerable code:
    // sprintf(buffer, format, arg1, arg2, arg3);  // CWE-787: No bounds checking
}

// Safe alternative implementations
void demonstrate_safe_alternatives() {
    printf("\n=== Safe Alternative Implementations ===\n");
    
    // Safe string copying
    char dest[10];
    char *src = "Long source string";
    
    strncpy(dest, src, sizeof(dest) - 1);
    dest[sizeof(dest) - 1] = '\0';
    printf("Safe strncpy result: %s\n", dest);
    
    // Safe memory copying with bounds check
    char dest2[5];
    char src2[] = "ABCDEFGH";
    size_t copy_size = sizeof(src2) < sizeof(dest2) ? sizeof(src2) : sizeof(dest2) - 1;
    
    memcpy(dest2, src2, copy_size);
    dest2[copy_size] = '\0';
    printf("Safe memcpy result: %s\n", dest2);
}

int main() {
    printf("CWE-787: Out-of-bounds Write Vulnerability Examples\n");
    printf("==================================================\n");
    printf("WARNING: These examples demonstrate security vulnerabilities\n");
    printf("for educational purposes. Do not use patterns in production!\n");
    
    example1_array_overflow();
    example2_strcpy_overflow();
    example3_memcpy_negative();
    example4_loop_overflow();
    example5_off_by_one();
    example6_pointer_overflow();
    example7_sprintf_overflow();
    
    demonstrate_safe_alternatives();
    
    printf("\n=== Key Mitigation Strategies ===\n");
    printf("1. Always validate input sizes\n");
    printf("2. Use safe string functions (strncpy, snprintf, etc.)\n");
    printf("3. Implement bounds checking in loops\n");
    printf("4. Use compiler protections (stack canaries, ASLR)\n");
    printf("5. Consider memory-safe languages for new projects\n");
    printf("6. Use static analysis tools\n");
    printf("7. Perform thorough testing with edge cases\n");
    
    return 0;
}