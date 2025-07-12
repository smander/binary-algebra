// Pure CWE-787 - minimal assembly
void _start() {
    // CWE-787: Stack buffer overflow
    char buf[4];
    buf[4] = 'E';  // Out-of-bounds write
    buf[5] = 'F';  // More overflow
    
    // CWE-787: Array index overflow  
    int arr[2];
    arr[2] = 42;   // Out-of-bounds write
    
    // Exit directly
    __asm__ volatile (
        "mov $60, %%rax\n"    // sys_exit
        "mov $0, %%rdi\n"     // exit code
        "syscall"
        :
        :
        : "rax", "rdi"
    );
}