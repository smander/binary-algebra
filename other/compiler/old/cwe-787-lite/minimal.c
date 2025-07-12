// Ultra-minimal CWE-787 without printf
int main() {
    int buf[3];
    buf[3] = 42;  // CWE-787: Out-of-bounds write
    
    char str[4];
    str[4] = 'X'; // CWE-787: Buffer overflow
    
    return 0;
}