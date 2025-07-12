#include <stdio.h>

int main() {
    // CWE-787: Array overflow
    int buf[3] = {1, 2, 3};
    buf[3] = 4;  // Out-of-bounds write
    
    // CWE-787: Buffer overflow  
    char str[4];
    str[0] = 'A'; str[1] = 'B'; str[2] = 'C'; str[3] = 'D'; str[4] = 'E';  // Overflow
    
    printf("Done\n");
    return 0;
}