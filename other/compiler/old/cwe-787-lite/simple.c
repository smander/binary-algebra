// Simplest possible CWE-787 for analysis
int main() {
    char buf[4];
    buf[4] = 42;  // CWE-787: Out-of-bounds write
    return 0;
}