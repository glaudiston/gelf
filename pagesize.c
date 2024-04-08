#include <stdio.h>
#include <unistd.h>

int main() {
    long page_size = sysconf(_SC_PAGESIZE);
    printf("%ld", page_size);

    return 0;
}
