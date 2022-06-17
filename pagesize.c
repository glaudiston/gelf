#include <unistd.h>

int main(void) { printf("%i", sysconf(_SC_PAGESIZE)); }
