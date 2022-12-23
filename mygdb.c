

#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
    pid_t child;
    long addr;
    int status;

    if (argc < 3) {
        printf("Uso: %s <elf> <virtual address>\n", argv[0]);
        return 1;
    }

    addr = strtol(argv[2], NULL, 16);

    child = fork();
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        execl(argv[1], argv[1], NULL);
    } else {
        wait(&status);
        ptrace(PTRACE_SET_BREAKPOINT, child, (void *)addr, 0);
        ptrace(PTRACE_CONT, child, NULL, NULL);
        wait(&status);
        ptrace(PTRACE_CONT, child, NULL, NULL);
    }

    return 0;
}
