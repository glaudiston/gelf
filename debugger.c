#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

unsigned print_current_address(pid_t child)
{
	struct user_regs_struct regs;
	unsigned data = ptrace(PTRACE_GETREGS, child, 0, &regs);
	if ( data != 0 ) {
		perror("unexpected getregs");
		printf("data: %08x", data);
	}
	return regs.rip;
}

unsigned get_first_byte(unsigned data)
{
	return data << 24 >> 24;
}

int main(int argc, char *argv[])
{
    pid_t child;
    int status;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <executable>\n", argv[0]);
        exit(1);
    }

    child = fork(); fflush(stdout);
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, NULL);
        execvp(argv[1], &argv[1]);
    } else {
	unsigned addr = 0;
	unsigned straddr;
	while ( 1 ) {
		waitpid(child, &status, 0);
		if (WIFEXITED(status)) {
		    printf("exited\n");
		    exit(0);
		}
		addr = print_current_address(child);
		unsigned data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0);
		// MOV RAX SYS_WRITE
		if ( ( get_first_byte(data) ) == 0xb8 ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
			printf("%08x: MOV RAX %x\n", addr, data);fflush(stdout);
		}
		// MOV RDI STDOUT
		else if ( ( get_first_byte(data) ) == 0xbf ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
			printf("%08x: MOV RDI %x\n", addr, data); fflush(stdout);
		}
		// MOV RSI STR ADDR
		else if ( get_first_byte(data) == 0xbe ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
			printf("%08x: MOV RSI %x\n", addr, data);
			straddr = data;
		}
		// MOV RDX SIZE
		else if ( get_first_byte(data) == 0xba ) {
			data = ptrace(PTRACE_PEEKTEXT, child,
				(void*)addr+1, 0);
			printf("%08x: MOV RDX %i", addr, data); fflush(stdout);
			int strsize = (int)data;
			char* c = malloc(sizeof(char) * strsize + 4);
			int i = 0;
			for ( i = 0; (i * 4) < strsize; i++ ){
				data = ptrace(PTRACE_PEEKTEXT, child,
					(void*)straddr + i * 4, 0);
				memcpy(&c[i * 4], &data, 4);
			}
			c[strsize] = 0;
			// string
			printf("{%s}\n", c);fflush(stdout);
			free(c);
		}
		// JMP SHORT
		else if ( get_first_byte(data) == 0xeb )
		{
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
			data = get_first_byte(data);
			printf("%08x: JMP SHORT (%i) %x\n", addr, (signed char)data, data);
		}
		// JMP NEAR
		else if ( get_first_byte(data) == 0xe9 )
		{
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
			printf("%08x: JMP NEAR (%d) %x (%i)\n", addr, (signed int)data, data, sizeof(signed int) * 8);
		}
		// SYSCALL
		else if ( ( data << 16 >> 16 ) == 0x050f )
		{
			printf("%08x: syscall\n", addr);fflush(stdout);
		}
		else
		{
			printf("%08x: unknown data: %08x, %x \n", addr, data, data << 16 >> 16);fflush(stdout);
		}
		data = ptrace(PTRACE_SINGLESTEP, child, 0, NULL);
		if ( data != 0 ) {
			printf("SINGLE STEP EXPECTED 0 but was %08x\n", data);
			perror("single step error");fflush(stderr);
		}
	}
    }

    return 0;
}
