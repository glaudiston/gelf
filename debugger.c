#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

struct user_regs_struct regs;
unsigned print_current_address(pid_t child)
{
	unsigned data = ptrace(PTRACE_GETREGS, child, 0, &regs);
	if ( data != 0 ) {
		perror("unexpected getregs");
		printf("data: %016x", data);
	}
	return regs.rip;
}

unsigned get_first_byte(unsigned data)
{
	return data << 24 >> 24;
}

void peek_string(pid_t child, void *addr, char* out){
	int pos=0;
	int done=0;
	while(!done) {
		unsigned data = ptrace(PTRACE_PEEKTEXT, child, addr+pos, 0);
		sprintf(out+pos, "%c%c%c%c", data, data >> 8, data >> 16, data >> 24);
		if ( ((char)(data)) == 0
		|| ( ((char)(data >> 8)) == 0 )
		|| ( ((char)(data >> 16)) == 0 )
		|| ( ((char)(data >> 24)) == 0 )){
			done=1;
		} else {
			pos+=4;
		}
	}
}
int main(int argc, char *argv[])
{
    char filename[256];
    pid_t child;
    int status;
    int printNextData=0;

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
		if ( printNextData ) {
			printf(" = %i\n", regs.rax);
			printNextData=0;
		}
		unsigned data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0);
		// MOV RAX SYS_WRITE
		if ( ( get_first_byte(data) ) == 0xb8 ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
			printf("%08x: mov eAX %x\n", addr, data);fflush(stdout);
		}
		else if ( ( data << 16 >> 16 ) == 0xb848 ) {
			unsigned rax = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
			printf("%016x: mov 0x%x, %rAX\n", addr, rax);fflush(stdout);
		}
		else if ( ( data << 8 >> 8 ) == 0xc0c748 ) {
			unsigned rax = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
			printf("%016x: mov 0x%x, %rAX\n", addr, rax);fflush(stdout);
		}
		else if ( ( data << 8 >> 8 ) == 0xc7c748 ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
			printf("%016x: mov 0x%x, %rdi\n", addr, data);fflush(stdout);
		}
		else if ( ( data << 8 >> 8 ) == 0xc2c748 ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
			printf("%016x: mov 0x%x, %rdx\n", addr, data);fflush(stdout);
		}
		else if ( ( data << 8 >> 8 ) == 0xf63148 ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
			printf("%016x: xor %rsi, %rsi\n", addr, data);fflush(stdout);
		}
		else if ( ( data << 16 >> 16 ) == 0xb849 ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
			printf("%016x: MOV R8 %x\n", addr, data);fflush(stdout);
		}
		else if ( ( data << 16 >> 16 ) == 0xb949 ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
			printf("%016x: MOV R9 %x\n", addr, data);fflush(stdout);
		}
		else if ( ( data << 16 >> 16 ) == 0xba49 ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
			printf("%016x: MOV R10 %x\n", addr, data);fflush(stdout);
		}
		// MOV RDI STDOUT
		else if ( ( get_first_byte(data) ) == 0xbf ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
			printf("%08x: MOV eDI 0x%08x\n", addr, data); fflush(stdout);
		}
		else if ( ( data << 8 >> 8 ) == 0xc08949 ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
			printf("%016x: mov %rax %r8\n", addr);fflush(stdout);
		}
		else if ( ( data << 8 >> 8 ) == 0xc68948 ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
			printf("%016x: MOV %RAX %RSI\n", addr);fflush(stdout);
		}
		// MOV_RDX_RSI
		else if ( ( data << 8 >> 8 ) == 0xf28948 ) {
			printf("%016x: MOV %RSI, %RDX\n", addr); fflush(stdout);
		}
		// MOV RSP RSI
		else if ( ( data << 8 >> 8 ) == 0xe68948 ) {
			printf("%016x: MOV %RSP, %RSI\n", addr); fflush(stdout);
		}
		// MOV RSP RDX
		else if ( ( data << 8 >> 8 ) == 0xe28948 ) {
			printf("%016x: MOV %RSP, %RDX\n", addr); fflush(stdout);
		}
		// MOV RSI RSI
		else if ( ( data << 8 >> 8 ) == 0x368b48 ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
			printf("%016x: MOV RSI RSI (resolve address)\n", addr);fflush(stdout);
		}
		// MOV RDX RDX
		else if ( ( data << 8 >> 8 ) == 0x128b48 ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
			printf("%016x: MOV RDX RDX (resolve address)\n", addr);fflush(stdout);
		}
		// MOV RDI HEXVALUE
		else if ( ( data << 16 >> 16 ) == 0xbf48 ) {
			unsigned rdi = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
			printf("%016x: mov 0x%x, %rDI\n", addr, rdi); fflush(stdout);
		}
		// SUB RDX RSI // RESULT IN RDX
		else if ( ( data << 8 >> 8 ) == 0xf22948 ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
			printf("%016x: SUB RDX RSI (result in RDX)\n", addr);fflush(stdout);
		}
		// CMP RDX 00
		else if ( ( data << 16 >> 16 ) == 0x850f ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0) << 8;
			printf("%016x: CMP RDX %x\n", addr, data);fflush(stdout);
		}
		// JNE
		else if ( ( data << 16 >> 16 ) == 0xea83 ) {
			printf("%016x: JNE\n", addr);fflush(stdout);
		}
		// JG
		else if ( ( data << 16 >> 16 ) == 0x8f0f ) {
			printf("%016x: JG\n", addr);fflush(stdout);
		}
		// CALL
		else if ( ( get_first_byte(data) ) == 0xe8 ) {
			printf("%016x: CALL\n", addr); fflush(stdout);
		}
		// RET
		else if ( ( get_first_byte(data) ) == 0xc3 ) {
			printf("%016x: RET\n", addr); fflush(stdout);
		}
		// ADD RSI HEXVALUE ??
		else if ( ( data << 16 >> 16 ) == 0x8348 ) {
			long r=data >> 16 << 24;
			if ( r == 0xc6000000 ) {
				printf("%016x: ADD 0x%x, %RSI\n", addr, data >> 24 ); fflush(stdout);
			} else if ( r == 0xc2000000 ) {
				printf("%016x: ADD 0x%x, %RDX\n", addr, data >> 24 ); fflush(stdout);
			} else {
				printf("%016x: CMP 0x%x\n", addr, r); fflush(stdout);
			}
		}
		// MOV eSI STR ADDR
		else if ( get_first_byte(data) == 0xbe ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
			printf("%08x: MOV eSI %x\n", addr, data);
			straddr = data;
		}
		// MOV RSI STR ADDR
		else if ( ( data << 16 >> 16 ) == 0xbe48 ) {
			data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
			printf("%016x: MOV RSI 0x%016x\n", addr, data);
			straddr = data;
		}
		// MOV eDX SIZE
		else if ( get_first_byte(data) == 0xba ) {
			data = ptrace(PTRACE_PEEKTEXT, child,
				(void*)addr+1, 0);
			printf("%08x: MOV eDX %i", addr, data); fflush(stdout);
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
		else if ( ( data << 16 >> 16 ) == 0xba48 ) {
			data = ptrace(PTRACE_PEEKTEXT, child,
				(void*)addr+2, 0);
			printf("%016x: MOV RDX 0x%016x", addr, data); fflush(stdout);
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
			char syscall[255];
			syscall[0]=0;
			char SYS_WRITE=1;
			char SYS_OPEN=2;
			char SYS_MMAP=9;
			char SYS_EXIT=60;
			if ( regs.rax==SYS_OPEN ) {
				peek_string(child, (void*)regs.rdi, filename);
				sprintf(&syscall, "open(%s)", filename);
			} else if ( regs.rax == SYS_WRITE ){
				char buff[256];
				peek_string(child, (void*)regs.rsi, buff);
				sprintf(&syscall, "write(%i, %x, %i)", regs.rdi, regs.rsi, regs.rdx);
			} else if ( regs.rax == SYS_MMAP ){
				sprintf(&syscall, "mmap(...); #alocates %i bytes using fd %i", regs.rsi, regs.r8);
			} else if ( regs.rax == SYS_EXIT ){
				sprintf(&syscall, "exit(%i)",regs.rdi);
			} else {
				printf("not implemented syscall for rax=%i...\n",regs.rax);
			}
			printf("%016x: syscall: %s", addr, syscall);fflush(stdout);
			printNextData = 1;
		}
		else
		{
			printf("%016x: unknown data: %016x, %06x \n", addr, data, data << 8 >> 8);fflush(stdout);
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
