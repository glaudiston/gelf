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

void peek_string(pid_t child, void *addr, char* out){
	int pos=0;
	int done=0;
	while(!done) {
		unsigned data = ptrace(PTRACE_PEEKTEXT, child, addr+pos, 0);
		sprintf(out+pos, "%c%c%c%c", 
				data, 
				data >> 8, 
				data >> 16, 
				data >> 24);
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

void trace_watcher(pid_t child)
{
	char filename[256];
	int printNextData=0;
	int status;
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
			printf(" = %i,%lu(0x%016x)\n", regs.rax, regs.rax, regs.rax);
			printNextData=0;
		}
		unsigned data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0);
		// data is composed of 4 bytes in a little-endian, so:
		unsigned char first_byte = data << 24 >> 24;
		unsigned char second_byte = data << 16 >> 24;
		unsigned char thirdbyte=data << 8 >> 24;

		switch (first_byte) {
			case 0x48:
				if ( second_byte == 0xb8 ) {
					unsigned rax = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
					printf("%016x: mov %i, %rax\n", addr, rax);fflush(stdout);
				}
				if ( second_byte == 0x8b ) {
					if ( thirdbyte == 0x36 ) {
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
						printf("%016x: mov %rsi, %rsi # (resolve address)\n", addr);fflush(stdout);
					}
					if ( thirdbyte == 0x12 ){
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
						printf("%016x: mov %rdx %rdx # (resolve address)\n", addr);fflush(stdout);
					}
				}
				if ( second_byte == 0xc7 ){
					if ( thirdbyte == 0xc0 ) {
						unsigned rax = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
						printf("%016x: mov 0x%x, %rAX\n", addr, rax);fflush(stdout);
					}
					else if ( thirdbyte == 0xc7 ) {
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
						printf("%016x: mov 0x%x, %rdi\n", addr, data);fflush(stdout);
					}
					else if ( thirdbyte == 0xc2 ) {
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
						printf("%016x: mov 0x%x, %rdx\n", addr, data);fflush(stdout);
					}
				}
				if ( second_byte == 0x89 ) {
					if ( thirdbyte == 0xc7 ) {
						printf("%016x: mov %rax, %rdi # %x(%li)\n", addr, regs.rax, regs.rax); fflush(stdout);
					}
					else if ( thirdbyte == 0xc6 ) {
						printf("%016x: mov %rax %rsi # %x(%li)\n", addr,regs.rax, regs.rax);fflush(stdout);
					}
					else if ( thirdbyte == 0xf2 ) {
						printf("%016x: mov %rsi, %rdx # %x(%li)\n", addr, regs.rsi, regs.rsi); fflush(stdout);
					}
					else if ( thirdbyte == 0xe6) {
						printf("%016x: MOV %RSP, %RSI\n", addr); fflush(stdout);
					}
					else if ( thirdbyte == 0xe2 ) {
						printf("%016x: MOV %RSP, %RDX\n", addr); fflush(stdout);
					}
					else if ( thirdbyte == 0xf0 ) {
						printf("%016x: mov %rsi, %rax # %x(%li)\n", addr, regs.rsi, regs.rsi); fflush(stdout);
					} else {
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
						printf("%016x: mov %li, %rsi\n", addr, data);
						straddr = data;
					}
				}
				else if ( second_byte == 0xbf ) {
					unsigned rdi = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
					printf("%016x: mov 0x%x, %rdi # %li\n", addr, rdi, rdi); fflush(stdout);
				}
				else if ( second_byte == 0xbe ) {
					long rsi = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
					printf("%016x: mov 0x%x, %rsi # %li\n", addr, rsi, rsi);
				}
				else if ( second_byte == 0xba ) {
					data = ptrace(PTRACE_PEEKTEXT, child,
						(void*)addr+2, 0);
					printf("%016x: mov 0x%016x, %rdx", addr, data); fflush(stdout);
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
				else if ( second_byte == 0x31 ) {
				       	if ( thirdbyte == 0xf6 ) {
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
						printf("%016x: xor %rsi, %rsi\n", addr, data);fflush(stdout);
					} else {
						printf("%016x: ??? xor %rsi, %rsi\n", addr, data);fflush(stdout);
					}
				}
				else if ( second_byte == 0x29 ) {
					if ( thirdbyte == 0xf2 ) {
						// SUB RDX RSI // RESULT IN RDX
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
						printf("%016x: SUB RDX RSI (result in RDX)\n", addr);fflush(stdout);
					} else {
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
						printf("%016x: ??? SUB RDX RSI (result in RDX)\n", addr);fflush(stdout);
					}
				}
				else if ( second_byte == 0x83 ) {
					data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
					long r=data;
					if ( thirdbyte == 0xc6 ) {
						// ADD RSI HEXVALUE ??
						printf("%016x: ADD 0x%x, %RSI\n", addr, data >> 24 ); fflush(stdout);
					} else if ( r == 0xc2000000 ) {
						printf("%016x: ADD 0x%x, %RDX\n", addr, data >> 24 ); fflush(stdout);
					} else if ( thirdbyte == 0xf8 ) {
						printf("%016x: cmp %rax, %i\n", addr, (char)r); fflush(stdout);
					} else if ( thirdbyte == 0xfe ) {
						printf("%016x: cmp %rsi, %i\n", addr, (char)r ); fflush(stdout);
					} else {
						printf("%016x: CMP ?? %i\n", addr, (char)r); fflush(stdout);
					}
				}
				break;
			case 0x49:
				if ( second_byte == 0xb8 ) {
					data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
					printf("%016x: MOV R8 %x\n", addr, data);fflush(stdout);
				}
				else if ( second_byte == 0xb9 ) {
					data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
					printf("%016x: mov %x, %r9\n", addr, data);fflush(stdout);
				}
				else if ( second_byte == 0xba ) {
					data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
					printf("%016x: mov %x, %r10\n", addr, data);fflush(stdout);
				}
				if ( second_byte == 0x89 ) {
					if ( thirdbyte == 0xc0 ) {
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
						printf("%016x: mov %rax, %r8 # %x(%li)\n", addr,regs.rax,regs.rax);fflush(stdout);
					}
					if ( thirdbyte == 0xc1 ) { // 0x4989c1
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
						printf("%016x: mov %rax, %r9 # %x(%x)\n", addr, regs.rax, regs.rax);fflush(stdout);
					}
				}
				break;
			case 0x4c:
				if ( second_byte == 0x89 ) {
					if ( thirdbyte == 0xc7 ) { // 0x4c89c7
						printf("%016x: mov %r8, %rdi # %x(%li)\n", addr, regs.r8, regs.r8); fflush(stdout);
					}
					else if ( thirdbyte == 0xc2 ) { // 0x4c89c7
						printf("%016x: mov %r8, %rdx # %x(%li)\n", addr, regs.r8, regs.r8); fflush(stdout);
					} else if (thirdbyte == 0xca ) {
						printf("%016x: MOV %r9, %rdx\n", addr); fflush(stdout);
					} else {
						printf("%016x: ??? MOV %r9, %rdx\n", addr); fflush(stdout);
					}
				}
				break;
			case 0xb8:
				data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
				printf("%08x: mov eAX %x\n", addr, data);fflush(stdout);
				break;
			case 0xba: // MOV eDX SIZE
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
				break;
			case 0xbe: // 32 bit mov
				data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
				printf("%08x: MOV eSI %x\n", addr, data);
				straddr = data;
				break;
			case 0xbf:
				data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
				printf("%08x: MOV eDI 0x%08x\n", addr, data); fflush(stdout);
				break;
			default:
				// JNE
				if ( ( data << 16 >> 16 ) == 0xea83 ) {
					printf("%016x: JNE\n", addr);fflush(stdout);
				}
				// CMP RDX 00
				if ( ( data << 16 >> 16 ) == 0x850f ) {
					data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0) << 8;
					printf("%016x: CMP RDX %x\n", addr, data);fflush(stdout);
				}
				// JG
				else if ( ( data << 16 >> 16 ) == 0x8f0f ) {
					data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0) << 8;
					int d = (data >> 8 + ( data << 8 >> 8 ));
					unsigned char instr_size=6;
					printf("%016x: jg, %x # jump %i bytes ahead\n", addr, instr_size + regs.rip + d, d);fflush(stdout);
				}
				// CALL
				else if ( first_byte == 0xe8 ) {
					printf("%016x: CALL\n", addr); fflush(stdout);
				}
				// RET
				else if ( first_byte == 0xc3 ) {
					printf("%016x: RET\n", addr); fflush(stdout);
				}
				// JMP SHORT
				else if ( first_byte == 0xeb )
				{
					data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
					printf("%08x: JMP SHORT (%i) %x\n", addr, first_byte, data);
				}
				// JMP NEAR
				else if ( first_byte == 0xe9 )
				{
					data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
					printf("%08x: JMP NEAR (%d) %x (%i)\n", addr, (signed int)data, data, sizeof(signed int) * 8);
				}
				// SYSCALL
				else if ( ( data << 16 >> 16 ) == 0x050f )
				{
					char syscall[255];
					syscall[0]=0;
					char SYS_READ=0;
					char SYS_WRITE=1;
					char SYS_OPEN=2;
					char SYS_STAT=4;
					char SYS_FSTAT=5;
					char SYS_MMAP=9;
					char SYS_EXIT=60;
					if ( regs.rax==SYS_OPEN ) {
						peek_string(child, (void*)regs.rdi, filename);
						sprintf(&syscall, "open(%s)", filename);
					} else if ( regs.rax == SYS_READ ){
						char buff[256];
						peek_string(child, (void*)regs.rsi, buff);
						sprintf(&syscall, "read(%i, %x, %i)", regs.rdi, regs.rsi, regs.rdx);
					} else if ( regs.rax == SYS_WRITE ){
						char buff[256];
						peek_string(child, (void*)regs.rsi, buff);
						sprintf(&syscall, "write(%i, %x, %i)", regs.rdi, regs.rsi, regs.rdx);
					} else if ( regs.rax == SYS_MMAP ){
						sprintf(&syscall, "mmap(...); #alocates %i bytes using fd %i", regs.rsi, regs.r8);
					} else if ( regs.rax == SYS_STAT ){
						sprintf(&syscall, "stat(%i)",regs.rsi);
					} else if ( regs.rax == SYS_FSTAT ){
						sprintf(&syscall, "fstat(%i, 0x%016x)",regs.rdi,regs.rsi);
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
			break;
		}
		data = ptrace(PTRACE_SINGLESTEP, child, 0, NULL);
		if ( data != 0 ) {
			printf("SINGLE STEP EXPECTED 0 but was %08x\n", data);
			perror("single step error");fflush(stderr);
		}
	}
}

int main(int argc, char *argv[])
{
    pid_t child;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <executable>\n", argv[0]);
        exit(1);
    }

    child = fork(); fflush(stdout);
    if (child == 0) {
        ptrace(PTRACE_TRACEME, 0, 0, NULL);
        execvp(argv[1], &argv[1]);
    } else {
		trace_watcher(child);
    }

    return 0;
}
