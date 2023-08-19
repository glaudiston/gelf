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

void printRegValue(unsigned long r)
{
	if ( r < 0 ) {
		printf(" = 0x%lx(%li|%lu)\n", r, r, r);
	} else {
		printf(" = 0x%lx(%lu)\n", r, r);
	}
}

#define TRUE 1
#define RAX 0
#define RCX 1
#define RDX 2
#define RBX 3
#define RSP 4
#define RBP 5
#define RSI 6
#define RDI 7
#define R8 8 
#define R9 9 
#define R10 10
#define R11 11
#define R12 12
#define R13 13
#define R14 14
#define R15 15
void trace_watcher(pid_t child)
{
	char filename[256];
	int printNextData=0;
	int status;
	unsigned long addr = 0;
	unsigned long straddr;
	while ( 1 ) {
		waitpid(child, &status, 0);
		if (WIFEXITED(status)) {
		    printf("exited\n");
		    exit(0);
		}
		addr = print_current_address(child);
		if ( printNextData ) {
			switch (printNextData-1) {
				case R15:
					printRegValue(regs.r15); break;
				case R14:
					printRegValue(regs.r14); break;
				case R13:
					printRegValue(regs.r13); break;
				case R12:
					printRegValue(regs.r12); break;
				case R11:
					printRegValue(regs.r11); break;
				case R10:
					printRegValue(regs.r10); break;
				case R9:
					printRegValue(regs.r9); break;
				case R8:
					printRegValue(regs.r8); break;
				case RSI:
					printRegValue(regs.rsi); break;
				case RSP:
					printRegValue(regs.rsp); break;
				case RBX:
					printRegValue(regs.rbx); break;
				case RDX:
					printRegValue(regs.rdx); break;
				case RCX:
					printRegValue(regs.rcx); break;
				default: // RAX
					printRegValue(regs.rax); break;
			}
			printNextData=0;
		}
		unsigned data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0);
		// data is composed of 4 bytes in a little-endian, so:
		unsigned char first_byte = data << 24 >> 24;
		unsigned char second_byte = data << 16 >> 24;
		unsigned char thirdbyte=data << 8 >> 24;
		unsigned char fourthbyte=data >> 24;

		switch (first_byte) {
			case 0x48:
				if ( second_byte == 0xb8 ) {
					long unsigned rax = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
					printf("%016lx: mov 0x%lx, %%rax # %li\n", addr, rax, rax);fflush(stdout);
				}
				if ( second_byte == 0x8b ) {
					if ( thirdbyte == 0x36 ) {
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
						printf("%016lx: mov %%rsi, %%rsi # (resolve address)\n", addr);fflush(stdout);
						printNextData = TRUE + RSI;
					}
					if ( thirdbyte == 0x12 ){
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
						printf("%016lx: mov %%rdx %%rdx # (resolve address)\n", addr);fflush(stdout);
					}
				}
				if ( second_byte == 0xc7 ){
					if ( thirdbyte == 0xc0 ) {
						unsigned rax = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
						printf("%016lx: mov 0x%x, %%rAX\n", addr, rax);fflush(stdout);
					}
					else if ( thirdbyte == 0xc7 ) {
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
						printf("%016lx: mov 0x%x, %%rdi\n", addr, data);fflush(stdout);
					}
					else if ( thirdbyte == 0xc2 ) {
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
						printf("%016lx: mov 0x%x, %%rdx\n", addr, data);fflush(stdout);
					}
				}
				if ( second_byte == 0x89 ) {
					if ( thirdbyte == 0x24 ) {
						if ( fourthbyte == 0x25 ) {
							printf("%016lx: mov %%rsp, 0x%llx\n", addr, regs.rsp);
						} else {
							printf("%016lx: ??", addr);
						}
					}
					if ( thirdbyte == 0xc7 ) {
						printf("%016lx: mov %%rax, %%rdi # 0x%llx(%lli)\n", addr, regs.rax, regs.rax); fflush(stdout);
					}
					else if ( thirdbyte == 0xc6 ) {
						printf("%016lx: mov %%rax %%rsi # 0x%llx(%lli)\n", addr,regs.rax, regs.rax);fflush(stdout);
					}
					else if ( thirdbyte == 0xf2 ) {
						printf("%016lx: mov %%rsi, %%rdx # 0x%llx(%lli)\n", addr, regs.rsi, regs.rsi); fflush(stdout);
					}
					else if ( thirdbyte == 0xe6) {
						printf("%016lx: mov %%rsp, %%rsi\n", addr); fflush(stdout);
					}
					else if ( thirdbyte == 0xe2 ) {
						printf("%016lx: mov %%rsp, %%rdx\n", addr); fflush(stdout);
					}
					else if ( thirdbyte == 0xf0 ) {
						printf("%016lx: mov %%rsi, %%rax # %llx(%lli)\n", addr, regs.rsi, regs.rsi); fflush(stdout);
					} else {
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
						printf("%016lx: mov 0x%x, %%rsi # %i\n", addr, data, data);
						straddr = data;
					}
				}
				else if ( second_byte == 0xbf ) {
					unsigned rdi = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
					printf("%016lx: mov 0x%x, %%rdi # %i\n", addr, rdi, rdi); fflush(stdout);
				}
				else if ( second_byte == 0xbe ) {
					long rsi = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
					printf("%016lx: mov 0x%lx, %%rsi # %li\n", addr, rsi, rsi);
				}
				else if ( second_byte == 0xba ) {
					data = ptrace(PTRACE_PEEKTEXT, child,
						(void*)addr+2, 0);
					printf("%016lx: mov 0x%016x, %%rdx", addr, data); fflush(stdout);
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
						printf("%016lx: xor %%rsi, %%rsi\n", addr);fflush(stdout);
					} else {
						printf("%016lx: ??? xor %%rsi, %%rsi\n", addr);fflush(stdout);
					}
				}
				else if ( second_byte == 0x29 ) {
					if ( thirdbyte == 0xf2 ) {
						// SUB RDX RSI // RESULT IN RDX
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
						printf("%016lx: SUB RDX RSI (result in RDX)\n", addr);fflush(stdout);
					} else {
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
						printf("%016lx: ??? SUB RDX RSI (result in RDX)\n", addr);fflush(stdout);
					}
				}
				else if ( second_byte == 0x83 ) {
					data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
					long r=data;
					if ( thirdbyte == 0xc6 ) {
						// ADD RSI HEXVALUE ??
						printf("%016lx: add 0x%x, %%rsi\n", addr, data >> 24 ); fflush(stdout);
					} else if ( r == 0xc2000000 ) {
						printf("%016lx: add 0x%x, %%rdx\n", addr, data >> 24 ); fflush(stdout);
					} else if ( thirdbyte == 0xf8 ) {
						printf("%016lx: cmp %%rax, %i\n", addr, (char)r); fflush(stdout);
					} else if ( thirdbyte == 0xfe ) {
						printf("%016lx: cmp %%rsi, %i\n", addr, (char)r ); fflush(stdout);
					} else {
						printf("%016lx: cmp ?? %i\n", addr, (char)r); fflush(stdout);
					}
				}
				break;
			case 0x49:
				if ( second_byte == 0xb8 ) {
					data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
					printf("%016lx: mov %x, %%r8\n", addr, data);fflush(stdout);
				}
				else if ( second_byte == 0xb9 ) {
					data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
					printf("%016lx: mov %x, %%r9\n", addr, data);fflush(stdout);
				}
				else if ( second_byte == 0xba ) {
					data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
					printf("%016lx: mov %x, %%r10\n", addr, data);fflush(stdout);
				}
				if ( second_byte == 0x89 ) {
					if ( thirdbyte == 0xc0 ) {
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
						printf("%016lx: mov %%rax, %%r8 # 0x%llx(%lli)\n", addr,regs.rax,regs.rax);fflush(stdout);
					}
					if ( thirdbyte == 0xc1 ) { // 0x4989c1
						data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
						printf("%016lx: mov %%rax, %%r9 # 0x%llx(%llx)\n", addr, regs.rax, regs.rax);fflush(stdout);
					}
				}
				break;
			case 0x4c:
				if ( second_byte == 0x89 ) {
					if ( thirdbyte == 0xc7 ) { // 0x4c89c7
						printf("%016lx: mov %%r8, %%rdi # 0x%llx(%lli)\n", addr, regs.r8, regs.r8); fflush(stdout);
					}
					else if ( thirdbyte == 0xc2 ) { // 0x4c89c7
						printf("%016lx: mov %%r8, %%rdx # 0x%llx(%lli)\n", addr, regs.r8, regs.r8); fflush(stdout);
					} else if (thirdbyte == 0xca ) {
						printf("%016lx: MOV %%r9, %%rdx # 0x%llx\n", addr, regs.r9); fflush(stdout);
					} else {
						printf("%016lx: ??? mov, %%r9, %%rdx\n", addr); fflush(stdout);
					}
				}
				break;
			case 0xb8:
				data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
				printf("%08lx: mov %x, %%eax\n", addr, data);fflush(stdout);
				break;
			case 0xba: // MOV eDX SIZE
				data = ptrace(PTRACE_PEEKTEXT, child,
					(void*)addr+1, 0);
				printf("%08lx: MOV %i, %%edx", addr, data); fflush(stdout);
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
				printf("%08lx: MOV %x, %%esi\n", addr, data);
				straddr = data;
				break;
			case 0xbf:
				data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
				printf("%08lx: MOV 0x%08x, %%edi\n", addr, data); fflush(stdout);
				break;
			default:
				// JNE
				if ( ( data << 16 >> 16 ) == 0xea83 ) {
					printf("%016lx: jne\n", addr);fflush(stdout);
				}
				// CMP RDX 00
				if ( ( data << 16 >> 16 ) == 0x850f ) {
					data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0) << 8;
					printf("%016lx: cmp rdx %x\n", addr, data);fflush(stdout);
				}
				// JG
				else if ( ( data << 16 >> 16 ) == 0x8f0f ) {
					data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0) << 8;
					int d = (data >> 8 + ( data << 8 >> 8 ));
					unsigned char instr_size=6;
					printf("%016lx: jg, %llx # jump %i bytes ahead\n", addr, instr_size + regs.rip + d, d);fflush(stdout);
				}
				// CALL
				else if ( first_byte == 0xe8 ) {
					printf("%016lx: call\n", addr); fflush(stdout);
				}
				// RET
				else if ( first_byte == 0xc3 ) {
					printf("%016lx: ret\n", addr); fflush(stdout);
				}
				// JMP SHORT
				else if ( first_byte == 0xeb )
				{
					data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
					printf("%08lx: jmp short (%i) %x\n", addr, first_byte, data);
				}
				// JMP NEAR
				else if ( first_byte == 0xe9 )
				{
					data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
					printf("%08lx: jmp near (%d) %x (%li)\n", addr, (signed int)data, data, sizeof(signed int) * 8);
				}
				// SYSCALL
				else if ( ( data << 16 >> 16 ) == 0x050f )
				{
					char syscall[512];
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
						sprintf((char*)&syscall, "open(%s)", filename);
					} else if ( regs.rax == SYS_READ ){
						char buff[256];
						peek_string(child, (void*)regs.rsi, buff);
						sprintf((char*)&syscall, "read(%lli, %llx, %lli)", regs.rdi, regs.rsi, regs.rdx);
					} else if ( regs.rax == SYS_WRITE ){
						char buff[256];
						peek_string(child, (void*)regs.rsi, buff);
						sprintf((char*)&syscall, "write(%lli, 0x%llx, %lli)", regs.rdi, regs.rsi, regs.rdx);
					} else if ( regs.rax == SYS_MMAP ){
						sprintf((char*)&syscall, "mmap(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx); # alocates %lli bytes using fd %lli", 
								regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9, regs.rsi, regs.r8);
					} else if ( regs.rax == SYS_STAT ){
						sprintf((char*)&syscall, "stat(%lli)",regs.rsi);
					} else if ( regs.rax == SYS_FSTAT ){
						sprintf((char*)&syscall, "fstat(%lli, 0x%016llx)",regs.rdi,regs.rsi);
					} else if ( regs.rax == SYS_EXIT ){
						sprintf((char*)&syscall, "exit(%lli)",regs.rdi);
					} else {
						printf("not implemented syscall for rax=%lli...\n",regs.rax);
					}
					printf("%016lx: syscall: %s", addr, syscall);fflush(stdout);
					printNextData = 1;
				}
				else
				{
					printf("%016lx: unknown data: %016x, %06x \n", addr, data, data << 8 >> 8);fflush(stdout);
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
