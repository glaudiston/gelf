#include "debugger.h"

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

// TODO this intent to print str on sys_write
// Make sense to call it on syscall.
void copy_bytes(pid_t child, long unsigned addr, char * target, size_t size)
{
	int i = 0;
	for ( i = 0; (i * 4) < size; i++ ){
		unsigned long data = ptrace(PTRACE_PEEKTEXT, child,
			(void*)addr + i * 4, 0);
		memcpy(&target[i * 4], &data, 4);
	}
}
int get_bytecode_fn(pid_t child, unsigned long addr, unsigned data)
{
	int l = sizeof(bytecodes_list) / sizeof(bytecodes_list[0]);
	unsigned char * mk; // bytecode map key
	int mkl=0; // bytecode map key length
	int i = 0;
	// data is composed of 4 bytes(32 bits) in a little-endian, so:
	unsigned char b1 = data << 24 >> 24;
	unsigned char b2 = data << 16 >> 24;
	unsigned char b3 = data << 8 >> 24;
	unsigned char b4 = data << 0 >> 24;
	unsigned char bytes[4] = {b1, b2, b3, b4};
	for (i=0; i<l; i++){
		struct bytecode_entry * entry = &bytecodes_list[i];
		mk = entry->k;
		mkl = entry->kl;
		if (strncmp(mk, bytes, mkl) == 0) {
			return entry->fn(child, addr);
		}
	}
	return -1;
}

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
		printNextData = get_bytecode_fn(child, addr, data);
		if ( printNextData == -1 ) {
			// data is composed of 4 bytes in a little-endian, so:
			unsigned char first_byte = data << 24 >> 24;
			unsigned char second_byte = data << 16 >> 24;
			unsigned char thirdbyte=data << 8 >> 24;
			unsigned char fourthbyte=data >> 24;
			switch (first_byte) {
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
						printf("%016lx: syscall: %s", addr, syscall);fflush(stdout);
						printNextData = 1;
					}
					else
					{
						printf("%016lx: unknown data: %016x, %06x \n", addr, data, data << 8 >> 8);fflush(stdout);
					}
				break;
			}
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
