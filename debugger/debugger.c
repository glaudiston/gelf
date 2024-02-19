#include "debugger.h"

#define BUFF_SIZE 256
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
	if ( addr == 0 )
		return;
	int done=0;
	int pos=0;
	out[0]=0;
	size_t l=0;
	size_t lastAllocSize=BUFF_SIZE;
	while(!done) {
		unsigned long data = ptrace(PTRACE_PEEKTEXT, child, addr+pos, 0);
		if ( data == 0xffffffffffffffff )
			break;
		int i;
		char c=1;
		for (i=64-8; i>8 && c > 0; i=i-8){
			c = data << i >> 56;
			if ( ++l > BUFF_SIZE ){
				// we need to manage realloc if needed
				if ( l > lastAllocSize ) {
					lastAllocSize = lastAllocSize + BUFF_SIZE;
					out=realloc(out, lastAllocSize);
				}
			}
			sprintf(out,"%s%c", out, c);
			if (c == 0){
				done=1;
				break;
			}
		}
		pos += 64 / 8;
	}
}

void printRegValue(pid_t child, unsigned long r)
{
	unsigned long v = ptrace(PTRACE_PEEKTEXT, child, (void*)r, 0);
	char * buff = malloc(BUFF_SIZE);
	peek_string(child, (void*)r, buff); // str?
	if (strlen(buff)>0){
		printf(" = 0x%lx == &(0x%x) == &(%s)\n", r, v, buff);
	} else {
		if ( r < 0 ) {
			printf(" = 0x%lx(%li|%lu) == &(0x%x)\n", r, r, r, v);
		} else {
			printf(" = 0x%lx(%lu) == &(0x%x)\n", r, r, v);
		}
	}
	free(buff);
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

int running_forks = 1;
void trace_watcher(pid_t pid)
{
	char filename[256];
	int printNextData=0;
	int status;
	unsigned long addr = 0;
	unsigned long straddr;
	unsigned long v;
	int once_set=0;
	while ( running_forks ) {
		waitpid(pid, &status, 0);
		if (!once_set){
			once_set++;
			long ptraceOptions = PTRACE_O_TRACEFORK | PTRACE_O_TRACECLONE | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEEXEC;
			ptrace(PTRACE_SETOPTIONS, pid, NULL, ptraceOptions); // allow trace forks and clones
		}
		if ( status>>8 == (SIGTRAP | (PTRACE_EVENT_EXEC<<8)) ){
			printf("execve\n");fflush(stdout);
			//ptrace(PTRACE_TRACEME, pid, 0, NULL); // this is the child thread, allow it to be traced.
			ptrace(PTRACE_CONT, pid, 0, NULL); // this is the child thread, allow it to be traced.
			//pid_t execve_pid;
			//ptrace(PTRACE_GETEVENTMSG, pid, NULL, &execve_pid);
			//printf("execve pid %u\n", execve_pid);fflush(stdout);
			continue;
		}
		if ( status>>8 == (SIGTRAP | (PTRACE_EVENT_VFORK<<8)) ){
			printf("vforked\n");fflush(stdout);
		}
		if ( status>>8 == (SIGTRAP | (PTRACE_EVENT_CLONE<<8)) ){
			printf("cloned\n");fflush(stdout);
		}
		if ( status>>8 == (SIGTRAP | (PTRACE_EVENT_FORK<<8)) ){
			pid_t forked_pid;
			ptrace(PTRACE_GETEVENTMSG, pid, NULL, &forked_pid);
			printf("forked %u\n", forked_pid);fflush(stdout);
			trace_watcher(forked_pid);
		}
		if (WIFEXITED(status)) {
		    printf("pid(%i) exited\n", pid);
		    running_forks--;
		    return;
		}
		addr = print_current_address(pid);
		if ( printNextData ) {
			switch (printNextData-1) {
				case R15:
					v = regs.r15; break;
				case R14:
					v = regs.r14; break;
				case R13:
					v = regs.r13; break;
				case R12:
					v = regs.r12; break;
				case R11:
					v = regs.r11; break;
				case R10:
					v = regs.r10; break;
				case R9:
					v = regs.r9; break;
				case R8:
					v = regs.r8; break;
				case RSI:
					v = regs.rsi; break;
				case RSP:
					v = regs.rsp; break;
				case RBX:
					v = regs.rbx; break;
				case RDX:
					v = regs.rdx; break;
				case RCX:
					v = regs.rcx; break;
				default: // RAX
					v = regs.rax; break;
			}
			printRegValue(pid, v);
			printNextData=0;
		}
		printf("PID(%i)",pid);fflush(stdout);
		uint32_t data = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, 0);
		printNextData = get_bytecode_fn(pid, addr, data);
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
					data = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr+1, 0);
					printf("%08lx: mov %x, %%eax\n", addr, data);fflush(stdout);
					break;
				case 0xba: // MOV eDX SIZE
					data = ptrace(PTRACE_PEEKTEXT, pid,
						(void*)addr+1, 0);
					printf("%08lx: MOV %i, %%edx", addr, data); fflush(stdout);
					int strsize = (int)data;
					char* c = malloc(sizeof(char) * strsize + 4);
					int i = 0;
					for ( i = 0; (i * 4) < strsize; i++ ){
						data = ptrace(PTRACE_PEEKTEXT, pid,
							(void*)straddr + i * 4, 0);
						memcpy(&c[i * 4], &data, 4);
					}
					c[strsize] = 0;
					// string
					printf("{%s}\n", c);fflush(stdout);
					free(c);
					break;
				case 0xbe: // 32 bit mov
					data = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr+1, 0);
					printf("%08lx: mov %x, %%esi\n", addr, data);
					straddr = data;
					break;
				case 0xbf:
					data = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr+1, 0);
					printf("%08lx: mov 0x%08x, %%edi\n", addr, data); fflush(stdout);
					break;
				default:
					// JNE
					if ( ( data << 16 >> 16 ) == 0xea83 ) {
						printf("%016lx: jne\n", addr);fflush(stdout);
					}
					// CMP RDX 00
					if ( ( data << 16 >> 16 ) == 0x850f ) {
						data = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr+3, 0) << 8;
						printf("%016lx: cmp rdx %x; #", addr, data);fflush(stdout);
					}
					// JG
					else if ( ( data << 16 >> 16 ) == 0x8f0f ) {
						data = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr+2, 0) << 8;
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
						data = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr+1, 0);
						printf("%08lx: jmp short (%i) %x\n", addr, first_byte, data);
					}
					// JMP NEAR
					else if ( first_byte == 0xe9 )
					{
						data = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr+1, 0);
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
		data = ptrace(PTRACE_SINGLESTEP, pid, 0, NULL);
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

    int child_pid = fork(); fflush(stdout);
    if (child_pid == 0) { // child thread
        ptrace(PTRACE_TRACEME, 0, 0, NULL); // this is the child thread, allow it to be traced.
        execvp(argv[1], &argv[1]); // replace this child forked thread with the binary to trace
    } else { // parent thread (pid has the child pid)
	trace_watcher(child_pid);
    }

    return 0;
}
