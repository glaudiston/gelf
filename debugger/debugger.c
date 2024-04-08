#include "debugger.h"

#define BUFF_SIZE 256
void get_registers(pid_t child, void* regs)
{
	unsigned data = ptrace(PTRACE_GETREGS, child, NULL, regs);
	if ( data != 0 ) {
		perror("unexpected getregs");
		printf("data: %016x", data);
	}
}

void peek_string(pid_t child, void *addr, char* out){
	if ( addr == 0 )
		return;
	int done=0;
	int pos=0;
	size_t l=0;
	size_t sizeBefore=BUFF_SIZE/3;
	size_t lastAllocSize=BUFF_SIZE;
	size_t newSize = 0;
	char ** data;
	while(!done) {
		out[pos]=0;
		data = (char**) ptrace(PTRACE_PEEKTEXT, child, addr+pos, 0);
		if ( data == (char**)0xffffffffffffffff )
			break;
		if ( pos+8+1 > lastAllocSize ) {
			newSize = lastAllocSize + sizeBefore; // Fibonacci like size growth
			out = realloc(out, newSize);
			sizeBefore = lastAllocSize;
			lastAllocSize = newSize;
		}
		sprintf(out,"%s%s", out, &data);
		if (strlen((const char *)&data) < 8){
			break;
		}
		pos+=8;
	}
}

void peek_array(pid_t child, void *addr, char* out){
	if ( addr == 0L ){
		sprintf(out, "NULL");
		return;
	}
	int pos = 0;
	unsigned long int item;
	sprintf(out, "[");
	void* item_addr;
        while (1) {
		item_addr = addr+(pos * 8);
		item = ptrace(PTRACE_PEEKTEXT, child, item_addr, 0);
		if ( item == 0L )
			break;
		char item_text[BUFF_SIZE];
		peek_string(child, (void*)item, item_text);
		sprintf(out, "%s%s\"%s\"", out, pos == 0 ? "" : "," , item_text);
		pos++;
	}
	sprintf(out, "%s]", out);
}

void printRegValue(pid_t child, unsigned long r, int deep)
{
	char lastbyte[10];
	lastbyte[0]='\n';
	lastbyte[1]=0;
	if (deep){
		sprintf(lastbyte, "<%i|", deep);
	}
	unsigned long v = ptrace(PTRACE_PEEKTEXT, child, r, 0);
	if ( v == 0xffffffffffffffff ) { // not a valid memory location
		// numeric
		printf(" <%i| H(0x%lx) == I(%i) == S(\"%s...\") %s", deep+1, r, r, &r, lastbyte);
		return;
	}
	if ( v == r ){
		printf(" <%i points itself: 0x%lx\n", deep +1, v);
		return;
	}
	printRegValue(child, v, deep+1);
	char * buff = malloc(BUFF_SIZE);
	peek_string(child, (void*)r, buff); // str?
	buff[BUFF_SIZE]=0;
	printf(" H(0x%lx) == S(\"%s\") %s", r, buff, lastbyte);
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
		get_registers(pid, &regs);
		addr = regs.rip;
		printRelevantRegisters(pid, regs, printNextData);
		printf(ANSI_COLOR_GRAY "PID(%i)",pid);fflush(stdout);
		uint32_t data = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, 0);
		printNextData = get_bytecode_fn(pid, addr, data);
		if ( printNextData == -1 ) {
			// data is composed of 4 bytes in a little-endian, so:
			unsigned char first_byte = data << 24 >> 24;
			unsigned char second_byte = data << 16 >> 24;
			unsigned char thirdbyte=data << 8 >> 24;
			unsigned char fourthbyte=data >> 24;
			printf("%016lx: unknown data: %016x, [\\x%x\\x%x\\x%x\\x%x] \n", addr, data, first_byte, second_byte, thirdbyte, fourthbyte);fflush(stdout);
			printNextData = 0;
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

    char *filename=argv[1];
    if (access(filename, X_OK) == -1) {
	fprintf(stderr, "The file does not exists or does not have the execute permission: %s", filename);
	exit(1);
    }

    int child_pid = fork(); fflush(stdout);
    if (child_pid == 0) { // child thread
        ptrace(PTRACE_TRACEME, 0, 0, NULL); // this is the child thread, allow it to be traced.
	char ** env = &argv[1];
        execvp(filename, env); // replace this child forked thread with the binary to trace
    } else { // parent thread (pid has the child pid)
	trace_watcher(child_pid);
    }

    printf(ANSI_COLOR_RESET);
    return 0;
}
