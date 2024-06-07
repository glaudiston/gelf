#include "debugger.h"

#define BUFF_SIZE 256
void get_registers(pid_t pid, void* regs)
{
	unsigned data = ptrace(PTRACE_GETREGS, pid, NULL, regs);
	if ( data != 0 ) {
		perror("unexpected getregs");
		printf("data: %016x", data);
	}
}

char escaped_byte[5];
char* escape_byte(unsigned char b){
	if (b==0x20 || b>32 && b<127){
		escaped_byte[0]=b;
		escaped_byte[1]=0;
		return escaped_byte;
	}
	sprintf(escaped_byte, "\\x%02x", b);
	return escaped_byte;
}
void peek_string_null(pid_t child, void *addr, char* out, unsigned char stop_on_null)
{
	if (addr == 0)
		return;
	int done=0;
	int pos=0;
	size_t l=0;
	int i=0;
	size_t sizeBefore=BUFF_SIZE/3;
	size_t lastAllocSize=BUFF_SIZE;
	size_t newSize = 0;
	char ** data;
	char escaped_data[33]; // escaped are bytes like "\x00", so 4 bytes * 8 + 1 for null byte
	out[pos]=0;
	while(!done) {
		data = (char**) ptrace(PTRACE_PEEKTEXT, child, addr+pos, 0);
		if ( data == (char**)0xffffffffffffffff )
			break;
		if ( pos+8+1 > lastAllocSize ) {
			newSize = lastAllocSize + sizeBefore; // Fibonacci like size growth
			out = realloc(out, newSize);
			sizeBefore = lastAllocSize;
			lastAllocSize = newSize;
		}
		escaped_data[0]=0;
		for (i=0;i<8;i++){
			char c=*((char*)&data+i);
			if ( c==0 && stop_on_null ){
				sprintf(out,"%s%s", out, escaped_data);
				return;
			}
			sprintf(escaped_data,"%s%s", escaped_data, escape_byte(c));
		}
		sprintf(out,"%s%s", out, escaped_data);
		if (strlen((const char *)&data) < 8){
			break;
		}
		pos+=8;
	}
}
// extract and escape strings
void peek_string(pid_t child, void *addr, char* out){
	peek_string_null(child,addr,out, false);
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
int running_forks = 1;
struct report_values {

};

void run_next_instruction(pid_t pid, instruction_info *ptr_parsed_instruction)
{
	ptr_parsed_instruction->asm_code[0]=0;
	ptr_parsed_instruction->print_request_size=0;
	unsigned long data = ptrace(PTRACE_SINGLESTEP, pid, 0, NULL);		// execute next instruction
	if ( data != 0 ) {
		printf("SINGLE STEP EXPECTED 0 but was %08x\n", data);
		perror("single step error");fflush(stderr);
	}
}

void printMemoryValue(pid_t child, unsigned long r, int deep)
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
	printMemoryValue(child, v, deep+1);
	char * buff = malloc(BUFF_SIZE);
	peek_string(child, (void*)r, buff); // str?
	buff[BUFF_SIZE]=0;
	printf(" H(0x%lx) == S(\"%s\") %s", r, buff, lastbyte);
	free(buff);
}

struct {
	unsigned char step;
	unsigned char breakpoint[32];
} user_request = {
	.step=false
};

void interactive_help(){
	printf("\n\
	?,help\n\
		show this help\n\
	s\n\
		step next instruction\n\
	c\n\
		continue execution\n\
	b address\n\
		set breakpoint at target address. eg: b 10078\n\
	p r\n\
		print the register value. eg: p rax\n\
	ctrl-r,arrow up/down\n\
		search prompt history\n\
	ctrl-d\n\
		quit\n\
	\n\
	\n");
}

char * history_file=".gelf-debugger-history";
void interact_user(pid_t pid, void * regs)
{
	char previous_input[256];
	while (true){
		char prompt[50];
		char color_reset[16]="\e[0m";
		if (!cmd_options.show_colors){
			color_reset[0]=0;
		}
		sprintf(prompt,"%s > ", color_reset);
		char * user_input = readline(prompt);
		if (user_input == NULL){
			fprintf(stderr,"input closed.\n");
			exit(2);
		}
		if (strlen(user_input) == 0){
			continue;
		}
		if (strcmp(previous_input,user_input) != 0){
			add_history(user_input);
		}
		sprintf(previous_input, "%s", user_input);
		if (strcmp(user_input,"?")==0 || strcmp(user_input,"help")==0){
			interactive_help();
			continue;
		}
		int i = write_history(history_file);
		if (i != 0){
			perror("Failed to write history file: ");
		}
		if (strcmp(user_input,"s") == 0) {
			//printf("step next;\n");fflush(stdout);
			user_request.step=true;
			break;
		}
		if (strcmp(user_input,"c") == 0) {
			user_request.step=false;
			break;
		}
		if (strncmp(user_input, "b ", 2) == 0) {
			sprintf(user_request.breakpoint,&user_input[2]);
			printf("breakpoint set to 0x%s. use \"c\" to continue until hit the breakpoint\n:", &user_input[2]);
			continue;
		}
		arch_interact_user(pid, regs, user_input);
	}
}

void trace_watcher(pid_t pid)
{
	if (cmd_options.interactive_mode){
		if (access(history_file, R_OK) == -1) {
			fclose(fopen(history_file,"w+"));
		}
		using_history();
		read_history(history_file);
		user_request.step=true;
	}
	char filename[256];
	instruction_info ptr_parsed_instruction = {
		.print_request_size=0,
	};
	int status;
	int once_set=0;
	unsigned long int ic=0;
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
		unsigned char prompt_user=true;
		prompt_user=prompt_user && user_request.step;
		char s_cur_addr[16];
		get_current_address((char*)&s_cur_addr, &regs);
		unsigned char breakpoint_hit=strcmp(s_cur_addr, user_request.breakpoint) == 0;
		prompt_user=prompt_user || breakpoint_hit;
		prompt_user=prompt_user && cmd_options.interactive_mode;
		ptr_parsed_instruction = parse_next_instruction(pid, regs);
		print_next_instruction(pid, ic, regs, &ptr_parsed_instruction);
		if (prompt_user){
			if (breakpoint_hit){
				printf("breakpoint hit 0x%s\n", user_request.breakpoint);
			}
			interact_user(pid, &regs);
		}
		run_next_instruction(pid, &ptr_parsed_instruction);
		ic++;
		print_previous_instruction_trace(pid, ic, regs, &ptr_parsed_instruction);
	}
}

void print_usage(char * command_name){
	fprintf(stderr, "\n\
Usage: %s <executable>\n\
	\n\
	--help\n\
		Show this text\n\
	--no-colors\n\
		do not print terminal color bytes\n\
	-i,--interactive\n\
		prompt user for commands, useful to set breakpoints and check registers and memory values. While in prompt use \"help\" or \"?\" for instructions\n\
	--binary-tips\n\
		show bit values for known composed bytes\n\
\n\
This app was developed by Glaudiston Gomes da Silva, while digging into Gelf development.\n\
See: github.com/glaudiston/gelf\n\
	\n", command_name);
}

void parse_options(int argc, char *argv[]){
	if (argc < 2){
		print_usage(argv[0]);
		exit(1);
	}
	int i=0;
	for (i=1;i<argc;i++){
		if ( strcmp(argv[i], "--help" ) == 0) {
			print_usage(argv[0]);
			exit(1);
		}
		if ( strcmp(argv[i], "--binary-tips" ) == 0 ) {
			cmd_options.binary_tips=true;
			continue;
		}
		if ( strcmp(argv[i], "--no-colors" ) == 0 ) {
			cmd_options.show_colors=false;
			continue;
		}
		if ( strcmp(argv[i], "--interactive") == 0 || strcmp(argv[i], "-i") == 0 ) {
			cmd_options.interactive_mode = true;
			continue;
		}
		cmd_options.cmd_index=i;
		break;
	}
	if (cmd_options.cmd_index==0){
		char color_red[16]="\e[38;2;255;0;0m";
		char color_reset[16]="\e[0m";
		if (!cmd_options.show_colors){
			color_red[0]=0;
			color_reset[0]=0;
		}
		fprintf(stderr, "%sERROR%s: you need to provide the ELF file to debug", color_red, color_reset);
		print_usage(argv[0]);
		exit(1);
	}
}

int main(int argc, char *argv[])
{
	parse_options(argc, argv);
	pid_t child;

	char *filename=argv[cmd_options.cmd_index];
	cmd_options.filename = filename;
	if (access(filename, X_OK) == -1) {
		fprintf(stderr, "The file does not exists or does not have the execute permission: %s\n", filename);
		exit(1);
	}

	int pid = fork(); fflush(stdout);
	if (pid == 0) { // child thread
		ptrace(PTRACE_TRACEME, 0, 0, NULL); // this is the child thread, allow it to be traced.
		char ** env = &argv[cmd_options.cmd_index];
		execvp(filename, env); // replace this child forked thread with the binary to trace
	} else {
		// parent thread (pid has the child pid)
		trace_watcher(pid);
	}

	return 0;
}
