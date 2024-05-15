#ifndef _debugger_h_
#define _debugger_h_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>
#include <readline/readline.h>
#include <readline/history.h>

#define false 0
#define true 1


struct {
	unsigned char help;		// show help and exit;
	unsigned char interactive_mode;
	unsigned char show_colors;	// use terminal color bytes
	unsigned char cmd_index;	// argv id of command to run
	unsigned char binary_tips;	// print binary on multi field bytes like REX and ModR/M
} cmd_options = {
	// default options
	.help=false,
	.show_colors=true,
	.binary_tips=false,
	.binary_tips=false,
	.interactive_mode=false,
	.cmd_index=0,
};
//Good ref https://www.felixcloutier.com/x86/
//
struct bytecode_return {
	int rv;
};
struct user_regs_struct regs;

extern int running_forks;
extern void printMemoryValue(pid_t child, unsigned long r, int deep);
extern void printInstructionTrace(pid_t pid, unsigned long int ic, struct user_regs_struct regs, int printNextData);
struct print_addr_request {
	unsigned char format[256];
	unsigned long addr;
};
typedef struct {
	unsigned long address;
	unsigned char bytes[8];
	unsigned char hexdump[20];
	unsigned char colored_hexdump[256];
	unsigned char asm_code[256];
	unsigned char comment[256];
	struct print_addr_request print_request[5];
	int print_request_size;
} instruction_info;

extern instruction_info parse_next_instruction(pid_t pid, struct user_regs_struct regs);
extern void print_next_instruction(pid_t pid, long int ic, struct user_regs_struct regs, instruction_info * ptr_parsed_instruction);
extern void copy_bytes(pid_t child, long unsigned addr, char * target, size_t size);
extern void peek_string(pid_t child, void *addr, char* out);
extern void peek_array(pid_t child, void *addr, char* out);
extern void arch_interact_user(pid_t pid, struct user_regs_struct * regs, char * user_input);
extern void get_current_address(char *s_curr_addr, struct user_regs_struct *regs);
#ifdef __aarch64__
#include "arch_aarch64.c"
#endif
#ifdef __x86_64__
#include "arch_x86-64.c"
#endif
#endif
