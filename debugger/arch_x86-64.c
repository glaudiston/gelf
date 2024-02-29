#include "debugger.h"
int mov_v_eax(pid_t child, unsigned long addr)
{
	long unsigned rax = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
	printf("%016lx: mov 0x%lx, %%eax;" ANSI_COLOR_GRAY "\t# %li\n", addr, rax, rax);fflush(stdout);
	return 0;
}

int mov_v_rsi(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
	printf("%016lx: mov $0x%x, %%rsi" ANSI_COLOR_GRAY "\t#", addr, v); fflush(stdout);
	return TRUE + RSI;
}

// movzbq (%rdx), %rax
int mov__rdx__rax(pid_t child, unsigned long addr)
{
	printf("%016lx: movzbq (%rdx), %rax;" ANSI_COLOR_GRAY "\t# move to rax the resolved pointer value of RDX", addr);fflush(stdout);
	return TRUE + RDX;
}
int mov_rax_addr(pid_t child, unsigned long addr)
{
	unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+4, 0);
	printf("%016lx: mov %rax, 0x%lx;" ANSI_COLOR_GRAY "\t# ", addr, v);fflush(stdout);
	return TRUE + RAX;
}
int mov_addr_rax(pid_t child, unsigned long addr)
{
	printf("%016lx: movzbq (%rsi), %rax;" ANSI_COLOR_GRAY "\t# move to rax the resolved pointer value of RSI", addr);fflush(stdout);
	return TRUE + RSI;
}

int mov_addr_rdx(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0) >> 8 * 4;
	long unsigned vv = ptrace(PTRACE_PEEKTEXT, child, (void*)v, 0);
	char buff[256];
	peek_string(child, (void*)vv, buff); // str?
	if ( strlen(buff) > 0 ) {
		printf("%016lx: mov 0x%08lx, %%rdx;" ANSI_COLOR_GRAY "\t# (0x%lx == &(%s))\n", addr, v, vv, buff);fflush(stdout);
	} else {
		long unsigned vvv = ptrace(PTRACE_PEEKTEXT, child, (void*)vv, 0);
		printf("%016lx: mov 0x%08lx, %%rdx;" ANSI_COLOR_GRAY "\t# (0x%lx == &(%lx))\n", addr, v, vv, vvv);fflush(stdout);
	}
	return 0;
}
int mov_addr_rsi(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0) >> 8 * 4;
	long unsigned vv = ptrace(PTRACE_PEEKTEXT, child, (void*)v, 0);
	char buff[256];
	peek_string(child, (void*)vv, buff); // str?
	if ( strlen(buff) > 0 ) {
		printf("%016lx: mov 0x%08lx, %%rsi;" ANSI_COLOR_GRAY "\t# (0x%lx == &(%s))\n", addr, v, vv, buff);fflush(stdout);
	} else {
		long unsigned vvv = ptrace(PTRACE_PEEKTEXT, child, (void*)vv, 0);
		printf("%016lx: mov 0x%08lx, %%rsi;" ANSI_COLOR_GRAY "\t# (0x%lx == &(%lx))\n", addr, v, vv, vvv);fflush(stdout);
	}
	return 0;
}
int mov_addr_rdi(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0) >> 8 * 4;
	long unsigned vv = ptrace(PTRACE_PEEKTEXT, child, (void*)v, 0);
	char buff[256];
	peek_string(child, (void*)vv, buff); // str?
	if ( strlen(buff) > 0 ) {
		printf("%016lx: mov 0x%08lx, %%rdi;" ANSI_COLOR_GRAY "\t# (0x%lx == &(%s))\n", addr, v, vv, buff);fflush(stdout);
	} else {
		long unsigned vvv = ptrace(PTRACE_PEEKTEXT, child, (void*)vv, 0);
		printf("%016lx: mov 0x%08lx, %%rdi;" ANSI_COLOR_GRAY "\t# (0x%lx == &(%lx))\n", addr, v, vv, vvv);fflush(stdout);
	}
	return 0;
}

int mov_rsi_rsi(pid_t child, unsigned long addr)
{
	printf("%016lx: mov (%%rsi), %%rsi;" ANSI_COLOR_GRAY "\t# (resolve address)", addr);fflush(stdout);
	return TRUE + RSI;
}

int mov_rdx_rdx(pid_t child, unsigned long addr)
{
	printf("%016lx: mov (%%rdx), %%rdx;" ANSI_COLOR_GRAY "\t# (resolve address)", addr);fflush(stdout);
	return TRUE + RDX;
}

int mov_rax_rax(pid_t child, unsigned long addr)
{
	printf("%016lx: mov (%%rax), %%rax;" ANSI_COLOR_GRAY "\t# (resolve address)", addr);fflush(stdout);
	return TRUE + RAX;
}
int mov_rdi_rdi(pid_t child, unsigned long addr)
{
	printf("%016lx: mov (%%rdi), %%rdi;" ANSI_COLOR_GRAY "\t# (resolve address)", addr);fflush(stdout);
	return TRUE + RDI;
}

int mov_v_rax(pid_t child, unsigned long addr)
{
	long unsigned rax = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
	printf("%016lx: mov 0x%08lx, %%rax;" ANSI_COLOR_GRAY "\t#", addr, rax);fflush(stdout);
	return TRUE + RAX;
}
int mov_v4_rax(pid_t child, unsigned long addr)
{
	long unsigned rax = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
	printf("%016lx: mov 0x%04x, %%rax;" ANSI_COLOR_GRAY "\t#", addr, rax);fflush(stdout);
	return TRUE + RAX;
}
int mov_v4_rcx(pid_t child, unsigned long addr)
{
	long unsigned rcx = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
	printf("%016lx: mov 0x%04x, %%rcx;" ANSI_COLOR_GRAY "\t#", addr, rcx);fflush(stdout);
	return TRUE + RCX;
}
int mov_v_rdx(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
	printf("%016lx: mov 0x%lx, %%rdx\n", addr, v);fflush(stdout);
	return 0;
}
int mov_v8_rdi(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2,0);
	printf("%016lx: mov 0x%08lx, %%rdi;" ANSI_COLOR_GRAY "\t#", addr, v);
	return TRUE + RDI;
}
int mov_v_rdi_3(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
	printf("%016lx: mov 0x%lx, %%rdi;" ANSI_COLOR_GRAY "\t#", addr, v);fflush(stdout);
	return TRUE + RDI;
}
int mov_v_r8(pid_t child, unsigned long addr)
{
	unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
	printf("%016lx: mov 0x%x, %%r8\n", addr, v);fflush(stdout);
}
int mov_v_r9(pid_t child, unsigned long addr)
{
	unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
	printf("%016lx: mov 0x%x, %%r9\n", addr, v);fflush(stdout);
}
int mov_v_r10(pid_t child, unsigned long addr)
{
	unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
	printf("%016lx: mov 0x%x, %%r10\n", addr, v);fflush(stdout);
}
int mov_rdx_addr(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0) >> 8 * 4;
	long unsigned vv = ptrace(PTRACE_PEEKTEXT, child, (void*)regs.rdx, 0);
	printf("%016lx: mov %%rdx, 0x%08lx;" ANSI_COLOR_GRAY "\t# (*0x%016lx==%li)\n", addr, v, regs.rdx, vv);fflush(stdout);
	return 0;
}
int mov_rsp_addr(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr, 0) >> 8 * 4;
	long unsigned vv = ptrace(PTRACE_PEEKTEXT, child, (void*)regs.rsp, 0);
	printf("%016lx: mov %%rsp, 0x%08lx;" ANSI_COLOR_GRAY "\t# (*0x%016lx==%li)\n", addr, v, regs.rsp, vv);fflush(stdout);
	return 0;
}

int mov_rax_rsi(pid_t child, unsigned long addr)
{
	printf("%016lx: mov %%rax, %%rsi;", addr); fflush(stdout);
	return TRUE + RSI;
}

int mov_rax_rdi(pid_t child, unsigned long addr)
{
	printf("%016lx: mov %%rax, %%rdi;" ANSI_COLOR_GRAY "\t#", addr); fflush(stdout);
	return TRUE + RDI;
}
int mov_rsp_rsi(pid_t child, unsigned long addr)
{
	printf(ANSI_COLOR_GRAY "%016lx: " ANSI_COLOR_RESET "mov %%rsp, %%rsi;" ANSI_COLOR_GRAY "\t#", addr); fflush(stdout);
	return TRUE + RSP;
}
int mov_rsi_rdx(pid_t child, unsigned long addr)
{
	printf("%016lx: mov %%rsi, %%rdx;" ANSI_COLOR_GRAY "\t#", addr); fflush(stdout);
	return TRUE + RDX;
}
int mov_rsp_rdx(pid_t child, unsigned long addr)
{
	printf("%016lx: mov %%rsp, %%rdx;" ANSI_COLOR_GRAY "\t#", addr); fflush(stdout);
	return TRUE + RDX;
}
int mov_rdx_rcx(pid_t child, unsigned long addr)
{
	printf("%016lx: mov %%rdx, %%rcx;" ANSI_COLOR_GRAY "\t#", addr); fflush(stdout);
	return TRUE + RCX;
}
int mov_rsi_rax(pid_t child, unsigned long addr)
{
	printf("%016lx: mov %%rsi, %%rax;\n", addr); fflush(stdout);
	return TRUE + RAX;
}
int xor_rax_rax(pid_t child, unsigned long addr)
{
	printf("%016lx: xor %%rax, %%rax;" ANSI_COLOR_GRAY "\t\t# zero\n", addr); fflush(stdout);
	return 0;
}
int xor_r8_r8(pid_t child, unsigned long addr)
{
	printf("%016lx: xor %%r8, %%r8;" ANSI_COLOR_GRAY "\t\t# zero\n", addr); fflush(stdout);
	return 0;
}
int xor_rdx_rdx(pid_t child, unsigned long addr)
{
	printf("%016lx: xor %%rdx, %%rdx;" ANSI_COLOR_GRAY "\t# zero\n", addr); fflush(stdout);
	return 0;
}
int xor_rsi_rsi(pid_t child, unsigned long addr)
{
	printf("%016lx: xor %%rsi, %%rsi;" ANSI_COLOR_GRAY "\t# zero\n", addr); fflush(stdout);
	return 0;
}
int xor_rdi_rdi(pid_t child, unsigned long addr)
{
	printf("%016lx: xor %%rdi, %%rdi;" ANSI_COLOR_GRAY "\t# zero\n", addr); fflush(stdout);
	return 0;
}
int sub_rdx_rsi(pid_t child, unsigned long addr)
{
	printf("%016lx: sub %rsi, %rdx;" ANSI_COLOR_GRAY "\t# (result in RDX) # rdx: %llx, rsi: %llx", addr, regs.rdx, regs.rsi);fflush(stdout);
	return TRUE + RDX;
}
int add_v_rdx(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+4, 0);
	printf("%016lx: add %lu rdx;" ANSI_COLOR_GRAY "\t# rdx: %lli\n", addr, v, regs.rdx);fflush(stdout);
	return TRUE + RDX;
}

int cmp_rax_v(pid_t child, unsigned long addr)
{
	unsigned char v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3,0);
	printf("%016lx: cmp %%rax, %i;" ANSI_COLOR_GRAY "\t\t# %s, rax==%i\n", addr, v, v == regs.rax ? "TRUE": "FALSE", (char)regs.rax);
	return 0;
}
int cmp_rsi_v(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3,0);
	printf("%016lx: cmp %%rsi, %lx;" ANSI_COLOR_GRAY "\t# %s\n", addr, v, v == regs.rsi ? "TRUE": "FALSE");
	return 0;
}

// add 8 bit value to rsi
int add_short_rsi(pid_t child, unsigned long addr)
{
	long unsigned lv = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3,0);
	short v = lv << 56 >> 56; // 56 == 64bits(register) - 8bits(short)
	printf("%016lx: add %i, %%rsi;" ANSI_COLOR_GRAY "\t\t# RSI", addr, v);
	return TRUE + RSI;
}
int mov_rsi_addr(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+4,0);
	printf("%016lx: mov %%rsi, 0x%x;" ANSI_COLOR_GRAY "\t#", addr, v << 32 >> 32);
	return TRUE + RSI;
}
int mov_v_rsi_2(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2,0);
	printf("%016lx: mov 0x%lx, %%rsi;" ANSI_COLOR_GRAY "\t#", addr, v);
	return TRUE + RSI;
}

int mov_v_rbx(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2,0);
	printf("%016lx: MOV 0x%%lx, %%rbx; # %lx\n", addr, v);
	return 0;
}

int push_rbx(pid_t child, unsigned long addr)
{
	printf("%016lx: PUSH %%rbx;\n", addr);
	return 0;
}
int push_rdx(pid_t child, unsigned long addr)
{
	printf("%016lx: PUSH %%rdx;\n", addr);
	return 0;
}
int push_rsp(pid_t child, unsigned long addr)
{
	printf("%016lx: PUSH %%rsp;\n", addr);
	return 0;
}
int push_rax(pid_t child, unsigned long addr)
{
	printf("%016lx: PUSH %%rax;\n", addr);
	return 0;
}
int pop_rax(pid_t child, unsigned long addr)
{
	printf("%016lx: POP %%rax;\n", addr);
	return 0;
}
int pop_rdx(pid_t child, unsigned long addr)
{
	printf("%016lx: POP %%rdx;\n", addr);
	return 0;
}
int pop_rsi(pid_t child, unsigned long addr)
{
	printf("%016lx: POP %%rsi;\n", addr);
	return 0;
}
int pop_rdi(pid_t child, unsigned long addr)
{
	printf("%016lx: POP %%rdi;\n", addr);
	return 0;
}
int movw_rsp(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+5,0);
	printf("%016lx: movw %li, %%rsp;\n",addr, v);
	return 0;
}
int pushq_v(pid_t child, unsigned long addr)
{
	long unsigned vw = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1,0);
	unsigned char *v = (unsigned char *)&vw;
	printf("%016lx: PUSHQ %c;\n", addr, v[4]);
	return 0;
}
int test_al(pid_t child, unsigned long addr)
{
	printf("%016lx: test al;" ANSI_COLOR_GRAY "\t\t# AL = %i, RAX", addr, regs.rax << 56 >> 56);
	return TRUE + RAX;
}
int jne(pid_t child, unsigned long addr)
{
	printf("%016lx: JNE;\n", addr);
	return 0;
}
int mov_al(pid_t child, unsigned long addr)
{
	printf("%016lx: MOV %%al;\n", addr);
	return 0;
}

void detect_friendly_instruction(pid_t child, unsigned long addr, char * friendly_instr)
{
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_OPEN 2
#define SYS_STAT 4
#define SYS_FSTAT 5
#define SYS_MMAP 9
#define SYS_FORK 57
#define SYS_EXECVE 59
#define SYS_EXIT 60
	char syscall[512];
	char buff[256];
	switch (regs.rax) {
		case SYS_OPEN:
			peek_string(child, (void*)regs.rdi, buff); // filename
			sprintf(friendly_instr, "open(%s)", buff);
			break;
		case SYS_WRITE:
			peek_string(child, (void*)regs.rsi, buff);
			long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)regs.rsi, 0);
			sprintf(friendly_instr, "write(%lli, \"%s\"(%lx), %lli)", regs.rdi, buff, v, regs.rdx);
			break;
		case SYS_READ:
			peek_string(child, (void*)regs.rsi, buff);
			sprintf(friendly_instr, "read(%lli, %llx, %lli)", regs.rdi, regs.rsi, regs.rdx);
			break;
		case SYS_MMAP:
			sprintf(friendly_instr, "mmap(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx); # alocates %lli bytes using fd %lli", 
				regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9, regs.rsi, regs.r8);
			break;
		case SYS_STAT:
			sprintf(friendly_instr, "stat(%lli)",regs.rsi);
			break;
		case SYS_FSTAT:
			sprintf(friendly_instr, "fstat(%lli, 0x%016llx)",regs.rdi,regs.rsi);
			break;
		case SYS_FORK:
			sprintf(friendly_instr, "fork()");
			running_forks++;
			break;
		case SYS_EXECVE:
			char filename[4096];
			char args[4096];
			char env[4096];
			peek_string(child, (void*)regs.rdi, filename);
			peek_array(child, (void*)regs.rsi, args);
			peek_array(child, (void*)regs.rdx, env);
			sprintf(friendly_instr, "execve(file: \"%s\", args: %s, env: %s)", filename, args, env);
			break;
		case SYS_EXIT:
			sprintf(friendly_instr, "exit(%lli)",regs.rdi);
			break;
		default:
			sprintf(friendly_instr, "# rax: %lli", regs.rax);
	}
}

int p_syscall(pid_t child, unsigned long addr)
{
	char friendly_instr[255];
	detect_friendly_instruction(child, addr, friendly_instr);
	printf("%016lx: syscall;" ANSI_COLOR_GRAY "\t\t#", addr);
	printf(" %s\n", friendly_instr);
	return 0;
}

int jz(pid_t child, unsigned long addr)
{
	unsigned data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
	printf("%016lx: jz .%i\t\t# jump if zero(int)\n", addr, data);
	return 0;
}
int jg_int(pid_t child, unsigned long addr)
{
	unsigned data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
	printf("%016lx: jg .%i\t\t# jump if greater than zero(int)", addr, data);
	return 0;
}

int jg_byte(pid_t child, unsigned long addr)
{
	printf("%016lx: jg .-9;" ANSI_COLOR_GRAY "\t\t# if previous test > 0 jump back 9 bytes\n", addr);
	return 0;
}

int inc_rdx(pid_t child, unsigned long addr)
{
	printf("%016lx: inc %%rdx;" ANSI_COLOR_GRAY "\t\t#", addr);
	return TRUE + RDX;
}
int dec_rdx(pid_t child, unsigned long addr)
{
	printf("%016lx: dec %%rdx;" ANSI_COLOR_GRAY "\t\t#", addr);
	return TRUE + RDX;
}
int inc_esi(pid_t child, unsigned long addr)
{
	printf("%016lx: INC %%esi;\n", addr);
	return 0;
}
int mul_esi(pid_t child, unsigned long addr)
{
	printf("%016lx: MUL %%esi;\n", addr);
	return 0;
}
int dec_esi(pid_t child, unsigned long addr)
{
	printf("%016lx: DEC %%esi;\n", addr);
	return 0;
}

int mov_v_rdx_2(pid_t child, unsigned long addr)
{
	unsigned long data = ptrace(PTRACE_PEEKTEXT, child,
		(void*)addr+2, 0);
	printf("%016lx: mov 0x%lx, %%rdx\n", addr, data); fflush(stdout);
	return 0;
}
int xchg_rax_rdi(pid_t child, unsigned long addr)
{
	printf("%016lx: xchg %%rax, %%rdi; # %lli <=> %lli\n", addr, regs.rax, regs.rdi);
	return 0;
}

int add_rcx_r8(pid_t child, unsigned long addr)
{
	printf("%016lx: add %%rcx, %%r8;" ANSI_COLOR_GRAY "\t#", addr);fflush(stdout);
	return TRUE + R8;
}
int add_r8_rdi(pid_t child, unsigned long addr)
{
	printf("%016lx: add %%r8, %%rdi;" ANSI_COLOR_GRAY "\t#", addr);fflush(stdout);
	return TRUE + RDI;
}
int mov_r8_rdi(pid_t child, unsigned long addr)
{
	printf("%016lx: mov %%r8, %%rdi;" ANSI_COLOR_GRAY "\t#", addr);fflush(stdout);
	return TRUE + RDI;
}
int mov_rax_r8(pid_t child, unsigned long addr)
{
	unsigned long data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
	printf("%016lx: mov %%rax, %%r8 # 0x%llx(%lli)\n", addr,regs.rax,regs.rax);fflush(stdout);
	return 0;
}
int mov_rax_r9(pid_t child, unsigned long addr)
{
	unsigned long data = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
	printf("%016lx: mov %%rax, %%r9 # 0x%llx(%lli)\n", addr,regs.rax,regs.rax);fflush(stdout);
	return 0;
}

int lea_rip_rbx(pid_t child, unsigned long addr)
{
	printf("%016lx: leaq %%rip, %%rbx;\n", addr);
	return 0;
}

int lea_rsp_rdi(pid_t child, unsigned long addr)
{
	printf("%016lx: lea %%rsp, %%rdi;\n", addr);
	return 0;
}

int rep_movsb(pid_t child, unsigned long addr)
{
	printf("%016lx: rep movsb;" ANSI_COLOR_GRAY "\t\t# RCX(after)",addr);
	return TRUE + RCX;
}

int rep(pid_t child, unsigned long addr)
{
	printf("%016lx: rep", addr);
	return 0;
}

int call(pid_t child, unsigned long addr)
{
	int data = (int)ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
	int bytecode_instr_size = 5;
	printf("%016lx: call %016lx; # near int: %i\n", addr, addr+data+bytecode_instr_size,(int) data + bytecode_instr_size); fflush(stdout);
	return 0;
}
// a map is better, this this is better than ifs
struct bytecode_entry
{
	unsigned char k[5];	// bytecode key bytes
	int kl;			// bytecode length
	int (*fn)(pid_t child, unsigned long addr);		// bytecode function pointer
} bytecodes_list[] = {
	{
		.k = {0x0f,0x05},
		.kl = 2,
		.fn = p_syscall,
	},
	{
		.k = {0x0f, 0x85},
		.kl = 2,
		.fn = jz,
	},
	{
		.k = {0x0f, 0x8f},
		.kl = 2,
		.fn = jg_int,
	},
	{
		.k = {0x48,0x01,0x04,0x25},
		.kl = 4,
		.fn = mov_rax_addr
	},
	{
		.k = {0x48,0x0f,0xb6, 0x02},
		.kl = 4,
		.fn = mov__rdx__rax
	},
	{
		.k = {0x48,0x0f,0xb6, 0x06},
		.kl = 4,
		.fn = mov_addr_rax
	},
	{
		.k = {0x48,0x29,0xf2},
		.kl = 3,
		.fn = sub_rdx_rsi
	},
	{
		.k = {0x48,0x31,0xc0},
		.kl = 3,
		.fn = xor_rax_rax
	},
	{
		.k = {0x48,0x31,0xd2},
		.kl = 3,
		.fn = xor_rdx_rdx
	},
	{
		.k = {0x48,0x31,0xf6},
		.kl = 3,
		.fn = xor_rsi_rsi
	},
	{
		.k = {0x48,0x31,0xff},
		.kl = 3,
		.fn = xor_rdi_rdi
	},
	{
		.k = {0x48,0x83,0xc2},
		.kl = 3,
		.fn = add_v_rdx
	},
	{
		.k = {0x48,0x83,0xf8},
		.kl = 3,
		.fn = cmp_rax_v
	},
	{
		.k = {0x48,0x83,0xfe},
		.kl = 3,
		.fn = cmp_rsi_v
	},
	{
		.k = {0x48,0x83,0xc6},
		.kl = 3,
		.fn = add_short_rsi
	},
	{
		.k = {0x48,0x89,0x14,0x25},
		.kl = 4,
		.fn = mov_rdx_addr
	},
	{
		.k = {0x48,0x89,0x24,0x25},
		.kl = 4,
		.fn = mov_rsp_addr
	},
	{
		.k = {0x48,0x89,0x34, 0x25},
		.kl = 3,
		.fn = mov_rsi_addr
	},
	{
		.k = {0x48,0x89,0xc6},
		.kl = 3,
		.fn = mov_rax_rsi
	},
	{
		.k = {0x48,0x89,0xc7},
		.kl = 3,
		.fn = mov_rax_rdi
	},
	{
		.k = {0x48,0x89,0xd1},
		.kl = 3,
		.fn = mov_rdx_rcx
	},
	{
		.k = {0x48,0x89,0xe2},
		.kl = 3,
		.fn = mov_rsp_rdx
	},
	{
		.k = {0x48,0x89,0xe6},
		.kl = 3,
		.fn = mov_rsp_rsi
	},
	{
		.k = {0x48,0x89,0xf0},
		.kl = 3,
		.fn = mov_rsi_rax
	},
	{
		.k = {0x48,0x89,0xf2},
		.kl = 3,
		.fn = mov_rsi_rdx
	},
	{
		.k = {0x48,0x8b,0x00},
		.kl = 3,
		.fn = mov_rax_rax
	},
	{
		.k = {0x48,0x8b,0x3f},
		.kl = 3,
		.fn = mov_rdi_rdi
	},
	{
		.k = {0x48,0x8b,0x12},
		.kl = 3,
		.fn = mov_rdx_rdx
	},
	{
		.k = {0x48,0x8b,0x14,0x25},
		.kl = 4,
		.fn = mov_addr_rdx
	},
	{
		.k = {0x48,0x8b,0x34,0x25},
		.kl = 4,
		.fn = mov_addr_rsi
	},
	{
		.k = {0x48,0x8b,0x36},
		.kl = 3,
		.fn = mov_rsi_rsi
	},
	{
		.k = {0x48,0x8b,0x3c,0x25},
		.kl = 4,
		.fn = mov_addr_rdi
	},
	{
		.k = {0x48,0x8d,0x1d},
		.kl = 3,
		.fn = lea_rip_rbx,
	},
	{
		.k = {0x48,0x8d,0x3c,0x24},
		.kl = 4,
		.fn = lea_rsp_rdi,
	},
	{
		.k = {0x48,0x97},
		.kl = 2,
		.fn = xchg_rax_rdi,
  	},
	{
		.k = {0x48,0xb8},
		.kl = 2,
		.fn = mov_v_rax
	},
	{
		.k = {0x48,0xba},
		.kl = 2,
		.fn = mov_v_rdx_2
	},
	{
		.k = {0x48,0xbb},
		.kl = 2,
		.fn = mov_v_rbx
	       	// v = 2f 62 69 6e 2f 2f 73 68
		// movabs $0x68732f2f6e69622f,%rbx
	},
	{
		.k = {0x48,0xbe},
		.kl = 2,
		.fn = mov_v_rsi_2
	},
	{
		.k = {0x48,0xbf},
		.kl = 2,
		.fn = mov_v8_rdi
	},
	{
		.k = {0x48,0xc7,0xc0},
		.kl = 3,
		.fn = mov_v4_rax
	},
	{
		.k = {0x48,0xc7,0xc1},
		.kl = 3,
		.fn = mov_v4_rcx
	},
	{
		.k = {0x48,0xc7,0xc2},
		.kl = 3,
		.fn = mov_v_rdx
	},
	{
		.k = {0x48,0xc7,0xc6},
		.kl = 3,
		.fn = mov_v_rsi
	},
	{
		.k = {0x48,0xc7,0xc7},
		.kl = 3,
		.fn = mov_v_rdi_3
	},
	{
		.k = {0x48,0xff,0xc2},
		.kl = 3,
		.fn = inc_rdx
	},
	{
		.k = {0x48,0xff,0xca},
		.kl = 3,
		.fn = dec_rdx
	},
	{
		.k = {0x49,0x01,0xc8},
		.kl = 3,
		.fn = add_rcx_r8,
	},
	{
		.k = {0x49,0x89,0xc0},
		.kl = 3,
		.fn = mov_rax_r8,
	},
	{
		.k = {0x49,0x89,0xc1},
		.kl = 3,
		.fn = mov_rax_r9,
	},
	{
		.k = {0x49,0xb8},
		.kl = 2,
		.fn = mov_v_r8,
	},
	{
		.k = {0x49,0xb9},
		.kl = 2,
		.fn = mov_v_r9,
	},
	{
		.k = {0x49,0xba},
		.kl = 2,
		.fn = mov_v_r10,
	},
	{
		.k = {0x4c,0x01,0xc7},
		.kl = 3,
		.fn = add_r8_rdi,
	},
	{
		.k = {0x4c, 0x89,0xc7},
		.kl = 3,
		.fn = mov_r8_rdi,
	},
	{
		.k = {0x4d,0x31,0xc0},
		.kl = 3,
		.fn = xor_r8_r8,
	},
	{
		.k = {0x52},
		.kl = 1,
		.fn = push_rdx,
	},
	{
		.k = {0x53},
		.kl = 1,
		.fn = push_rbx,
	},
	{
		.k = {0x54},
		.kl = 1,
		.fn = push_rsp,
	},
	{
		.k = {0x58},
		.kl = 1,
		.fn = pop_rax,
	},
	{
		.k = {0x5a},
		.kl = 1,
		.fn = pop_rdx,
	},
	{
		.k = {0x5e},
		.kl = 1,
		.fn = pop_rsi,
	},
	{
		.k = {0x5f},
		.kl = 1,
		.fn = pop_rdi,
	},
	{
		.k = {0x66,0xc7,0x44,0x24,0x02},
		.kl = 5,
		.fn = movw_rsp,
	        //	15 e0 	movw   $0xe015,0x2(%rsp)
	},
	{
		// pushq $0x2
		// push 1 byte
		.k = {0x6a},
		.kl = 1,
		.fn = pushq_v
	},
	{
		.k = {0x75,0xf8},
		.kl = 2,
		.fn = jne,
	},
	{
		.k = {0x7f, 0xf5},
		.kl = 2,
		.fn = jg_byte,
	},
	{
		.k = {0x84,0xc0},
		.kl = 2,
		.fn = test_al,
	},
	{
		.k = {0xb0},
		.kl = 1,
		.fn = mov_al,
	},
	{
		.k = {0xb8},
		.kl = 1,
		.fn = mov_v_eax
	}, 
	{
		.k = {0xe8},
		.kl = 1,
		.fn = call,
	},
	{
		.k = {0xf3, 0xa4},
		.kl = 2,
		.fn = rep_movsb,
	},
	{
		.k = {0xf3},
		.kl = 1,
		.fn = rep,
	},
	{
		.k = {0xf7,0xe6},
		.kl = 2,
		.fn = mul_esi
	},
	{
		.k = {0xff,0xc6},
		.kl = 2,
		.fn = inc_esi,
	},
	{
		.k = {0xff,0xce},
		.kl = 2,
		.fn = dec_esi,
	},
};

