#include "debugger.h"
int mov_v_eax(pid_t child, unsigned long addr)
{
	long unsigned rax = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1, 0);
	printf("%016lx: mov 0x%lx, %%eax # %li\n", addr, rax, rax);fflush(stdout);
	return 0;
}

int mov_v_rsi(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
	printf("%016lx: mov 0x%lx, %%rsi\n", addr, v); fflush(stdout);
	return 0;
}

int mov_rsi_rsi(pid_t child, unsigned long addr)
{
	printf("%016lx: mov %%rsi, %%rsi # (resolve address)\n", addr);fflush(stdout);
	return TRUE + RSI;
}

int mov_rdx_rdx(pid_t child, unsigned long addr)
{
	printf("%016lx: mov %%rdx %%rdx # (resolve address)\n", addr);fflush(stdout);
	return TRUE + RDX;
}

int mov_v_rax(pid_t child, unsigned long addr)
{
	long unsigned rax = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
	printf("%016lx: mov 0x%lx, %%rax\n", addr, rax);fflush(stdout);
	return 0;
}
int mov_v_rax_3(pid_t child, unsigned long addr)
{
	long unsigned rax = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
	printf("%016lx: mov 0x%lx, %%rax\n", addr, rax);fflush(stdout);
	return 0;
}
int mov_v_rdx(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
	printf("%016lx: mov 0x%lx, %%rdx\n", addr, v);fflush(stdout);
	return 0;
}
int mov_v_rdi_3(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3, 0);
	printf("%016lx: mov 0x%lx, %%rdi\n", addr, v);fflush(stdout);
	return 0;
}
int mov_v_r8(pid_t child, unsigned long addr)
{
	unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
	printf("%016lx: mov %x, %%r8\n", addr, v);fflush(stdout);
}
int mov_v_r9(pid_t child, unsigned long addr)
{
	unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
	printf("%016lx: mov %x, %%r9\n", addr, v);fflush(stdout);
}
int mov_v_r10(pid_t child, unsigned long addr)
{
	unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2, 0);
	printf("%016lx: mov %x, %%r10\n", addr, v);fflush(stdout);
}
int mov_v_rsp(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+4, 0);
	printf("%016lx: mov 0x%lx, %%rsp\n", addr, v);fflush(stdout);
	return 0;
}

int mov_rax_rsi(pid_t child, unsigned long addr)
{
	printf("%016lx: mov %%rax, %%rsi\n", addr); fflush(stdout);
	return TRUE + RSI;
}

int mov_rax_rdi(pid_t child, unsigned long addr)
{
	printf("%016lx: mov %%rax, %%rdi\n", addr); fflush(stdout);
	return TRUE + RDI;
}
int mov_rsp_rsi(pid_t child, unsigned long addr)
{
	printf("%016lx: mov %%rsp, %%rsi\n", addr); fflush(stdout);
	return TRUE + RSI;
}
int mov_rsi_rdx(pid_t child, unsigned long addr)
{
	printf("%016lx: mov %%rsi, %%rdx\n", addr); fflush(stdout);
	return TRUE + RDX;
}
int mov_rsp_rdx(pid_t child, unsigned long addr)
{
	printf("%016lx: mov %%rsp, %%rdx\n", addr); fflush(stdout);
	return TRUE + RDX;
}
int mov_rsi_rax(pid_t child, unsigned long addr)
{
	printf("%016lx: mov %%rsi, %%rax\n", addr); fflush(stdout);
	return TRUE + RAX;
}
int xor_rax_rax(pid_t child, unsigned long addr)
{
	printf("%016lx: xor %%rax, %%rax\n # zero", addr); fflush(stdout);
	return 0;
}
int xor_rdx_rdx(pid_t child, unsigned long addr)
{
	printf("%016lx: xor %%rdx, %%rdx\n # zero", addr); fflush(stdout);
	return 0;
}
int xor_rsi_rsi(pid_t child, unsigned long addr)
{
	printf("%016lx: xor %%rsi, %%rsi\n # zero", addr); fflush(stdout);
	return 0;
}
int sub_rdx_rsi(pid_t child, unsigned long addr)
{
	printf("%016lx: SUB RDX RSI (result in RDX)# rdx: %lli, rsi: %lli\n", addr, regs.rdx, regs.rsi);fflush(stdout);
	return TRUE + RDX;
}
int add_v_rdx(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+4, 0);
	printf("%016lx: ADD %lu RDX # rdx: %lli\n", addr, v, regs.rdx);fflush(stdout);
	return TRUE + RDX;
}

int cmp_rax_v(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3,0);
	printf("%016lx: CMP %%rax, %lx; # %s\n", addr, v, v == regs.rax ? "TRUE": "FALSE");
	return 0;
}
int cmp_rsi_v(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3,0);
	printf("%016lx: CMP %%rsi, %lx; # %s\n", addr, v, v == regs.rsi ? "TRUE": "FALSE");
	return 0;
}
int add_v_rsi(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+3,0);
	printf("%016lx: ADD %lx, %%rsi; \n", addr, v);
	return 0;
}
int mov_v_rsi_2(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2,0);
	printf("%016lx: MOV %lx, %%rsi; \n", addr, v);
	return 0;
}
int mov_v_rdi_2(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2,0);
	printf("%016lx: MOV %lx, %%rdi; \n", addr, v);
	return 0;
}

int mov_v_rbx(pid_t child, unsigned long addr)
{
	long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+2,0);
	printf("%016lx: MOV %%lx, %%rbx; # %lx\n", addr, v);
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
	printf("%016lx: MOVW %li, %%RSP;\n",addr, v);
	return 0;
}
int pushq_v(pid_t child, unsigned long addr)
{
	long unsigned vw = ptrace(PTRACE_PEEKTEXT, child, (void*)addr+1,0);
	unsigned char *v = (unsigned char *)&vw;
	printf("%016lx: PUSHQ %c;\n", addr, v[4]);
	return 0;
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
	if ( regs.rax == 1L ) {
		char bytes[256];
		copy_bytes(child, regs.rsi, (char *)&bytes, regs.rdx);
		//unsigned long data = ptrace(PTRACE_PEEKTEXT, child,
		//	(void*)addr+2, 0);
		sprintf(friendly_instr, "# write\t%s\n", (char *)&bytes);
	} else if ( regs.rax == 2L ) {
		char bytes[256];
		unsigned long data = ptrace(PTRACE_PEEKTEXT, child,
			(void*)regs.rdi, 0);
		fprintf(stdout, "\n** [%s] **\n", (char *)data);
		copy_bytes(child, regs.rdi, (char *)&bytes, regs.rdx);
		sprintf(friendly_instr, "# open\t%s\n", (char *)&bytes);
	} else {
		sprintf(friendly_instr, "# rax: %lli", regs.rax);
	}
}

int p_syscall(pid_t child, unsigned long addr)
{
	char friendly_instr[255];
	detect_friendly_instruction(child, addr, friendly_instr);
	printf("%016lx: SYSCALL;", addr);
	printf(" %s\n", friendly_instr);
	return 0;
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

int lea_rsp_rdi(pid_t child, unsigned long addr)
{
	printf("%016lx: lea %%rsp, %%rdi;\n", addr);
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
		.fn = add_v_rsi
	},
	{
		.k = {0x48,0x89,0x24,0x25},
		.kl = 4,
		.fn = mov_v_rsp
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
		.k = {0x48,0x89},
		.kl = 2,
		.fn = mov_v_rsi
	},
	{
		.k = {0x48,0x8b,0x12},
		.kl = 3,
		.fn = mov_rdx_rdx
	},
	{
		.k = {0x48,0x8b,0x36},
		.kl = 3,
		.fn = mov_rsi_rsi
	},
	{
		.k = {0x48,0x97},
		.kl = 2,
		.fn = xchg_rax_rdi,
  	},
	{
		.k = {0x48,0x8d,0x3c,0x24},
		.kl = 4,
		.fn = lea_rsp_rdi,
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
		.fn = mov_v_rdi_2
	},
	{
		.k = {0x48,0xc7,0xc0},
		.kl = 3,
		.fn = mov_v_rax_3
	},
	{
		.k = {0x48,0xc7,0xc2},
		.kl = 3,
		.fn = mov_v_rdx
	},
	{
		.k = {0x48,0xc7,0xc7},
		.kl = 3,
		.fn = mov_v_rdi_3
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
		.k = {0x0f,0x05},
		.kl = 2,
		.fn = p_syscall,
	},
	{
		.k = {0xe8},
		.kl = 1,
		.fn = call,
	},
	{
		.k = {0xff,0xc6},
		.kl = 2,
		.fn = inc_esi,
	},
	{
		.k = {0xf7,0xe6},
		.kl = 2,
		.fn = mul_esi
	},
	{
		.k = {0xff,0xce},
		.kl = 2,
		.fn = dec_esi,
	},
};

