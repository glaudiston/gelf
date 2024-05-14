#include "debugger.h"
typedef enum {
	NONE,
	REX,	// REX Prefix (0x40 - 0x4F):
		// 	The REX prefix is used in 64-bit mode to extend the instruction set
		// 	to handle 64-bit operands and additional registers.
	osize,	// Operand Size Override Prefix (0x66):
		// 	Override the default operand size of an instruction.
		// 	When this prefix is present, the instruction operates on 16-bit operands
		// 	instead of the default operand size (e.g., 32-bit or 64-bit).
	asize,	// Address Size Override Prefix (0x67):
		// 	Override the default address size of an instruction.
		// 	It can switch between 16-bit and 32/64-bit address sizes.
	ssize,	//
	LOCK,	// Lock Prefix (0xF0):
		// 	The lock prefix is used to ensure atomicity of certain memory operations,
		// 	such as atomic read-modify-write instructions like xchg.
	REP,
	REPE,
	REPNE,	// REP related Prefixes (0xF2, 0xF3):
		// 	These prefixes are used with certain string instructions (movs, cmps, scas, lods, stos)
		// 	to repeat the operation while certain conditions are met 
		// 	(e.g., ECX register is not zero, or the ZF flag is set).
	BRANCH_HINT,	// Branch Hints Prefixes (0x2E, 0x3E):
			// 	These prefixes are used as branch hints for the processor's branch prediction mechanism.
			// 	They hint whether a branch is likely or unlikely to be taken.
	SEGMENT_OVERRIDE,	// Segment override (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65):
				// 	These prefixes override the default segment register used for memory addressing.
	EVEX,	// EVEX (0x62):
		// 	This is an AVX-512 prefix used for instructions operating on 512-bit registers.
		// 	It replaces the REX prefix in AVX-512 instructions.
	VEX,	// VEX (0xC4, 0xC5):
		// 	These prefixes are used for AVX (Advanced Vector Extensions) instructions.
	XOP	// XOP (0x8F):
		// 	This prefix is used for XOP (eXtended Operations) instructions,
		// 	which are a set of additional SIMD instructions introduced by AMD.
} prefix_type;

/*
#  REX Bits:
#  |7|6|5|4|3|2|1|0|
#  |0|1|0|0|W|R|X|B|
*/
struct rex {
	char W;	// W bit = Operand size 1==64-bits, 0 == legacy, Operand size determined by CS.D (Code Segment)
	char R;	// R bit = Extends the ModR/M reg field to 4 bits. 0 selects rax-rsi, 1 selects r8-r15
	char X;	// X bit = extends SIB 'index' field, same as R but for the SIB byte (memory operand)
	char B;	// B bit = extends the ModR/M r/m or 'base' field or the SIB field
};
struct prefix {
	prefix_type type;
	union {
		struct rex rex;
	};
};
struct rmmod {
	unsigned char mod;
	unsigned char v1;
	unsigned char v2;
};
struct modrm {
	unsigned char byte;
	unsigned char mod;	// defines if operands are register/memory/pointer
	unsigned char target;	// Reg/Mem or SIB ?
	unsigned char source;	// Reg/Mem?
	unsigned char has_SIB;	// 1 if target is 100
};
struct displacement {
	union{
		signed char v8bit;
		signed long int v32bit;
		signed long long int v64bit;
	};
};
struct instruction {
	int parsed;
	int rv;
	struct prefix prefix;
	unsigned char opcode; // operator
	struct modrm modrm;	// ModR/M
	struct displacement displacement;
	unsigned char sib;
};

char *get_color(char *item)
{
	if (!cmd_options.show_colors){
		return "";
	}
	if ( strcmp(item, "REX") == 0){
		return "\033[38;2;100;44;130m";
	}
	if ( strcmp(item, "jmp") == 0){
		return "\033[38;2;0;120;135m";
	}
	if ( strcmp(item, "int") == 0){
		return "\033[38;2;50;100;80m";
	}
	if ( strcmp(item, "gray") == 0){
		return "\033[38;2;80;80;80m";
	}
	return "\033[0m";
}

void detect_friendly_instruction(pid_t child, unsigned long addr, char * friendly_instr)
{
#define SYS_READ 0
#define SYS_WRITE 1
#define SYS_OPEN 2
#define SYS_STAT 4
#define SYS_FSTAT 5
#define SYS_MMAP 9
#define SYS_PIPE 22
#define SYS_DUP2 33
#define SYS_FORK 57
#define SYS_EXECVE 59
#define SYS_EXIT 60
#define SYS_WAIT4 61
	char syscall[512];
	char buff[256];
	switch (regs.rax) {
		case SYS_OPEN:
			peek_string(child, (void*)regs.rdi, buff); // filename
			sprintf(friendly_instr, "sys_open(%s)", buff);
			break;
		case SYS_WRITE:
			peek_string(child, (void*)regs.rsi, buff);
			long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)regs.rsi, 0);
			sprintf(friendly_instr, "sys_write(%lli, \"%s\"(%lx), %lli)", regs.rdi, buff, v, regs.rdx);
			break;
		case SYS_READ:
			sprintf(friendly_instr, "sys_read(%lli, 0x%llx, %lli)", regs.rdi, regs.rsi, regs.rdx);
			break;
		case SYS_MMAP:
			sprintf(friendly_instr, "sys_mmap(0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx, 0x%llx); # alocates %lli bytes using fd %lli", 
				regs.rdi, regs.rsi, regs.rdx, regs.r10, regs.r8, regs.r9, regs.rsi, regs.r8);
			break;
		case SYS_STAT:
			sprintf(friendly_instr, "sys_stat(%lli)",regs.rsi);
			break;
		case SYS_FSTAT:
			sprintf(friendly_instr, "sys_fstat(%lli, 0x%016llx)",regs.rdi,regs.rsi);
			break;
		case SYS_PIPE:
			sprintf(friendly_instr, "sys_pipe(0x%x);", regs.rdi);
			break;
		case SYS_DUP2:
			sprintf(friendly_instr, "sys_dup2(%i,%i);", regs.rdi, regs.rsi);
			break;
		case SYS_FORK:
			sprintf(friendly_instr, "sys_fork()");
			running_forks++;
			break;
		case SYS_EXECVE:
			char filename[4096];
			char args[4096];
			char env[4096];
			peek_string(child, (void*)regs.rdi, filename);
			peek_array(child, (void*)regs.rsi, args);
			peek_array(child, (void*)regs.rdx, env);
			sprintf(friendly_instr, "sys_execve(file: \"%s\", args: %s, env: %s)", filename, args, env);
			break;
		case SYS_EXIT:
			sprintf(friendly_instr, "sys_exit(%lli)%s",regs.rdi, get_color(""));
			break;
		case SYS_WAIT4:
			sprintf(friendly_instr, "sys_wait4(%lli,%lli,%lli,%lli)",regs.rdi,regs.rsi,regs.rdx, regs.r10);
			break;
		default:
			sprintf(friendly_instr, "# rax: %lli", regs.rax);
	}
}

int p_syscall(pid_t child, unsigned long addr)
{
	char friendly_instr[255];
	detect_friendly_instruction(child, addr, friendly_instr);
	printf("%ssyscall;%s\t\t\t#", addr, get_color("white"), get_color("gray"));
	printf(" %s\n", friendly_instr);
	return 0;
}

void print_previous_instruction_trace(pid_t pid, unsigned long int ic, struct user_regs_struct regs, instruction_info * ptr_parsed_instruction)
{
	int i;
	for ( i=0; i<ptr_parsed_instruction->print_request_size; i++ ) {
		printf("here print_request_size %i\n", ptr_parsed_instruction->print_request_size);fflush(stdout);
		struct print_addr_request pr = ptr_parsed_instruction->print_request[i];
		printMemoryValue(pid, pr.addr, 0);
	}
	ptr_parsed_instruction->asm_code[0]=0;
	ptr_parsed_instruction->print_request_size=0;
}

/*
 *  check_prefix should detect and print all instruction prefixes
 */
prefix_type prefix_type_of(unsigned char b){
	if ( b >= 0x40 && b <=0x4f ){
		return REX;
	}
	/*
# 	The REX prefix is used in 64-bit mode to extend the instruction set to handle 64-bit operands and additional registers.
# osize: The Operand Size Override Prefix (0x66):
# 	Override the default operand size of an instruction.
# 	When this prefix is present, the instruction operates on 16-bit operands
# 	instead of the default operand size (e.g., 32-bit or 64-bit).
# asize: Address Size Override Prefix (0x67):
# 	Override the default address size of an instruction. It can switch between 16-bit and 32/64-bit address sizes.
# ssize?:
# Lock Prefix (0xF0):
# 	The lock prefix is used to ensure atomicity of certain memory operations,
# 	such as atomic read-modify-write instructions like xchg.
# REP/REPE/REPNE Prefixes (0xF2, 0xF3):
# 	These prefixes are used with certain string instructions (movs, cmps, scas, lods, stos)
# 	to repeat the operation while certain conditions are met (e.g., ECX register is not zero, or the ZF flag is set).
# Branch Hints Prefixes (0x2E, 0x3E):
# 	These prefixes are used as branch hints for the processor's branch prediction mechanism.
# 	They hint whether a branch is likely or unlikely to be taken.
# Segment override (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65):
# 	These prefixes override the default segment register used for memory addressing.
# EVEX (0x62):
#	This is an AVX-512 prefix used for instructions operating on 512-bit registers.
#	It replaces the REX prefix in AVX-512 intructions.
# VEX (0xC4, 0xC5):
#	These prefixes are used for AVX (Advanced Vector Extensions) instructions.
# XOP (0x8F):
#	This prefix is used for XOP (eXtended Operations) instructions,
#	which are a set of additional SIMD instructions introduced by AMD.
	*/
	return NONE;
}

void get_instruction_bytes(pid_t pid, unsigned long addr, unsigned char * b){
	// data is composed of 4 bytes(32 bits) in a little-endian, so we need 2:
	uint32_t d1 = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, 0);
	uint32_t d2 = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr+4, 0);
	b[0] = d1 << 24 >> 24;
	b[1] = d1 << 16 >> 24;
	b[2] = d1 << 8 >> 24;
	b[3] = d1 << 0 >> 24;
	b[4] = d2 << 24 >> 24;
	b[5] = d2 << 16 >> 24;
	b[6] = d2 << 8 >> 24;
	b[7] = d2 << 0 >> 24;
}

/*
# 8bit(hi,low)	16bits	32bits	64bits	bitval
ah=0;	al=0;	ax=0;	eax=0;	rax=0;	# 000
ch=0;	cl=1;	cx=1;	ecx=1;	rcx=1;	# 001	special because `rep` and others? uses it
dh=0;	dl=2;	dx=2;	edx=2;	rdx=2;	# 010
bh=0;	bl=3;	bx=3;	ebx=3;	rbx=3;	# 011
spl=4;	sp=4;	esp=4;	rsp=4;	# 100	processor controlled pointing to stack pointer, same value for SIB
bpl=5;	bp=5;	ebp=5;	rbp=5;	# 101
sil=6;	si=6;	rsi=6;	rsi=6;	# 110
dil=7;	di=7;	edi=7;	rdi=7;	# 111
r8b=0;	r8w=0;	r8d=0;	r8=0;	# 000
r9b=1;	r9w=1;	r9d=1;	r9=1;	# 001
r10b=2;	r10w=2;	r10d=2;	r10=2;	# 010
r11b=3;	r11w=3;	r11d=3; r11=3;	# 011
r12b=4;	r12w=4;	r12d=4;	r12=4;	# 100
r13b=5;	r13w=5;	r13d=5;	r13=5;	# 101
r14b=6;	r14w=6;	r14d=6;	r14=6;	# 110
r15b=7;	r15w=7;	r15d=7;	r15=7;	# 111
 * */
char **r64a = (char *[]){ "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi" };
char **r64b = (char *[]){ "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
char **r32a = (char *[]){ "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
char **r32b = (char *[]){ "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d" };
char **r16a = (char *[]){ "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };
char **r16b = (char *[]){ "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w" };
char **r8a = (char *[]){ "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil" };
char **r8b = (char *[]){ "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b" };
char **r8bh = (char *[]){ "ah", "ch", "dh", "bh" };
char * a, b;

struct modrm parse_modrm(struct instruction instr, unsigned char byte){
	instr.modrm.byte=byte;
	instr.modrm.mod=( (instr.modrm.byte & 192) >> 6 );	// 11000000
	instr.modrm.source=( (instr.modrm.byte & 56) >> 3 );	// 00111000
	instr.modrm.target=instr.modrm.byte & 7;		// 00000111
	return instr.modrm;
}

void get_modrm_source(struct instruction instr, char *a){
	if (instr.prefix.type != REX) {
		sprintf(a,r32b[instr.modrm.source]);
		return;
	}
	if (instr.prefix.rex.W && instr.prefix.rex.R) {
		sprintf(a,r8a[instr.modrm.source]);
		return;
	}
	if (instr.prefix.rex.R) {
		sprintf(a,r64b[instr.modrm.source]);
		return;
	}
	sprintf(a,r64a[instr.modrm.source]);
}

void get_modrm_target(struct instruction instr, char *b){
	if (instr.prefix.type != REX) {
		sprintf(b,r32b[instr.modrm.target]);
		return;
	}
	if (instr.modrm.mod == 3 && instr.prefix.rex.W && instr.prefix.rex.B) {
		sprintf(b, r64a[instr.modrm.target]);
		return;
	}
	if (instr.modrm.mod == 0 && instr.prefix.rex.W && instr.prefix.rex.B) {
		sprintf(b, r8a[instr.modrm.target]);
		return;
	}
	if (instr.prefix.rex.B) {
		sprintf(b,r64b[instr.modrm.target]);
		return;
	}
	sprintf(b,r64a[instr.modrm.target]);
}

long long unsigned int get_reg_val(char *r)
{
	if (strcmp(r,"rsi")==0) {
		return regs.rsi;
	}
}

/**
 * try to parse the bytes populating the instr_struct;
 * if succeed set instr_struct->parsed=TRUE;
 * */
instruction_info parse_next_instruction(pid_t pid, struct user_regs_struct regs){
	unsigned char bytes[8];
	get_instruction_bytes(pid, regs.rip, (unsigned char *)&bytes);
	instruction_info rv = {
		.print_request_size = 0,
		.address = regs.rip,
	};
	sprintf(rv.bytes, bytes);
	sprintf(rv.hexdump, "%02x%02x %02x%02x %02x%02x %02x%02x",
		bytes[0], bytes[1], bytes[2], bytes[3],
		bytes[4], bytes[5], bytes[6], bytes[7]);
	sprintf(rv.colored_hexdump, "");
	struct instruction instr;
	instr.prefix.type = prefix_type_of(bytes[0]);
	unsigned char instr_size = 0;
	switch (instr.prefix.type) {
		case REX:
			instr.prefix.rex.W = bytes[0] & (1 << 3);
			instr.prefix.rex.R = bytes[0] & (1 << 2);
			instr.prefix.rex.X = bytes[0] & (1 << 1);
			instr.prefix.rex.B = bytes[0] & (1 << 0);
			instr_size++;
			instr.opcode=bytes[instr_size++];
			char rex_binary_tips[100]="";
			if (cmd_options.binary_tips){
				char w[50], r[50], x[50], b[50];
				sprintf(w, "%sW%s%s", 
					instr.prefix.rex.W ? get_color("REX.W") : get_color("gray"),
					instr.prefix.rex.W ? "¹" : "°", get_color(""));
				sprintf(r, "%sR%s%s", 
					instr.prefix.rex.R ? get_color("REX.R") : get_color("gray"),
					instr.prefix.rex.R ? "¹" : "°", get_color(""));
				sprintf(x, "%sX%s%s", 
					instr.prefix.rex.X ? get_color("REX.X") : get_color("gray"),
					instr.prefix.rex.X ? "¹" : "°", get_color(""));
				sprintf(b, "%sB%s%s", 
					instr.prefix.rex.B ? get_color("REX.B") : get_color("gray"),
					instr.prefix.rex.B ? "¹" : "°", get_color(""));
				sprintf(rex_binary_tips,"(REX°¹°°%s%s%s%s)", w, r , x, b );
			}
			sprintf(rv.colored_hexdump, "%s%x%s%s", get_color("REX"), bytes[0], rex_binary_tips, get_color(""));
			break;
		default:
			instr.opcode=bytes[instr_size++];
	}
	struct print_addr_request print_request[5];
	int print_request_size;
	sprintf(rv.asm_code, "");
	char a[256], b[256];
	switch (instr.opcode) {
		case 0x01:	// add
		{
			sprintf(rv.colored_hexdump, "%s%s%x%s", rv.colored_hexdump, get_color("add"), bytes[instr_size-1], get_color(""));
			instr.modrm=parse_modrm(instr,bytes[instr_size++]);
			if ( instr.modrm.mod == 3 ){
				get_modrm_source(instr, (char*)&a);
				get_modrm_target(instr, (char*)&b);
				sprintf(rv.asm_code, "add %s, %s", a, b);
				sprintf(rv.comment,"");
				break;
			}
			break;
		}
		case 0x31:	// xor
		{
			sprintf(rv.colored_hexdump, "%s%s%x%s", rv.colored_hexdump, get_color("xor"), bytes[instr_size-1], get_color(""));
			instr.modrm=parse_modrm(instr, bytes[instr_size++]);
			get_modrm_source(instr, (char*)&a);
			get_modrm_target(instr, (char*)&b);
			sprintf(rv.asm_code, "xor %s, %s", a, b);
			break;
		}
		case 0x50:	// push %rax
		{
			sprintf(rv.colored_hexdump, "%s%s%x%s", rv.colored_hexdump, get_color("push"), bytes[instr_size-1], get_color(""));
			sprintf(rv.asm_code, "push %rax");
			sprintf(rv.comment, "0x%x", regs.rax);
			break;
		}
		case 0x74:	// jz short
		{
			sprintf(rv.colored_hexdump, "%s%s%x%s", rv.colored_hexdump, get_color("jz"), bytes[instr_size-1], get_color(""));
			signed char v = bytes[instr_size++];
			sprintf(rv.asm_code, "jz .%i", v);
			sprintf(rv.comment, "0x%x:{ZF}", regs.rip + instr_size + v);
			break;
		}
		case 0x80:	// cmp
		{
			sprintf(rv.colored_hexdump, "%s%s%x%s", rv.colored_hexdump, get_color("cmp"), bytes[instr_size-1], get_color(""));
			instr.modrm=parse_modrm(instr, bytes[instr_size++]);
			sprintf(a, "0x%x", bytes[instr_size++]);
			get_modrm_target(instr, (char*)&b);
			sprintf(rv.asm_code, "cmp %s, %s", a, b);
			sprintf(rv.comment, "%s:0x%x:{ZF}", b, (unsigned char)get_reg_val(b));
			break;
		}
		case 0x83:	// add
		{
			sprintf(rv.colored_hexdump, "%s%s%x%s", rv.colored_hexdump, get_color("add"), bytes[instr_size-1], get_color(""));
			instr.modrm=parse_modrm(instr,bytes[instr_size++]);
			if ( instr.modrm.mod == 3 ) { // 11
				instr.displacement.v8bit = bytes[instr_size++];
				sprintf(a, "%i", instr.displacement.v8bit);
				get_modrm_target(instr, (char*)&b);
				sprintf(rv.asm_code, "add %s, %s", a, b);
				sprintf(rv.comment, "");
				break;
			}
			break;
		}
		case 0x89:	// mov
		{
			sprintf(rv.colored_hexdump, "%s%s%x%s", rv.colored_hexdump, get_color("mov"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%x%s", rv.colored_hexdump, get_color(""), bytes[instr_size], get_color(""));
			instr.modrm=parse_modrm(instr,bytes[instr_size++]);
			if ( instr.modrm.mod == 3 ) { // 11
				get_modrm_source(instr, (char*)&a);
				get_modrm_target(instr, (char*)&b);
				sprintf(rv.asm_code, "mov %s, %s", a, b);
				sprintf(rv.comment, "");
				break;
			}
			if ( instr.modrm.mod == 0 ) { // 00
				unsigned char HAS_DISPLACEMENT=4;
				sprintf(a, r64a[instr.modrm.source]);
				if ( instr.modrm.target == HAS_DISPLACEMENT ) {
					unsigned int tgt_addr = ptrace(PTRACE_PEEKTEXT, pid, (void*)regs.rip+(++instr_size), 0);
					sprintf(b, "[0x%x]", tgt_addr);
				}
				else
				{
					get_modrm_target(instr, (char*)&b);
				}
				sprintf(rv.asm_code, "mov %s, %s", a, b);
				sprintf(rv.comment, "");
				break;
			}
			break;
		}
		case 0x8b:	// mov (%r), %r;
		{
			sprintf(rv.colored_hexdump, "%s%s%x%s", rv.colored_hexdump, get_color("mov"), bytes[instr_size-1], get_color(""));
			instr.modrm=parse_modrm(instr,bytes[instr_size++]);
			if ( instr.modrm.mod == 0 ) { // 00
				get_modrm_source(instr, (char*)&b);
				get_modrm_target(instr, (char*)&a);
				sprintf(rv.asm_code, "mov (%s), %s", a, b);
				sprintf(rv.comment, "");
				break;
			}
			break;
		}
		case 0xe8:	// call
		{
			sprintf(rv.colored_hexdump, "%s%s%x%s", rv.colored_hexdump, get_color("call"), bytes[instr_size-1], get_color(""));
			long int v = ptrace(PTRACE_PEEKTEXT, pid, (void*)regs.rip+instr_size, 0);
			instr_size += 4; // 4 bytes addr
			instr.displacement.v32bit = (v);
			sprintf(rv.asm_code, "call .%i", instr.displacement.v32bit);
			sprintf(rv.comment,"0x%x", regs.rip + instr_size + instr.displacement.v32bit);
			break;
		}
		case 0xeb:	// jmp
		{
			sprintf(rv.colored_hexdump, "%s%s%x%s", rv.colored_hexdump, get_color("jmp"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%x%s", rv.colored_hexdump, get_color("int"), bytes[instr_size], get_color(""));
			instr.displacement.v8bit = bytes[instr_size++];
			sprintf(rv.asm_code, "%sjmp%s .%s%i%s", get_color("jmp"), get_color(""), get_color("int"), instr.displacement.v8bit, get_color(""));
			sprintf(rv.comment, "0x%x", regs.rip + instr_size + instr.displacement.v8bit);
			break;
		}
		case 0xc7:	// mov v4, %r
		{
			sprintf(rv.colored_hexdump, "%s%s%x%s", rv.colored_hexdump, get_color("mov"), bytes[instr_size-1], get_color(""));
			instr.modrm=parse_modrm(instr,bytes[instr_size++]);
			if (instr.modrm.mod = 3){
				if ( instr.modrm.source == 0 ) {
					long unsigned tgt_addr = ptrace(PTRACE_PEEKTEXT, pid, regs.rip+(instr_size), 0);
					sprintf(a, "0x%x", tgt_addr);
					sprintf(b, r64a[instr.modrm.source]);
					sprintf(rv.asm_code, "mov %s, %s", a, b);
					sprintf(rv.comment, "");
				}
			}
			break;
		}
	}
	return rv;
}

//string_replace(target, template

void print_next_instruction(pid_t pid, long int ic, struct user_regs_struct regs, instruction_info * ptr_parsed_instruction){
	unsigned long addr = regs.rip;
	unsigned char bytes[8];
	get_instruction_bytes(pid, addr, (unsigned char *)&bytes);
	if ( ptr_parsed_instruction->asm_code[0] != 0 ){
		unsigned char colored_hexdump[256];
		printf("%sIC:%li|PID:%i|rip:0x%lx|%s|", get_color("gray"),
				ic, pid, regs.rip, ptr_parsed_instruction->colored_hexdump);fflush(stdout);
		int carry_flag = (regs.eflags & (1 << 0)) ? 1 : 0;
		int zero_flag = (regs.eflags & (1 << 6)) ? 1 : 0;
		/* substr(ptr_parsed_instruction->comment, "{ZF}", zero_flag ? "true" : "false"); */
		printf("%s%s%s|%s\n", get_color("white"), ptr_parsed_instruction->asm_code, get_color("gray"), ptr_parsed_instruction->comment);
		ptr_parsed_instruction->asm_code[0]=0;
		ptr_parsed_instruction->comment[0]=0;
		return;
	}
	int ok;
	// failed to detect the instruction, fallback to ndisasm without colors;
	printf("%sIC:%li|PID:%i|rip:0x%lx|%s|", get_color("gray"), ic, pid, regs.rip, ptr_parsed_instruction->hexdump);fflush(stdout);
	char ndisasm[256];
	sprintf(ndisasm, "/bin/sh -c '{ xxd --ps -r | ndisasm -b %i - | head -1 | tr -s \\  | cut -d \\  -f3-; } <<<\"%s\" '", 64, ptr_parsed_instruction->hexdump);
	printf("ndisasm: ");fflush(stdout);
	system(ndisasm);fflush(stdout);
}

/*
bytecode_parse_state
bytecode_parse_states {
	reading
	done
}
bytecode_parse_events {
	char_bits_starts with 0100 -> do_parse_operand_size
	* -> parse_modr/m
}
bytecode_parse_actions {
#  REX Bits:
#  |7|6|5|4|3|2|1|0|
#  |0|1|0|0|W|R|X|B|
#  W bit = Operand size 1==64-bits, 0 == legacy, depends on opcode.
#  R bit = Extends the ModR/M reg field to 4 bits. 0 selects RAX-RSI, 1 selects R8-R15
#  X bit = extends SIB 'index' field, same as R but for the SIB byte (memory operand)
#  B bit = extends the ModR/M r/m or 'base' field or the SIB field
	do_parse_rex -> (another state machine)
}
*/
/* arch_interact_user receives a user input and answer it
*/
void arch_interact_user(pid_t pid, struct user_regs_struct * regs, char * user_input) {
	if ( strcmp(user_input, "p rax") == 0 ) {
		printf("rax = 0x%lx\n", regs->rax);
	}
}
