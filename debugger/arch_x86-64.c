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
	unsigned char byte;
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
	if ( strcmp(item, "mov") == 0){
		return "\033[38;2;0;120;135m";
	}
	if ( strcmp(item, "add") == 0){
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
	if (instr.modrm.mod == 3) {
		if (!instr.prefix.rex.W && !instr.prefix.rex.R) {
			sprintf(a, r32a[instr.modrm.source]);
			return;
		}
		if (!instr.prefix.rex.W && instr.prefix.rex.R) {
			sprintf(a, r32b[instr.modrm.source]);
			return;
		}
		if (instr.prefix.rex.W && !instr.prefix.rex.R) {
			sprintf(a, r64a[instr.modrm.source]);
			return;
		}
		if (instr.prefix.rex.W && instr.prefix.rex.R) {
			sprintf(a, r64b[instr.modrm.source]);
			return;
		}
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
	if (instr.modrm.mod == 3) {
		if (!instr.prefix.rex.W && !instr.prefix.rex.B) {
			sprintf(b, r32a[instr.modrm.target]);
			return;
		}
		if (!instr.prefix.rex.W && instr.prefix.rex.B) {
			sprintf(b, r32b[instr.modrm.target]);
			return;
		}
		if (instr.prefix.rex.W && !instr.prefix.rex.B) {
			sprintf(b, r64a[instr.modrm.target]);
			return;
		}
		if (instr.prefix.rex.W && instr.prefix.rex.B) {
			sprintf(b, r64b[instr.modrm.target]);
			return;
		}
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
struct instruction instr;
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
	instr.prefix.type = prefix_type_of(bytes[0]);
	unsigned char instr_size = 0;
	switch (instr.prefix.type) {
		case REX:
			instr.prefix.rex.byte=bytes[0];
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
			sprintf(rv.colored_hexdump, "%s%02x%s%s", get_color("REX"), bytes[0], rex_binary_tips, get_color(""));
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
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("add"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color(""), bytes[instr_size], get_color(""));
			instr.modrm=parse_modrm(instr,bytes[instr_size++]);
			if ( instr.modrm.mod == 3 ){
				get_modrm_source(instr, (char*)&a);
				get_modrm_target(instr, (char*)&b);
				sprintf(rv.asm_code, "%sadd%s %s%s, %s", get_color("add"), get_color("") ,a, get_color(""), b);
				sprintf(rv.comment,"");
				break;
			}
			break;
		}
		case 0x31:	// xor
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("xor"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color(""), bytes[instr_size], get_color(""));
			instr.modrm=parse_modrm(instr, bytes[instr_size++]);
			get_modrm_source(instr, (char*)&a);
			get_modrm_target(instr, (char*)&b);
			sprintf(rv.asm_code, "xor %s, %s", a, b);
			break;
		}
		case 0x50:	// push %rax
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("push"), bytes[instr_size-1], get_color(""));
			sprintf(rv.asm_code, "push rax");
			sprintf(rv.comment, "0x%x", regs.rax);
			break;
		}
		case 0x74:	// jz short
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("jz"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("int"), bytes[instr_size], get_color(""));
			signed char v = bytes[instr_size++];
			sprintf(rv.asm_code, "jz .%s%i%s", get_color("int"), v, get_color(""));
			int carry_flag = (regs.eflags & (1 << 0));
			int zero_flag = (regs.eflags & (1 << 6));
			sprintf(rv.comment, "0x%x:%s", regs.rip + instr_size + v, zero_flag ? "true" : "false");
			break;
		}
		case 0x80:	// multiple one byte operations:
				// 	00-3f byte [64bit(a) reg]
				// 		add(00-07);
				// 		or(08-0F);
				// 		adc(10-17);
				// 		sbb(18-1F);
				// 		and(20-27);
				// 		sub(28-2F);
				// 		xor(30-37);
				// 		cmp(38-3F);
				// 	c0-ff byte reg
				//
				// 	no rex:	(al,cl,dl,bl,ah,ch,dh,bh)
				// 	rex:	(al,cl,dl,bl,spl,bpl,sil,dil)
				// 	rex.B:	(r8b-r15b)
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("cmp"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color(""), bytes[instr_size], get_color(""));
			instr.modrm=parse_modrm(instr, bytes[instr_size++]);
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("int"), bytes[instr_size], get_color(""));
			sprintf(a, "0x%x", bytes[instr_size++]);
			if (!instr.prefix.rex.B){
				sprintf(b, r8a[instr.modrm.target]);
			}
			if (instr.prefix.rex.B){
				sprintf(b, r8b[instr.modrm.target]);
			}
			sprintf(rv.asm_code, "cmp %s%s%s, %s", get_color("int"), a, get_color(""), b);
			unsigned char regv=(unsigned char) get_reg_val(b);
			sprintf(rv.comment, "%s:0x%x:%s", b, regv, regv == *b ? "true": "false");
			break;
		}
		case 0x83:
		{	// multiple one byte operations: 
			// 	00-3f(dword [32b reg]);
			// 		add(00-07);
			// 		or(08-0F);
			// 		adc(10-17);
			// 		sbb(18-1F);
			// 		and(20-27);
			// 		sub(28-2F);
			// 		xor(30-37);
			// 		cmp(38-3F);
			// 	C0-FF(32b reg):
			// 		add(C0-C7);
			// 		or(C8-CF);
			// 		adc(D0-D7);
			// 		sbb(D8-DF);
			// 		and(E0-E7);
			// 		sub(E8-EF);
			// 		xor(F0-F7);
			// 		cmp(F8-FF);
			//
			// 	no rex:	(eax,ecx,edx,ebx,esp,ebp,esi,edi)
			// 	rex.B:	(r8d-r15d)
			// 	rex.W:	(rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi)
			// 	rex.WB:	(r8-r15)

			//for ((i=0;i<256;i++)); do { xxd --ps -r | ndisasm -b 64 -; } <<<"83$( printf %02x $((16#00 + i)))00"; done | grep 83 | grep -v db
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("add"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("modrm"), bytes[instr_size], get_color(""));
			unsigned char opcode=bytes[instr_size++];
			signed char v8bit=bytes[instr_size++];
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("int"), v8bit, get_color(""));
			instr.displacement.v8bit = v8bit;
			sprintf(a, "%i", instr.displacement.v8bit);
			unsigned char regv=opcode % 8;
			char **regt = r32a;
			if (instr.prefix.type == REX){
				unsigned char W=instr.prefix.rex.W;
				unsigned char B=instr.prefix.rex.B;
				if (!W && B){
					regt = r32b;
				}
				if (W && !B){
					regt = r64a;
				}
				if (W && B){
					regt = r64b;
				}
			}
			printf("opcode=%x; regv[%i];\n", opcode,regv);
			sprintf(b,"%s", (char *)regt[regv]);
			sprintf(rv.comment, "");
			char * opmap[8] = {"add","or","adc","ssb","and","sub","xor","cmp"};
			char *op_s=opmap[(opcode & 0x38) >> 3]; // The operation is the 3 bits so use "and" over 00111000 and shift right to match the opmap index;
			printf("found operation [%s]\n",op_s);
			switch (opcode & 0xc0){
				case 0x00:
					sprintf(rv.asm_code, "%s%s %s%s%s, [%s]", get_color("op_s"), op_s, get_color("int"), a, get_color(""), b);
					break;
				case 0xc0:
					sprintf(rv.asm_code, "%s%s %s%s%s, %s", get_color(op_s), op_s, get_color("int"), a, get_color(""), b);
					break;
			}
			break;
		}
		case 0x89:	// mov
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("mov"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color(""), bytes[instr_size], get_color(""));
			instr.modrm=parse_modrm(instr,bytes[instr_size++]);
			if ( instr.modrm.mod == 3 ) { // 11
				get_modrm_source(instr, (char*)&a);
				get_modrm_target(instr, (char*)&b);
				sprintf(rv.asm_code, "%smov %s%s%s, %s%s%s", get_color("mov"), get_color("src_reg"), a, get_color(""), get_color("tgt_reg"), b, get_color(""));
				sprintf(rv.comment, "");
				break;
			}
			if ( instr.modrm.mod == 0 ) { // 00
				sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color(""), bytes[instr_size], get_color(""));
				unsigned char HAS_DISPLACEMENT=4;
				sprintf(a, r64a[instr.modrm.source]);
				if ( instr.modrm.target == HAS_DISPLACEMENT ) {
					unsigned int tgt_addr = ptrace(PTRACE_PEEKTEXT, pid, (void*)regs.rip+(++instr_size), 0);
					sprintf(rv.colored_hexdump, "%s%s%02x%02x%02x%02x%s", 
							rv.colored_hexdump, get_color("int"), 
							(unsigned char)(tgt_addr << 24 >> 24), 
							(unsigned char)(tgt_addr << 16 >> 24), 
							(unsigned char)(tgt_addr << 8 >> 24), 
							(unsigned char)(tgt_addr << 0 >> 24), 
							get_color(""));
					sprintf(b, "[%s0x%x%s]", get_color("int"),tgt_addr, get_color(""));
				}
				else
				{
					get_modrm_target(instr, (char*)&b);
				}
				sprintf(rv.asm_code, "%smov%s %s, %s", get_color("mov"), get_color(""), a, b);
				sprintf(rv.comment, "");
				break;
			}
			break;
		}
		case 0x8b:	// mov (%r), %r;
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("mov"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%02x", rv.colored_hexdump, bytes[instr_size]);
			instr.modrm=parse_modrm(instr,bytes[instr_size++]);
			if ( instr.modrm.mod == 0 ) { // 00
				get_modrm_source(instr, (char*)&b);
				get_modrm_target(instr, (char*)&a);
				sprintf(rv.asm_code, "%smov%s [%s], %s", get_color("mov"), get_color(""), a, b);
				sprintf(rv.comment, "");
				break;
			}
			break;
		}
		case 0xe8:	// call
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("call"), bytes[instr_size-1], get_color(""));
			long int v = ptrace(PTRACE_PEEKTEXT, pid, (void*)regs.rip+instr_size, 0);
			sprintf(rv.colored_hexdump, "%s%s%02x%02x%02x%02x%s", 
					rv.colored_hexdump, get_color("int"), 
					(unsigned char)(v << 24 >> 24), 
					(unsigned char)(v << 16 >> 24), 
					(unsigned char)(v << 8 >> 24), 
					(unsigned char)(v << 0 >> 24), 
					get_color(""));
			instr_size += 4; // 4 bytes addr
			instr.displacement.v32bit = (v);
			sprintf(rv.asm_code, "call .%s%i%s", get_color("int"), instr.displacement.v32bit, get_color(""));
			sprintf(rv.comment,"0x%x", regs.rip + instr_size + instr.displacement.v32bit);
			break;
		}
		case 0xeb:	// jmp
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("jmp"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("int"), bytes[instr_size], get_color(""));
			instr.displacement.v8bit = bytes[instr_size++];
			sprintf(rv.asm_code, "%sjmp%s .%s%i%s", get_color("jmp"), get_color(""), get_color("int"), instr.displacement.v8bit, get_color(""));
			sprintf(rv.comment, "0x%x", regs.rip + instr_size + instr.displacement.v8bit);
			break;
		}
		case 0xc7:	// mov v4, %r
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("mov"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color(""), bytes[instr_size], get_color(""));
			instr.modrm=parse_modrm(instr,bytes[instr_size++]);
			if (instr.modrm.mod = 3){
				if ( instr.modrm.source == 0 ) {
					long unsigned tgt_addr = ptrace(PTRACE_PEEKTEXT, pid, regs.rip+(instr_size), 0);
					sprintf(rv.colored_hexdump, "%s%s%02x%02x%02x%02x%s", 
							rv.colored_hexdump, get_color("int"), 
							(unsigned char)(tgt_addr << 24 >> 24), 
							(unsigned char)(tgt_addr << 16 >> 24), 
							(unsigned char)(tgt_addr << 8 >> 24), 
							(unsigned char)(tgt_addr << 0 >> 24), 
							get_color(""));
					sprintf(a, "0x%x", tgt_addr);
					sprintf(b, r64a[instr.modrm.source]);
					sprintf(rv.asm_code, "%smov %s%s%s, %s", get_color("mov"), get_color("int"), a, get_color(""), b);
					sprintf(rv.comment, "");
				}
			}
			break;
		}
	}
	return rv;
}

//string_replace(target, template

void ndisasm(char *hexdump)
{
	char ndisasm[256];
	sprintf(ndisasm, "/bin/sh -c '{ xxd --ps -r | ndisasm -b %i - | head -1 | tr -s \\  | cut -d \\  -f3-; } <<<\"%s\" '", 64, hexdump);
	//printf("%s", ndisasm);
	printf("ndisasm: ");fflush(stdout);
	system(ndisasm);fflush(stdout);
}
void print_next_instruction(pid_t pid, long int ic, struct user_regs_struct regs, instruction_info * ptr_parsed_instruction){
	unsigned long addr = regs.rip;
	unsigned char bytes[8];
	get_instruction_bytes(pid, addr, (unsigned char *)&bytes);
	if ( ptr_parsed_instruction->asm_code[0] != 0 ){
		unsigned char colored_hexdump[256];
		printf("%sIC:%li|PID:%i|rip:0x%lx|%s|", get_color("gray"),
				ic, pid, regs.rip, ptr_parsed_instruction->colored_hexdump);fflush(stdout);
		int carry_flag = (regs.eflags & (1 << 0));
		int zero_flag = (regs.eflags & (1 << 6));
		/* substr(ptr_parsed_instruction->comment, "{ZF}", zero_flag ? "true" : "false"); */
		printf("%s%s%s|%s\n", get_color("white"), ptr_parsed_instruction->asm_code, get_color("gray"), ptr_parsed_instruction->comment);
		return;
	}
	int ok;
	// failed to detect the instruction, fallback to ndisasm without colors;
	printf("%sIC:%li|PID:%i|rip:0x%lx|%s|", get_color("gray"), ic, pid, regs.rip, ptr_parsed_instruction->hexdump);fflush(stdout);
	ndisasm(ptr_parsed_instruction->hexdump);
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

void explain_modrm()
{
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
	printf("REX is \"%02x\": %s%s%s%s\n", instr.prefix.rex.byte, w, r , x, b );
	printf("ModR/M Byte \"%02x\"\n", instr.modrm.byte);
	printf("\twhere:\n\t\tmod=%i;\n", (instr.modrm.byte & 0xc0) >> 6);
	printf("\t\ta=%i\n", (instr.modrm.byte & 0x38) >> 3);
	printf("\t\tb=%i\n", instr.modrm.byte & 0x7);
}

/*
* arch_interact_user receives a user input and answer it
*/
void arch_interact_user(pid_t pid, struct user_regs_struct * regs, char * user_input) {
	if ( strcmp(user_input, "p rax") == 0 ) {
		printf("rax = 0x%lx\n", regs->rax);
	}
	if ( strcmp(user_input, "p rcx") == 0 ) {
		printf("rcx = 0x%lx\n", regs->rcx);
	}
	if ( strcmp(user_input, "p rdx") == 0 ) {
		printf("rdx = 0x%lx\n", regs->rdx);
	}
	if ( strcmp(user_input, "p rbx") == 0 ) {
		printf("rbx = 0x%lx\n", regs->rbx);
	}
	if ( strcmp(user_input, "p rsp") == 0 ) {
		printf("rsp = 0x%lx\n", regs->rsp);
	}
	if ( strcmp(user_input, "p rbp") == 0 ) {
		printf("rbp = 0x%lx\n", regs->rbp);
	}
	if ( strcmp(user_input, "p rsi") == 0 ) {
		printf("rsi = 0x%lx\n", regs->rsi);
	}
	if ( strcmp(user_input, "p rdi") == 0 ) {
		printf("rdi = 0x%lx\n", regs->rdi);
	}
	if ( strcmp(user_input, "p r8") == 0 ) {
		printf("r8 = 0x%lx\n", regs->r8);
	}
	if ( strcmp(user_input, "p r9") == 0 ) {
		printf("r9 = 0x%lx\n", regs->r9);
	}
	if ( strcmp(user_input, "p r10") == 0 ) {
		printf("r10 = 0x%lx\n", regs->r10);
	}
	if ( strcmp(user_input, "p r11") == 0 ) {
		printf("r11 = 0x%lx\n", regs->r11);
	}
	if ( strcmp(user_input, "p r12") == 0 ) {
		printf("r12 = 0x%lx\n", regs->r12);
	}
	if ( strcmp(user_input, "p r13") == 0 ) {
		printf("r13 = 0x%lx\n", regs->r13);
	}
	if ( strcmp(user_input, "p r14") == 0 ) {
		printf("r14 = 0x%lx\n", regs->r14);
	}
	if ( strcmp(user_input, "p r15") == 0 ) {
		printf("r15 = 0x%lx\n", regs->r15);
	}

	if ( strcmp(user_input, "p eax") == 0 ) {
		printf("eax = 0x%x\n", (unsigned long)regs->rax);
	}
	if ( strcmp(user_input, "p ecx") == 0 ) {
		printf("ecx = 0x%x\n", (unsigned long)regs->rcx);
	}
	if ( strcmp(user_input, "p edx") == 0 ) {
		printf("edx = 0x%x\n", (unsigned long)regs->rdx);
	}
	if ( strcmp(user_input, "p ebx") == 0 ) {
		printf("ebx = 0x%x\n", (unsigned long)regs->rbx);
	}
	if ( strcmp(user_input, "p esp") == 0 ) {
		printf("esp = 0x%x\n", (unsigned long)regs->rsp);
	}
	if ( strcmp(user_input, "p ebp") == 0 ) {
		printf("ebp = 0x%x\n", (unsigned long)regs->rbp);
	}
	if ( strcmp(user_input, "p esi") == 0 ) {
		printf("esi = 0x%x\n", (unsigned long)regs->rsi);
	}
	if ( strcmp(user_input, "p edi") == 0 ) {
		printf("edi = 0x%x\n", (unsigned long)regs->rdi);
	}
	if ( strcmp(user_input, "p r8d") == 0 ) {
		printf("r8d = 0x%x\n", (unsigned long)regs->r8);
	}
	if ( strcmp(user_input, "p r9d") == 0 ) {
		printf("r9d = 0x%x\n", (unsigned long)regs->r9);
	}
	if ( strcmp(user_input, "p r10d") == 0 ) {
		printf("r10d = 0x%x\n", (unsigned long)regs->r10);
	}
	if ( strcmp(user_input, "p r11d") == 0 ) {
		printf("r11d = 0x%x\n", (unsigned long)regs->r11);
	}
	if ( strcmp(user_input, "p r12d") == 0 ) {
		printf("r12d = 0x%x\n", (unsigned long)regs->r12);
	}
	if ( strcmp(user_input, "p r13d") == 0 ) {
		printf("r13d = 0x%x\n", (unsigned long)regs->r13);
	}
	if ( strcmp(user_input, "p e14") == 0 ) {
		printf("r14d = 0x%x\n", (unsigned long)regs->r14);
	}
	if ( strcmp(user_input, "p e15") == 0 ) {
		printf("r15d = 0x%x\n", (unsigned long) regs->r15);
	}
//char **r16a = (char *[]){ "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };
//char **r16b = (char *[]){ "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w" };
//char **r8a = (char *[]){ "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil" };
//char **r8b = (char *[]){ "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b" };
//char **r8bh = (char *[]){ "ah", "ch", "dh", "bh" };
	if ( strcmp(user_input, "p dil") == 0 ) {
		printf("dil = 0x%02x\n", (unsigned char)regs->rdi);
	}
	if ( strcmp(user_input, "p sil") == 0 ) {
		printf("sil = 0x%02x\n", (unsigned char)regs->rsi);
	}
	if ( strcmp(user_input, "p rip") == 0 ) {
		printf("rip = 0x%lx\n", regs->rip);
	}
	if ( strncmp(user_input, "px ", 3) == 0 ) {
		long unsigned vaddr;
		sscanf(&user_input[3], "%lx", &vaddr);
		long unsigned v = ptrace(PTRACE_PEEKTEXT, pid, (void*)vaddr, 0);
		printf("[0x%s]: %02x%02x %02x%02x %02x%02x %02x%02x\n", &user_input[3]
			, (unsigned char)(v << 56 >> 56)
			, (unsigned char)(v << 48 >> 56)
			, (unsigned char)(v << 40 >> 56)
			, (unsigned char)(v << 32 >> 56)
			, (unsigned char)(v << 24 >> 56)
			, (unsigned char)(v << 16 >> 56)
			, (unsigned char)(v << 8 >> 56)
			, (unsigned char)(v << 0 >> 56)
		);
	}
	if ( strncmp(user_input, "bc ", 3) == 0 ) {
		char cmd[4096];
		char vars[1024];
		vars[0]=0;
		sprintf(vars, "%srax=%lu;eax=%u;ax=%u;al=%u;ah=%u;", vars, regs->rax, (unsigned int)regs->rax, (unsigned short)regs->rax, (unsigned char)regs->rax, (unsigned char) (regs->rax >> 56));
		sprintf(vars, "%srcx=%lu;ecx=%u;cx=%u;cl=%u;ch=%u;", vars, regs->rcx, (unsigned int)regs->rcx, (unsigned short)regs->rcx, (unsigned char)regs->rcx, (unsigned char) (regs->rcx >> 56));
		sprintf(vars, "%srdx=%lu;edx=%u;dx=%u;dl=%u;dh=%u;", vars, regs->rdx, (unsigned int)regs->rdx, (unsigned short)regs->rdx, (unsigned char)regs->rdx, (unsigned char) (regs->rdx >> 56));
		sprintf(vars, "%srbx=%lu;ebx=%u;bx=%u;bl=%u;bh=%u;", vars, regs->rbx, (unsigned int)regs->rbx, (unsigned short)regs->rbx, (unsigned char)regs->rbx, (unsigned char) (regs->rbx >> 56));
		sprintf(cmd, "/bin/sh -c 'bc <<<\"%s%s\"'", vars, &user_input[3]);
		//printf("bc: %s\n",cmd);fflush(stdout);
		system(cmd);fflush(stdout);
	}
	if ( strcmp(user_input, "explain modrm") == 0 ){
		explain_modrm();
	}
	if ( strncmp(user_input, "ndisasm", 7) == 0 ){
		long unsigned vaddr = regs->rip;
		if (strlen(user_input) > 8){
			sscanf(&user_input[8], "%lx", &vaddr);
		}
		long unsigned v = ptrace(PTRACE_PEEKTEXT, pid, (void*)vaddr, 0);
		char hexdump[17];
		sprintf(hexdump,"%02x%02x%02x%02x%02x%02x%02x%02x"
			, (unsigned char)(v << 56 >> 56)
			, (unsigned char)(v << 48 >> 56)
			, (unsigned char)(v << 40 >> 56)
			, (unsigned char)(v << 32 >> 56)
			, (unsigned char)(v << 24 >> 56)
			, (unsigned char)(v << 16 >> 56)
			, (unsigned char)(v << 8 >> 56)
			, (unsigned char)(v << 0 >> 56)
		);
		ndisasm((char*)&hexdump);
	}
}
void get_current_address(char *s_curr_addr, struct user_regs_struct *regs){
	sprintf(s_curr_addr, "%x", regs->rip);
}
