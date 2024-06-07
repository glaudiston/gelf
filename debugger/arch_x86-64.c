#ifndef _ARCH_X86_64_
#define _ARCH_X86_64_
#include "debugger.h"
#include <sys/stat.h>
#define REX_B 1
#define REX_X 2
#define REX_R 4
#define REX_W 8
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
	unsigned char reg_opcode;	// Reg/Opcode
	unsigned char rm;	// RM
};
typedef enum {
	SIB_TYPE_NONE,
	SIB_TYPE_REG,
	SIB_TYPE_REG_REG_SCALE,
	SIB_TYPE_REG_SCALE_DISPLACEMENT32,
	SIB_TYPE_REG_IMM8,
	SIB_TYPE_IMM32,
	SIB_TYPE_DISPLACEMENT8,
	SIB_TYPE_DISPLACEMENT32,
} sib_type;
struct sib {
	sib_type type;
	unsigned char byte;
	unsigned char scale;
	unsigned char index;
	unsigned char base;
	unsigned long displacement;
};
struct instruction {
	int parsed;
	int rv;
	struct prefix prefix;
	unsigned char opcode; // operator
	struct modrm modrm;	// ModR/M
	union {
		signed char s1B;
		signed long s2B;
		signed long int s4B;
		signed long long int s8B;
	} displacement;
	union{
		unsigned char imm8;	// immediate 8bit value;
		unsigned short imm16;	// immediate 16bit value;
		unsigned int imm32;	// immediate 32bit value;
		unsigned long imm64;	// immediate 64bit value;
	} immediate;
	struct sib sib;
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
	if ( strcmp(item, "imm8") == 0){
		return "\033[38;2;50;100;80m";
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
#define SYS_GETEUID 107
	char syscall[512];
	char buff[256];
	switch (regs.rax) {
		case SYS_OPEN:
			peek_string(child, (void*)regs.rdi, buff); // filename
			sprintf(friendly_instr, "sys_open(\"%s\", \"%s\")", buff, (char*)&regs.rsi);
			break;
		case SYS_WRITE:
			peek_string(child, (void*)regs.rsi, buff);
			//long unsigned v = ptrace(PTRACE_PEEKTEXT, child, (void*)regs.rsi, 0);
			sprintf(friendly_instr, "sys_write(%lli, \"%s\", %lli)", regs.rdi, buff, regs.rdx);
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
			sprintf(friendly_instr, "sys_pipe(0x%llx);", regs.rdi);
			break;
		case SYS_DUP2:
			sprintf(friendly_instr, "sys_dup2(%llu,%llu);", regs.rdi, regs.rsi);
			break;
		case SYS_FORK:
			sprintf(friendly_instr, "sys_fork()");
			running_forks++;
			break;
		case SYS_EXECVE:
		{
			char filename[4096];
			char args[4096];
			char env[4096];
			peek_string(child, (void*)regs.rdi, filename);
			peek_array(child, (void*)regs.rsi, args);
			peek_array(child, (void*)regs.rdx, env);
			sprintf(friendly_instr, "sys_execve(file: \"%s\", args: %s, env: %s)", filename, args, env);
			break;
		}
		case SYS_EXIT:
			sprintf(friendly_instr, "sys_exit(%lli)%s",regs.rdi, get_color(""));
			break;
		case SYS_WAIT4:
			sprintf(friendly_instr, "sys_wait4(%lli,%lli,%lli,%lli)",regs.rdi,regs.rsi,regs.rdx, regs.r10);
			break;
		case SYS_GETEUID:
			sprintf(friendly_instr, "sys_geteuid");
			break;
		default:
			sprintf(friendly_instr, "# rax: %lli", regs.rax);
	}
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

void sprintx(unsigned char *buff, long unsigned v){
	sprintf(buff,"%02x%02x%02x%02x%02x%02x%02x%02x"
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
void sprintx4(unsigned char *buff, unsigned v){
	sprintf(buff, "%02x%02x%02x%02x",
		(unsigned char)(v << 24 >> 24), 
		(unsigned char)(v << 16 >> 24), 
		(unsigned char)(v << 8 >> 24), 
		(unsigned char)(v << 0 >> 24));
}
void sprintx_le(unsigned char *buff, long unsigned v){
	sprintf(buff,"%02x%02x%02x%02x%02x%02x%02x%02x"
		, (unsigned char)(v << 0 >> 56)
		, (unsigned char)(v << 8 >> 56)
		, (unsigned char)(v << 16 >> 56)
		, (unsigned char)(v << 24 >> 56)
		, (unsigned char)(v << 32 >> 56)
		, (unsigned char)(v << 40 >> 56)
		, (unsigned char)(v << 48 >> 56)
		, (unsigned char)(v << 56 >> 56)
	);
}

void get_instruction_bytes(pid_t pid, unsigned long addr, unsigned char * b){
	// data is composed of 4 bytes(32 bits) in a little-endian, so we need 2:
	uint32_t d1 = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr, 0);
	uint32_t d2 = ptrace(PTRACE_PEEKTEXT, pid, (void*)addr+4, 0);
	sprintx4(b, d1);
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
const char **r64a = (const char *[]){ "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi" };
const char **r64b = (const char *[]){ "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
const char **r32a = (const char *[]){ "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
const char **r32b = (const char *[]){ "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d" };
const char **r16a = (const char *[]){ "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };
const char **r16b = (const char *[]){ "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w" };
const char **r8a = (const char *[]){ "al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil" };
const char **r8b = (const char *[]){ "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b" };
const char **r8lh = (const char *[]){ "al", "cl", "dl", "bl", "ah", "ch", "dh", "bh" };

//TODO study check and implement; implement in get_reg_value?
//https://en.wikipedia.org/wiki/FLAGS_register
//https://www.aldeid.com/wiki/X86-assembly/Registers#OF_.28Overflow_Flag.29
#define CF 0
#define ZF 6
#define SF 7
#define OF 11
const char **flags = (const char *[]){
	"cf",
	"reserved1",
	"pf",
	"reserved3",
	"af",
	"reserved5",
	"zf",
	"sf",
	"tf",
	"if",
	"df",
	"of",
	"iopl",
	"iopl",
	"nt",
	"md"
};

const char **eflags = (const char*[]){
	"rf", "vm", "ac", "vif", "vip", "id", 
	"reserved", "reserved", "reserved", "reserved",
	"reserved", "reserved", "reserved", "reserved", "reserved", 
	"ai"
};
const char **rflags = (const char*[]){
	"reserved","reserved","reserved","reserved","reserved",
	"reserved","reserved","reserved","reserved","reserved",
	"reserved","reserved","reserved","reserved","reserved",
	"reserved","reserved","reserved","reserved","reserved",
	"reserved","reserved","reserved","reserved","reserved",
	"reserved","reserved","reserved","reserved","reserved",
	"reserved","reserved"
};

const char ***all_registers[]={&r64a,&r64b,&r32a,&r32b,&r16a,&r16b,&r8a,&r8b,&r8lh};
const char **all_registers_print_format = (const char*[]){ "%lu", "%lu", "%u", "%u", "%u", "%u", "%u", "%u", "%u" };

#define BITS_8 unsigned char
#define BITS_16 unsigned short
#define BITS_32 unsigned int
#define BITS_64 unsigned long long
unsigned long get_reg_value(const char * r)
{
	int i,j;
	for (i=0;i<9;i++){
		const char **rt=*all_registers[i];
		for (j=0; j<8; j++){
			if (strcmp(r,rt[j]) == 0){
				long long unsigned int r64a_ptr[] = { regs.rax, regs.rcx, regs.rdx, regs.rbx, regs.rsp, regs.rbp, regs.rsi, regs.rdi };
				long long unsigned int r64b_ptr[] = { regs.r8, regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15 };
				long long BITS_32 r32a_ptr[] = { (BITS_32)regs.rax, (BITS_32)regs.rcx, (BITS_32)regs.rdx, (BITS_32)regs.rbx, (BITS_32)regs.rsp, (BITS_32)regs.rbp, (BITS_32)regs.rsi, (BITS_32)regs.rdi };
				long long BITS_32 r32b_ptr[] = { (BITS_32)regs.r8, (BITS_32)regs.r9, (BITS_32)regs.r10, (BITS_32)regs.r11, (BITS_32)regs.r12, (BITS_32)regs.r13, (BITS_32)regs.r14, (BITS_32)regs.r15 };
				long long unsigned int r16a_ptr[] = { (BITS_16)regs.rax, (BITS_16)regs.rcx, (BITS_16)regs.rdx, (BITS_16)regs.rbx, (BITS_16)regs.rsp, (BITS_16)regs.rbp, (BITS_16)regs.rsi, (BITS_16)regs.rdi };
				long long unsigned int r16b_ptr[] = { (BITS_16)regs.r8, (BITS_16)regs.r9, (BITS_16)regs.r10, (BITS_16)regs.r11, (BITS_16)regs.r12, (BITS_16)regs.r13, (BITS_16)regs.r14, (BITS_16)regs.r15 };
				long long unsigned int r8a_ptr[] = { (BITS_8)regs.rax, (BITS_8)regs.rcx, (BITS_8)regs.rdx, (BITS_8)regs.rbx, (BITS_8)regs.rsp, (BITS_8)regs.rbp, (BITS_8)regs.rsi, (BITS_8)regs.rdi };
				long long unsigned int r8b_ptr[] = { (BITS_8)regs.r8, (BITS_8)regs.r9, (BITS_8)regs.r10, (BITS_8)regs.r11, (BITS_8)regs.r12, (BITS_8)regs.r13, (BITS_8)regs.r14, (BITS_8)regs.r15 };
				long long unsigned int r8lh_ptr[] = { (BITS_8)regs.rax, (BITS_8)regs.rcx, (BITS_8)regs.rdx, (BITS_8)regs.rbx, (BITS_8)(regs.rax >> 8), (BITS_8)(regs.rcx >> 8), (BITS_8)(regs.rdx >> 8), (BITS_16)(regs.rbx >> 8) };
				long long unsigned int *all_registers_ptr[]={r64a_ptr, r64b_ptr, r64a_ptr, r64b_ptr, r16a_ptr, r16b_ptr, r8a_ptr, r8b_ptr, r8lh_ptr};
				long long unsigned int v = all_registers_ptr[i][j];
				return v;
			}
		}
	}
	return -1;
}

char * a, b;

struct modrm parse_modrm(struct instruction instr, unsigned char byte){
	instr.modrm.byte=byte;
	instr.modrm.mod=( (instr.modrm.byte & 192) >> 6 );	// 11000000
	instr.modrm.reg_opcode=( (instr.modrm.byte & 56) >> 3 );	// 00111000
	instr.modrm.rm=instr.modrm.byte & 7;		// 00000111
	return instr.modrm;
}

struct sib parse_sib(struct instruction instr, unsigned char * bytes){
	struct sib sib = 
	{
		.type = SIB_TYPE_NONE,
		.byte = bytes[0],
		.base = 0,
		.scale = 1,
		.index = 0,
		.displacement = 0,
	};
	if (instr.modrm.mod == 3){
		sib.byte=0;
		return sib; // no sib
	}
	
	// 16-bit addressing mode (either BITS 16 with no 67 prefix, or BITS 32 with a 67 prefix)
	// I understand that the x64 processor boots at 16bit mode, can I set 16bit mode at userspace elf file?
	unsigned char is_16bit_addr_mode = false; // TODO implement 16 detection
	if (is_16bit_addr_mode){
		// in this path the SIB byte is never used.
		return sib;
	}

	unsigned char is_32bit_addr_mode = true;// TODO how to detect it; i think it is the default(when no rex present)
	if ( is_32bit_addr_mode && instr.modrm.mod == 0 && instr.modrm.rm == 5){
		sib.type = SIB_TYPE_DISPLACEMENT32;
		return sib;
	}

	if (instr.modrm.rm == 5){
		sib.type = SIB_TYPE_DISPLACEMENT32;
		return sib;
	}
	if(instr.modrm.rm == 4){
		sib.scale = 2 ^ ((sib.byte >> 6) & 3);
		if (sib.byte & 5){
			if (((sib.byte >> 3) & 7) == 4){
				sib.type = SIB_TYPE_IMM32;
				memcpy(&sib.displacement, &bytes[1], 4);
				return sib;
			}
			sib.type = SIB_TYPE_REG_SCALE_DISPLACEMENT32;
			memcpy(&sib.displacement, &bytes[1], 4);
			return sib;
		}
		if ((sib.byte & (7 << 3)) == (4<<3)){
			sib.type = SIB_TYPE_REG;
			return sib;
		}
		sib.type = SIB_TYPE_REG_REG_SCALE; // reg+reg*scale
		return sib;
	}
	return sib;
}

typedef enum{
	DISPLACEMENT_TYPE_NONE,
	DISPLACEMENT_TYPE_IMM8,
	DISPLACEMENT_TYPE_IMM32,
	DISPLACEMENT_TYPE_IMM64
} displacement_type;

struct displacement {
	displacement_type type;
	union {
		unsigned char imm8;
		unsigned char imm32[4];
		unsigned char imm64[8];
	};
};

struct displacement parse_displacement(struct instruction instr){
	struct displacement d = 
	{
		.type = DISPLACEMENT_TYPE_NONE
	};
	if ( instr.modrm.mod == 3 ){
		return d;
	}

	// In 16-bit addressing mode (either BITS 16 with no 67 prefix, or BITS 32 with a 67 prefix), the SIB byte is never used. The general rules for mod and r/m (there is an exception, given below) are:
	unsigned char is_16bit_addr_mode = instr.prefix.type = asize;
	if (is_16bit_addr_mode){
	}
	// 
	// The mod field gives the length of the displacement field: 0 means no displacement, 1 means one byte, and 2 means two bytes.
	// The r/m field encodes the combination of registers to be added to the displacement to give the accessed address: 0 means BX+SI, 1 means BX+DI, 2 means BP+SI, 3 means BP+DI, 4 means SI only, 5 means DI only, 6 means BP only, and 7 means BX only.
}

const char ** get_reg_map_WR(struct instruction instr)
{
	unsigned char W = instr.prefix.rex.byte & REX_W;
	unsigned char R = instr.prefix.rex.byte & REX_R;
	const char **rt = r32a;

	if (instr.prefix.type != REX) {
		return rt;
	}
	if (instr.modrm.mod == 3) {
		rt = W
			? (R ? r64b : r64a)
			: (R ? r32b : r32a);
		return rt;
	}

	/*
	rt = W
		? R ? r8a : r64a
		: R ? r64b: r64a;
	*/
	rt = W
		? R ? r64b : r64a
		: R ? r8b  : r32a;
	return rt;
}

void get_modrm_regopcode(struct instruction instr, char *a){
	const char **rt = get_reg_map_WR(instr);
	sprintf(a, rt[instr.modrm.reg_opcode]);
	return;
}

void get_modrm_rm(struct instruction instr, char *b, unsigned char *bytes){
	instr.sib=parse_sib(instr,bytes);
	const char **rt = r32a;
	if (instr.modrm.mod == 3) { // C0
		// C0-FF: means a register pair
		// 	No SIB for mod 3
		// 	No displacement for mod 3
		if (!instr.prefix.rex.W && !instr.prefix.rex.B) {
			sprintf(b, r32a[instr.modrm.rm]);
			return;
		}
		if (!instr.prefix.rex.W && instr.prefix.rex.B) {
			sprintf(b, r32b[instr.modrm.rm]);
			return;
		}
		if (instr.prefix.rex.W && !instr.prefix.rex.B) {
			sprintf(b, r64a[instr.modrm.rm]);
			return;
		}
		if (instr.prefix.rex.W && instr.prefix.rex.B) {
			sprintf(b, r64b[instr.modrm.rm]);
			return;
		}
	}
	if (instr.modrm.mod == 0){
		if (instr.modrm.rm == 4){
			// SIB Imm
			sprintf(b, "[0x%lx]", 
				instr.sib.displacement
			);
			return;
		}
		if (instr.modrm.rm == 5){
			// SIB
			sprintf(b, "SIB rel [0x%lx]", instr.sib.displacement);
			return;
		}
		if (instr.prefix.rex.W && instr.prefix.rex.B) {
			sprintf(b, r8a[instr.modrm.rm]);
			return;
		}
	}
	if (instr.prefix.rex.B) {
		sprintf(b,"[%s]",r64b[instr.modrm.rm]);
		return;
	}
	sprintf(b,"[%s]",r64a[instr.modrm.rm]);
}

long long unsigned int get_reg_val(char *r)
{
	if (strcmp(r,"rsi")==0) {
		return regs.rsi;
	}
}

/* multiple one byte operations: 
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

//for ((i=0;i<256;i++)); do { xxd --ps -r | ndisasm -b 64 -; } <<<"83$( printf %02x $((16#00 + i)))00"; done | grep 83 | grep -v db
*/
int multiple_one_byte_operation(instruction_info *instr_info, int instr_size, struct instruction *instr,
		const char **no_rex, const char** rex_b, const char** rex_w, const char **rex_wb)
{
	char a[50],b[50];
	char * opmap[8] = {"add","or","adc","ssb","and","sub","xor","cmp"};
	char * cxd = instr_info->colored_hexdump;
	sprintf(cxd, "%s%s%02x%s", cxd, get_color("add"), instr_info->bytes[instr_size-1], get_color(""));
	sprintf(cxd, "%s%s%02x%s", cxd, get_color("modrm"), instr_info->bytes[instr_size], get_color(""));
	unsigned char opcode=instr_info->bytes[instr_size++];
	signed char imm8=instr_info->bytes[instr_size++];
	sprintf(cxd, "%s%s%02x%s", cxd, get_color("int"), imm8, get_color(""));
	instr->immediate.imm8 = imm8;
	sprintf(a, "%i", imm8);
	unsigned char regv=opcode % 8;
	const char **regt = no_rex;
	if (instr->prefix.type == REX){
		unsigned char W=instr->prefix.rex.W;
		unsigned char B=instr->prefix.rex.B;
		if (!W && B){
			regt = rex_b;
		}
		if (W && !B){
			regt = rex_w;
		}
		if (W && B){
			regt = rex_wb;
		}
	}
	sprintf(b,"%s", (char *)regt[regv]);
	char *op_s=opmap[(opcode & 0x38) >> 3]; // The operation is the 3 bits so use "and" over 00111000 and shift right to match the opmap index;
	switch (opcode & 0xc0){
		case 0x00:
			sprintf(instr_info->asm_code, "%s%s %s%s%s, [%s]", get_color(op_s), op_s, get_color("int"), a, get_color(""), b);
			break;
		case 0xc0:
			sprintf(instr_info->asm_code, "%s%s %s%s%s, %s", get_color(op_s), op_s, get_color("int"), a, get_color(""), b);
			break;
	}
	sprintf(instr_info->comment, "before: 0x%x", get_reg_value(b));
	return instr_size;
}

struct instruction instr;
struct asm_operation{
	char asm_code[20];
	int argc;
	unsigned char has_imm8;
};

const char **detect_operand_a()
{
	const char **rt = r64a;
	//TODO mov all code from caller to here.
	return rt;
}

void multiple_operations(char * colored_hexdump, char * asm_code, unsigned char *bytes, struct asm_operation *operations)
{
	int instr_pos=0;
	// multiple operations:
	// (00-07): 48C10001          rol qword [rax],byte 0x1
	//  SIB-04: 48C1040102        rol qword [rcx+rax],byte 0x2
	//  SIB-05: 48C1050102030405  rol qword [rel 0x4030209],byte 0x5
	// (08-0f): 48C10801          ror qword [rax],byte 0x1
	//  SIB-0C: 48C10C0102        ror qword [rcx+rax],byte 0x2
	//  SIB-0D: 48C10D0102030405  ror qword [rel 0x4030209],byte 0x5
	// (10-17): 48C11001          rcl qword [rax],byte 0x1
	// (18-1f): 48C11801          rcr qword [rax],byte 0x1
	// (20-27): 48C12001          shl qword [rax],byte 0x1
	// (28-2f): 48C12801          shr qword [rax],byte 0x1
	// (30-37): 48C13001          sal qword [rax],byte 0x1
	// (38-3f): 48C13801          sar qword [rax],byte 0x1
	// (40-47): 48C1400102        rol qword [rax+0x1],byte 0x2
	// (48-4f): 48C1480102        ror qword [rax+0x1],byte 0x2
	// (50-57): 48C1500102        rcl qword [rax+0x1],byte 0x2
	// (58-5f): 48C1580102        rcr qword [rax+0x1],byte 0x2
	// (60-67): 48C1600102        shl qword [rax+0x1],byte 0x2
	// (68-6f): 48C1680102        shr qword [rax+0x1],byte 0x2
	// (70-77): 48C1700102        sal qword [rax+0x1],byte 0x2
	// (78-7f): 48C1780102        sar qword [rax+0x1],byte 0x2
	// (80-87): 48C1800102030405  rol qword [rax+0x4030201],byte 0x5
	// (88-8f): 48C1880102030405  ror qword [rax+0x4030201],byte 0x5
	// (90-97): 48C1900102030405  rcl qword [rax+0x4030201],byte 0x5
	// (98-9f): 48C1980102030405  rcr qword [rax+0x4030201],byte 0x5
	// (a0-a7): 48C1A00102030405  shl qword [rax+0x4030201],byte 0x5
	// (a8-af): 48C1A80102030405  shr qword [rax+0x4030201],byte 0x5
	// (b0-b7): 48C1B00102030405  sal qword [rax+0x4030201],byte 0x5
	// (b8-bf): 48C1B80102030405  sar qword [rax+0x4030201],byte 0x5
	// (c0-c7): 48C1C001          rol rax,byte 0x1
	// (c8-cf): 48C1C801          ror rax,byte 0x1
	// (d0-d7): 48C1D001          rcl rax,byte 0x1
	// (d8-df): 48C1D801          rcr rax,byte 0x1
	// (e0-e7): 48C1E001          shl rax,byte 0x1
	// (e8-ef): 48C1E801          shr rax,byte 0x1
	// (f0-f8): 48C1F001          sal rax,byte 0x1
	// (f8-ff): 48C1F801          sar rax,byte 0x1
	// IF NOT TEST C0;
	//    IF target is 100(rbp), uses SIB for regiters
	//    IF NOT TEST FOR 0x40;
	//      AND target is 101(rsp), uses SIB for memory displacement rel 32bit
	// 48C1050102030405  rol qword [rel 0x4030209],byte 0x5
	// for ((i=0;i<256;i++)); do { xxd --ps -r | ndisasm -b 64 -; } <<<"c1$( printf %02x $((16#00 + i)))010203040506070809010a0b0c0d0e0faa" | head -1; done  | cat -n
	sprintf(colored_hexdump, "%s%s%02x%s", colored_hexdump, get_color(""), bytes[instr_pos], get_color(""));
	instr.modrm=parse_modrm(instr,bytes[instr_pos+1]);
	sprintf(colored_hexdump, "%s%s%02x%s", colored_hexdump, get_color(""), bytes[++instr_pos], get_color(""));
	const char **rt,**rta,**rtb;
	rt=detect_operand_a();
	if (instr.prefix.type == REX){
		rta = instr.prefix.rex.byte & REX_B ? r64b : r64a;
		rtb = instr.prefix.rex.byte & REX_X ? r64b : r64a; 
		rt = rta;
	}
	instr.sib=parse_sib(instr, &bytes[instr_pos]);
	if (instr.modrm.mod == 0){
		if (instr.sib.type == SIB_TYPE_NONE){
			instr.immediate.imm8=bytes[++instr_pos];
			sprintf(asm_code,"%s %s%i%s, [%s]", operations[instr.modrm.reg_opcode], get_color("int"), 
					instr.immediate.imm8, get_color(""),
					rt[instr.modrm.rm]);
			return;
		}
		if (instr.sib.type == SIB_TYPE_REG){
		}
		if (instr.sib.type == SIB_TYPE_IMM32){
		}
		if (instr.sib.type == SIB_TYPE_DISPLACEMENT32){
			if (instr.modrm.rm == 4){
				instr.immediate.imm8=bytes[++instr_pos];
				sprintf(asm_code,"%s %s%i%s, [%s+%s]",operations[instr.modrm.reg_opcode], get_color("int"),instr.immediate.imm8, get_color(""), rta[instr.sib.index], rtb[instr.sib.base]);
				return;
			}
			if (instr.modrm.rm == 5){
				instr.immediate.imm32=*(unsigned int*)&bytes[++instr_pos];
				sprintf(asm_code,"%s %s%i%s, [rel %s]", operations[instr.modrm.reg_opcode], 
						get_color("int"),instr.immediate.imm32, get_color(""),
						rta[instr.sib.index]);
				return;
			}
		}
	}
	if (instr.modrm.mod == 2){
		if (instr.modrm.rm == 5){
			instr.immediate.imm32=*(unsigned int*)&bytes[++instr_pos];
			sprintf(asm_code,"%s %s%i%s, [rel %s]", operations[instr.modrm.reg_opcode], 
					get_color("int"),instr.immediate.imm32, get_color(""),
					rta[instr.sib.index]);
			return;
		}
	}
	if (instr.modrm.mod == 3){
		rt=get_reg_map_WR(instr);
		struct asm_operation *op=&operations[instr.modrm.reg_opcode];

		sprintf(asm_code, "%s%s%s",  
				get_color(op->asm_code), op->asm_code, get_color(""));

		if (op->argc > 0) {
			sprintf(asm_code,"%s %s", asm_code, rt[instr.modrm.rm]);
			if (op->argc > 1){
				if (op->has_imm8){
					instr.immediate.imm8=bytes[++instr_pos];
					sprintf(colored_hexdump, "%s%s%02x%s", colored_hexdump,
							get_color("int"), instr.immediate.imm8, get_color(""));
					sprintf(asm_code, "%s, %s%i%s", asm_code, get_color("imm8"), instr.immediate.imm8, get_color(""));
				}
			}
		}
	}
}

const char *operation_byte[]={ 
	"add to 8bit register",
	"add",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"multiple operations",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"xor",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"cmp",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"push rax/r8",
	"push rcx/r9",
	"push rdx/r10",
	"push rsp/r12",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"mov from reg",
	"unknown",
	"mov to reg",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"mov",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
	"unknown",
};
/**
 * try to parse the bytes populating the instr_struct;
 * if succeed set instr_struct->parsed=TRUE;
 * */
instruction_info parse_next_instruction(pid_t pid, struct user_regs_struct regs){
	int carry_flag = (regs.eflags & (1 << CF));
	int zero_flag = (regs.eflags & (1 << ZF));
	int sign_flag = (regs.eflags & (1 << SF));
	int overflow_flag = (regs.eflags & (1 << OF));
	instruction_info rv = {
		.print_request_size = 0,
		.address = regs.rip,
	};
	get_instruction_bytes(pid, regs.rip, (unsigned char*)&rv.bytes[0]);
	unsigned char *bytes=rv.bytes;
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
	sprintf(rv.comment,"");
	char a[256], b[256];
	switch (instr.opcode) {
		case 0x00:	// add to 8bit reg
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("add"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("add"), bytes[instr_size], get_color(""));
			instr.modrm=parse_modrm(instr,bytes[instr_size++]);
			const char **st=r64a;
			const char **tt=r8lh;
			if ( instr.prefix.type != REX ) {
				if (instr.modrm.mod < 3){
					st=r64a;
					tt=r8lh;
				}
			}
			if ( instr.prefix.type == REX ) {
				unsigned char W,R,X,B;
				W = instr.prefix.rex.W;
				R = instr.prefix.rex.R;
				X = instr.prefix.rex.X;
				B = instr.prefix.rex.B;
				if (!W && !R && !X && !B){
					st=r8a;
					tt=r8lh;
				}
			}
			if ( instr.modrm.mod == 3 ){
				sprintf(rv.asm_code, "%sadd%s %s%s, %s", get_color("add"), get_color("") ,st[instr.modrm.reg_opcode], get_color(""), tt[instr.modrm.rm]);
			}
			break;
		}
		case 0x01:	// add
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("add"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color(""), bytes[instr_size], get_color(""));
			instr.modrm=parse_modrm(instr,bytes[instr_size++]);
			if ( instr.modrm.mod == 3 ){
				get_modrm_regopcode(instr, (char*)&a);
				get_modrm_rm(instr, (char*)&b, &bytes[instr_size]);
				sprintf(rv.asm_code, "%sadd%s %s%s, %s", get_color("add"), get_color("") ,a, get_color(""), b);
				break;
			}
			break;
		}
		case 0x0f:
		{
			// for ((i=0;i<256;i++)); do { xxd --ps -r | ndisasm -b 64 -; } <<<"0f$( printf %02x $((16#00 + i)))0102030405" | head -1; done
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color(""), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color(""), bytes[instr_size], get_color(""));
			/*
00000000  0F0001            sldt [rcx]
00000000  0F0101            sgdt [rcx]
00000000  0F0201            lar eax,[rcx]
00000000  0F0301            lsl eax,[rcx]
00000000  0F                db 0x0f
00000000  0F05              syscall
*/
			if ( bytes[instr_size] == 0x05 ){
				sprintf(rv.asm_code, "syscall");
				char friendly_instr[255];
				detect_friendly_instruction(pid, regs.rip, friendly_instr);
				sprintf(rv.comment,"%s", friendly_instr);
				break;
			}

/*
00000000  0F06              clts
00000000  0F07              sysret
00000000  0F08              invd
00000000  0F09              wbinvd
00000000  0F                db 0x0f
00000000  0F0B              ud2
00000000  0F                db 0x0f
00000000  0F0D01            prefetch [rcx]
00000000  0F0E              femms
00000000  0F                db 0x0f
00000000  0F1001            movups xmm0,oword [rcx]
00000000  0F1101            movups oword [rcx],xmm0
00000000  0F1201            movlps xmm0,qword [rcx]
00000000  0F1301            movlps qword [rcx],xmm0
00000000  0F1401            unpcklps xmm0,oword [rcx]
00000000  0F1501            unpckhps xmm0,oword [rcx]
00000000  0F1601            movhps xmm0,qword [rcx]
00000000  0F1701            movhps qword [rcx],xmm0
00000000  0F1801            prefetchnta byte [rcx]
00000000  0F1901            hint_nop8 dword [rcx]
00000000  0F1A01            bndldx bnd0,[rcx]
00000000  0F1B01            bndstx [rcx],bnd0
00000000  0F1C01            cldemote [rcx]
00000000  0F1D01            hint_nop40 dword [rcx]
00000000  0F1E01            hint_nop48 dword [rcx]
00000000  0F1F01            nop dword [rcx]
00000000  0F                db 0x0f
00000000  0F                db 0x0f
00000000  0F                db 0x0f
00000000  0F                db 0x0f
00000000  0F                db 0x0f
00000000  0F                db 0x0f
00000000  0F                db 0x0f
00000000  0F                db 0x0f
00000000  0F2801            movaps xmm0,oword [rcx]
00000000  0F2901            movaps oword [rcx],xmm0
00000000  0F2A01            cvtpi2ps xmm0,qword [rcx]
00000000  0F2B01            movntps oword [rcx],xmm0
00000000  0F2C01            cvttps2pi mm0,[rcx]
00000000  0F2D01            cvtps2pi mm0,qword [rcx]
00000000  0F2E01            ucomiss xmm0,dword [rcx]
00000000  0F2F01            comiss xmm0,dword [rcx]
00000000  0F30              wrmsr
00000000  0F31              rdtsc
00000000  0F32              rdmsr
00000000  0F33              rdpmc
00000000  0F34              sysenter
00000000  0F35              sysexit
00000000  0F3601            rdshr dword [rcx]
00000000  0F37              getsec
00000000  0F380102          phaddw mm0,[rdx]
00000000  0F39              dmint
00000000  0F                db 0x0f
00000000  0F                db 0x0f
00000000  0F3C              cpu_write
00000000  0F3D              cpu_read
00000000  0F                db 0x0f
00000000  0F                db 0x0f
00000000  0F4001            cmovo eax,[rcx]
00000000  0F4101            cmovno eax,[rcx]
00000000  0F4201            cmovc eax,[rcx]
00000000  0F4301            cmovnc eax,[rcx]
00000000  0F4401            cmovz eax,[rcx]
00000000  0F4501            cmovnz eax,[rcx]
00000000  0F4601            cmovna eax,[rcx]
00000000  0F4701            cmova eax,[rcx]
00000000  0F4801            cmovs eax,[rcx]
00000000  0F4901            cmovns eax,[rcx]
00000000  0F4A01            cmovpe eax,[rcx]
00000000  0F4B01            cmovpo eax,[rcx]
00000000  0F4C01            cmovl eax,[rcx]
00000000  0F4D01            cmovnl eax,[rcx]
00000000  0F4E01            cmovng eax,[rcx]
00000000  0F4F01            cmovg eax,[rcx]
00000000  0F5001            paveb mm0,[rcx]
00000000  0F5101            sqrtps xmm0,oword [rcx]
00000000  0F5201            rsqrtps xmm0,oword [rcx]
00000000  0F5301            rcpps xmm0,oword [rcx]
00000000  0F5401            andps xmm0,oword [rcx]
00000000  0F5501            andnps xmm0,oword [rcx]
00000000  0F5601            orps xmm0,oword [rcx]
00000000  0F5701            xorps xmm0,oword [rcx]
00000000  0F5801            addps xmm0,oword [rcx]
00000000  0F5901            mulps xmm0,oword [rcx]
00000000  0F5A01            cvtps2pd xmm0,[rcx]
00000000  0F5B01            cvtdq2ps xmm0,[rcx]
00000000  0F5C01            subps xmm0,oword [rcx]
00000000  0F5D01            minps xmm0,oword [rcx]
00000000  0F5E01            divps xmm0,oword [rcx]
00000000  0F5F01            maxps xmm0,oword [rcx]
00000000  0F6001            punpcklbw mm0,[rcx]
00000000  0F6101            punpcklwd mm0,[rcx]
00000000  0F6201            punpckldq mm0,[rcx]
00000000  0F6301            packsswb mm0,[rcx]
00000000  0F6401            pcmpgtb mm0,[rcx]
00000000  0F6501            pcmpgtw mm0,[rcx]
00000000  0F6601            pcmpgtd mm0,[rcx]
00000000  0F6701            packuswb mm0,[rcx]
00000000  0F6801            punpckhbw mm0,[rcx]
00000000  0F6901            punpckhwd mm0,[rcx]
00000000  0F6A01            punpckhdq mm0,[rcx]
00000000  0F6B01            packssdw mm0,[rcx]
00000000  0F                db 0x0f
00000000  0F                db 0x0f
00000000  0F6E01            movd mm0,dword [rcx]
00000000  0F6F01            movq mm0,[rcx]
00000000  0F700102          pshufw mm0,[rcx],0x2
00000000  0F                db 0x0f
00000000  0F                db 0x0f
00000000  0F                db 0x0f
00000000  0F7401            pcmpeqb mm0,[rcx]
00000000  0F7501            pcmpeqw mm0,[rcx]
00000000  0F7601            pcmpeqd mm0,[rcx]
00000000  0F77              emms
00000000  0F7801            vmread qword [rcx],rax
00000000  0F7901            vmwrite rax,qword [rcx]
00000000  0F                db 0x0f
00000000  0F7B01            rsldt tword [rcx]
00000000  0F7C01            svts tword [rcx]
00000000  0F7D01            rsts tword [rcx]
00000000  0F7E01            movd dword [rcx],mm0
00000000  0F7F01            movq [rcx],mm0
00000000  0F8001020304      jo near 0x4030207
00000000  0F8101020304      jno near 0x4030207
00000000  0F8201020304      jc near 0x4030207
00000000  0F8301020304      jnc near 0x4030207
00000000  0F8401020304      jz near 0x4030207
*/
			if ( bytes[instr_size] == 0x84 ){
				instr.immediate.imm32=*(unsigned int*)&bytes[++instr_size];
				sprintf(rv.asm_code,"%s %s%i%s", "jz near", 
						get_color("int"),instr.immediate.imm32, get_color(""));
				char buf[30];
				sprintf(rv.colored_hexdump, "%s%s%02x%02x%02x%02x%s", rv.colored_hexdump, get_color("int")
						, bytes[instr_size+0]
						, bytes[instr_size+1]
						, bytes[instr_size+2]
						, bytes[instr_size+3]
						, get_color(""));
				sprintf(rv.comment, "0x%x: %s", regs.rip + instr_size + instr.immediate.imm32, zero_flag ? "true" : "false");
				break;
			}
/*
00000000  0F8501020304      jnz near 0x4030207
00000000  0F8601020304      jna near 0x4030207
00000000  0F8701020304      ja near 0x4030207
00000000  0F8801020304      js near 0x4030207
00000000  0F8901020304      jns near 0x4030207
00000000  0F8A01020304      jpe near 0x4030207
00000000  0F8B01020304      jpo near 0x4030207
00000000  0F8C01020304      jl near 0x4030207
00000000  0F8D01020304      jnl near 0x4030207
00000000  0F8E01020304      jng near 0x4030207
00000000  0F8F01020304      jg near 0x4030207
00000000  0F9001            seto [rcx]
00000000  0F9101            setno [rcx]
00000000  0F9201            setc [rcx]
00000000  0F9301            setnc [rcx]
00000000  0F9401            setz [rcx]
00000000  0F9501            setnz [rcx]
00000000  0F9601            setna [rcx]
00000000  0F9701            seta [rcx]
00000000  0F9801            sets [rcx]
00000000  0F9901            setns [rcx]
00000000  0F9A01            setpe [rcx]
00000000  0F9B01            setpo [rcx]
00000000  0F9C01            setl [rcx]
00000000  0F9D01            setnl [rcx]
00000000  0F9E01            setng [rcx]
00000000  0F9F01            setg [rcx]
00000000  0FA0              push fs
00000000  0FA1              pop fs
00000000  0FA2              cpuid
00000000  0FA301            bt [rcx],eax
00000000  0FA40102          shld [rcx],eax,0x2
00000000  0FA501            shld [rcx],eax,cl
00000000  0F                db 0x0f
00000000  0F                db 0x0f
00000000  0FA8              push gs
00000000  0FA9              pop gs
00000000  0FAA              rsm
00000000  0FAB01            bts [rcx],eax
00000000  0FAC0102          shrd [rcx],eax,0x2
00000000  0FAD01            shrd [rcx],eax,cl
00000000  0FAE01            fxsave [rcx]
00000000  0FAF01            imul eax,[rcx]
00000000  0FB001            cmpxchg [rcx],al
00000000  0FB101            cmpxchg [rcx],eax
00000000  0FB201            lss eax,[rcx]
00000000  0FB301            btr [rcx],eax
00000000  0FB401            lfs eax,[rcx]
00000000  0FB501            lgs eax,[rcx]
00000000  0FB601            movzx eax,byte [rcx]
00000000  0FB701            movzx eax,word [rcx]
00000000  0FB801020304      jmpe 0x4030207
00000000  0FB901            ud1 eax,dword [rcx]
00000000  0F                db 0x0f
00000000  0FBB01            btc [rcx],eax
00000000  0FBC01            bsf eax,[rcx]
00000000  0FBD01            bsr eax,[rcx]
00000000  0FBE01            movsx eax,byte [rcx]
00000000  0FBF01            movsx eax,word [rcx]
00000000  0FC001            xadd [rcx],al
00000000  0FC101            xadd [rcx],eax
00000000  0FC20102          cmpleps xmm0,oword [rcx]
00000000  0FC301            movnti [rcx],eax
00000000  0FC40102          pinsrw mm0,[rcx],0x2
00000000  0F                db 0x0f
00000000  0FC60102          shufps xmm0,oword [rcx],byte 0x2
00000000  0F                db 0x0f
00000000  0FC8              bswap eax
00000000  0FC9              bswap ecx
00000000  0FCA              bswap edx
00000000  0FCB              bswap ebx
00000000  0FCC              bswap esp
00000000  0FCD              bswap ebp
00000000  0FCE              bswap esi
00000000  0FCF              bswap edi
00000000  0F                db 0x0f
00000000  0FD101            psrlw mm0,[rcx]
00000000  0FD201            psrld mm0,[rcx]
00000000  0FD301            psrlq mm0,[rcx]
00000000  0FD401            paddq mm0,[rcx]
00000000  0FD501            pmullw mm0,[rcx]
00000000  0F                db 0x0f
00000000  0F                db 0x0f
00000000  0FD801            psubusb mm0,[rcx]
00000000  0FD901            psubusw mm0,[rcx]
00000000  0FDA01            pminub mm0,[rcx]
00000000  0FDB01            pand mm0,[rcx]
00000000  0FDC01            paddusb mm0,[rcx]
00000000  0FDD01            paddusw mm0,[rcx]
00000000  0FDE01            pmaxub mm0,[rcx]
00000000  0FDF01            pandn mm0,[rcx]
00000000  0FE001            pavgb mm0,[rcx]
00000000  0FE101            psraw mm0,[rcx]
00000000  0FE201            psrad mm0,[rcx]
00000000  0FE301            pavgw mm0,[rcx]
00000000  0FE401            pmulhuw mm0,[rcx]
00000000  0FE501            pmulhw mm0,[rcx]
00000000  0F                db 0x0f
00000000  0FE701            movntq [rcx],mm0
00000000  0FE801            psubsb mm0,[rcx]
00000000  0FE901            psubsw mm0,[rcx]
00000000  0FEA01            pminsw mm0,[rcx]
00000000  0FEB01            por mm0,[rcx]
00000000  0FEC01            paddsb mm0,[rcx]
00000000  0FED01            paddsw mm0,[rcx]
00000000  0FEE01            pmaxsw mm0,[rcx]
00000000  0FEF01            pxor mm0,[rcx]
00000000  0F                db 0x0f
00000000  0FF101            psllw mm0,[rcx]
00000000  0FF201            pslld mm0,[rcx]
00000000  0FF301            psllq mm0,[rcx]
00000000  0FF401            pmuludq mm0,[rcx]
00000000  0FF501            pmaddwd mm0,[rcx]
00000000  0FF601            psadbw mm0,[rcx]
00000000  0F                db 0x0f
00000000  0FF801            psubb mm0,[rcx]
00000000  0FF901            psubw mm0,[rcx]
00000000  0FFA01            psubd mm0,[rcx]
00000000  0FFB01            psubq mm0,[rcx]
00000000  0FFC01            paddb mm0,[rcx]
00000000  0FFD01            paddw mm0,[rcx]
00000000  0FFE01            paddd mm0,[rcx]
00000000  0FFF              ud0

			 * */
			break;
		}
		case 0x31:	// xor
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("xor"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color(""), bytes[instr_size], get_color(""));
			instr.modrm=parse_modrm(instr, bytes[instr_size++]);
			get_modrm_regopcode(instr, (char*)&a);
			get_modrm_rm(instr, (char*)&b, &bytes[instr_size]);
			sprintf(rv.asm_code, "xor %s, %s", a, b);
			break;
		}
		case 0x3c:	// cmp al, imm8
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("cmp"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("int"), bytes[instr_size], get_color(""));
			sprintf(rv.asm_code, "cmp %s%i%s, %s", get_color("int"), bytes[instr_size], get_color(""), "al");
			break;
		}
		case 0x50:	// push %rax/r8
		case 0x51:	// push %rcx/r9
		case 0x52:	// push %rdx/r10
		case 0x53:	// push %rbx/r11
		case 0x54:	// push %rsp/r12
		case 0x55:	// push %rbp/r13
		case 0x56:	// push %rsi/r14
		case 0x57:	// push %rdi/r15
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("push"), bytes[instr_size-1], get_color(""));
			const char **rt=r64a;
			if (instr.prefix.type == REX && instr.prefix.rex.B){
				rt=r64b;
			}
			const char *r=rt[instr.opcode-0x50];
			sprintf(rv.asm_code, "push %s", r);
			sprintf(rv.comment, "0x%x", get_reg_value(r));
			break;
		}
		case 0x58:	// pop %rax/r8
		case 0x59:	// pop %rcx/r9
		case 0x5a:	// pop %rdx/r10
		case 0x5b:	// pop %rbx/r11
		case 0x5c:	// pop %rsp/r12
		case 0x5d:	// pop %rbp/r13
		case 0x5e:	// pop %rsi/r14
		case 0x5f:	// pop %rdi/r15
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("pop"), bytes[instr_size-1], get_color(""));
			const char **rt=r64a;
			if (instr.prefix.type == REX && instr.prefix.rex.B){
				rt=r64b;
			}
			const char *r=rt[instr.opcode-0x58];
			sprintf(rv.asm_code, "pop %s", r);
			sprintf(rv.comment, "0x%x", get_reg_value(r));
			break;
		}
		case 0x6b:	// imul
		{
			// for ((i=0;i<256;i++)); do { xxd --ps -r | ndisasm -b 64 -; } <<<"6b$( printf %02x $((16#00 + i)))0102030405" | head -1; done
			//
			// 00000000  6B3C0102          imul edi,[rcx+rax],byte +0x2
			// 00000000  6B3D0102030405    imul edi,[rel 0x4030208],byte +0x5
			// 00000000  6B3F01            imul edi,[rdi],byte +0x1
			// 00000000  6B7C010203        imul edi,[rcx+rax+0x2],byte +0x3
			// 00000000  6B7F0102          imul edi,[rdi+0x1],byte +0x2
			// 00000000  6BBF0102030405    imul edi,[rdi+0x4030201],byte +0x5
			// 00000000  6BFF01            imul edi,edi,byte +0x1
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("imul"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("modrm"), bytes[instr_size], get_color(""));
			instr.modrm=parse_modrm(instr, bytes[instr_size++]);
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("int"), bytes[instr_size], get_color(""));
			get_modrm_regopcode(instr, (char*)&a);
			get_modrm_rm(instr, (char*)&b, &bytes[instr_size]);
			instr.immediate.imm8=bytes[instr_size++];
			sprintf(rv.asm_code, "%s %s*%s%i%s, %s", "imul", a, get_color("int"), instr.immediate.imm8, get_color(""), b);
			sprintf(rv.comment, "before: 0x%x", get_reg_value(b));
			break;
		}
		case 0x74:	// jz short
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("jz"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("int"), bytes[instr_size], get_color(""));
			signed char v = bytes[instr_size++];
			sprintf(rv.asm_code, "jz .%s%i%s", get_color("int"), v, get_color(""));
			sprintf(rv.comment, "0x%x:%s", regs.rip + instr_size + v, zero_flag ? "true" : "false");
			break;
		}
		case 0x75:	// jnz short
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("jnz"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("int"), bytes[instr_size], get_color(""));
			signed char v = bytes[instr_size++];
			sprintf(rv.asm_code, "jnz .%s%i%s", get_color("int"), v, get_color(""));
			sprintf(rv.comment, "0x%x:%s", regs.rip + instr_size + v, zero_flag ? "true" : "false");
			break;
		}
		case 0x7f:	// jg short
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("jg"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("int"), bytes[instr_size], get_color(""));
			signed char v = bytes[instr_size++];
			sprintf(rv.asm_code, "jg .%s%i%s", get_color("int"), v, get_color(""));
			sprintf(rv.comment, "0x%x:%s", regs.rip + instr_size + v, 
					sign_flag == overflow_flag && zero_flag == 0 ? "true" : "false");
			break;
		}
		case 0x80:
		{
			// 	no rex:	(al,cl,dl,bl,ah,ch,dh,bh)
			// 	rex:	(al,cl,dl,bl,spl,bpl,sil,dil)
			// 	rex.B:	(r8b-r15b)
			instr_size = multiple_one_byte_operation(&rv, instr_size, &instr, r8lh, r8b, r8a, r8b);
			break;
		}
		case 0x83:
		{
			// no rex:	(eax,ecx,edx,ebx,esp,ebp,esi,edi)
			// rex.B:	(r8d-r15d)
			// rex.W:	(rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi)
			// rex.WB:	(r8-r15)
			instr_size = multiple_one_byte_operation(&rv, instr_size, &instr, r32a, r32b,r64a,r64b);
			break;
		}
		case 0x88:	// mov 8 bit regs
		{
			unsigned char b2=bytes[instr_size-1];
			unsigned char b3=bytes[instr_size];
			sprintf(rv.colored_hexdump, "%02x%s%02x%s", b2, get_color("mov"), b3, get_color(""));
			instr.modrm = parse_modrm(instr, bytes[instr_size++]);
			if (instr.prefix.type == REX && instr.prefix.rex.byte==0x40){
				if (instr.modrm.mod == 3){
					const char *a=r8a[instr.modrm.reg_opcode];
					const char *b=r8a[instr.modrm.rm];
					sprintf(rv.asm_code, "%s%s%s %s, %s", get_color("mov"), "mov", get_color(""), a, b);
				}
			}
			break;
		}
		case 0x89:	// mov
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("mov"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color(""), bytes[instr_size], get_color(""));
			instr.modrm=parse_modrm(instr,bytes[instr_size++]);
			if ( instr.modrm.mod == 3 ) { // 11
				get_modrm_regopcode(instr, (char*)&a);
				get_modrm_rm(instr, (char*)&b, &bytes[instr_size]);
				sprintf(rv.asm_code, "%smov %s%s%s, %s%s%s", get_color("mov"), get_color("src_reg"), a, get_color(""), get_color("tgt_reg"), b, get_color(""));
				break;
			}
			instr.sib=parse_sib(instr, &bytes[instr_size]);
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color(""), bytes[instr_size], get_color(""));
			get_modrm_regopcode(instr, (char*)&a);
			get_modrm_rm(instr, (char*) &b, (unsigned char*)&bytes);
			if (instr.sib.type == SIB_TYPE_NONE){
				sprintf(rv.asm_code, "%smov%s %s, %s", get_color("mov"), get_color(""), a, b);
				break;
			}
			if (instr.sib.type == SIB_TYPE_IMM32){
				unsigned int tgt_addr = ptrace(PTRACE_PEEKTEXT, pid, (void*)regs.rip+(++instr_size), 0);
				unsigned char c[9];
				sprintx4(c, tgt_addr);
				sprintf(rv.colored_hexdump, "%s%s%s%s", 
						rv.colored_hexdump, get_color("int"), 
						c,
						get_color(""));
				sprintf(b, "[%s0x%x%s]", get_color("int"),tgt_addr, get_color(""));
			}
			/*
			unsigned char HAS_DISPLACEMENT=4;
			if ( instr.modrm.rm == HAS_DISPLACEMENT ) {
			}
			else
			{
				get_modrm_rm(instr, (char*)&b, &bytes[instr_size]);
			}
			*/
			sprintf(rv.asm_code, "%s%s%s %s, %s", get_color("mov"), "mov", get_color(""), a, b);
			break;
		}
		case 0x8b:	// mov (%r), %r;
		{
			/*
			 * Move r/m16 to r16.
			 * Move r/m32 to r32.
			 * Move r/m64 to r64.
			*/
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("mov"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%02x", rv.colored_hexdump, bytes[instr_size]);
			instr.modrm=parse_modrm(instr,bytes[instr_size++]);
			instr.sib=parse_sib(instr,&bytes[instr_size++]);
			if (instr.sib.type == SIB_TYPE_IMM32){
				get_modrm_rm(instr, (char*)&a, &bytes[instr_size-1]);
				get_modrm_regopcode(instr, (char*)&b);
				sprintf(rv.asm_code, "%s%s%s %s, %s", get_color("mov"), "mov", get_color(""), a, b);
				break;
			}
			get_modrm_rm(instr, (char*)&a, &bytes[instr_size-1]);
			get_modrm_regopcode(instr, (char*)&b);
			sprintf(rv.asm_code, "%s%s%s %s, %s", get_color("mov"), "mov", get_color(""), a, b);
			break;
			/*
			operation={
			{
				.asm_code="mov",
				.argc=2,
				.argv = { 
					{
						is_pointer
					}, 
					{
						.sib_op = {
							.has_sib_1=true,
							.has_sib_4
						}
					}
				}
			}
			detect_asm_operation(instr, op_params), 
			*/
		}
		case 0xb8:	// reg.W + b8-cf: mov r64
		case 0xb9:
		case 0xba:
		case 0xbb:
		case 0xbc:
		case 0xbd:
		case 0xbe:
		case 0xbf:
		{
			char *opcode_s="mov";
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color(opcode_s), bytes[instr_size-1], get_color(""));
			long unsigned tgt_addr = ptrace(PTRACE_PEEKTEXT, pid, regs.rip+instr_size, 0);
			char xd64[17];
			sprintx4(xd64, tgt_addr);
			sprintf(rv.colored_hexdump, "%s%s%s%s", rv.colored_hexdump, get_color("int"), xd64, get_color(""));
			const char ** rt=r32a;
			if ( instr.prefix.type == REX ){
				unsigned char W,R,X,B;
				W = instr.prefix.rex.W;
				R = instr.prefix.rex.R;
				X = instr.prefix.rex.X;
				B = instr.prefix.rex.B;
				if (W) {
					tgt_addr = ptrace(PTRACE_PEEKTEXT, pid, regs.rip+instr_size+4, 0);
					sprintx4(&xd64[4], tgt_addr);
					sprintf(rv.colored_hexdump, "%s%s%s%s", rv.colored_hexdump, get_color("int"), &xd64[4], get_color(""));
					if ( !B ) {
						rt=r64a;
					}
					if ( B ) {
						rt=r64b;
					}
				}
			}
			sprintf(b,"%s",r64a[instr.opcode-0xb8]);
			sprintf(rv.asm_code, "%s%s%s %s0x%s%s, %s", get_color(opcode_s), opcode_s, get_color(""), get_color("int"), xd64, get_color(""), b);
			break;
		}
		case 0xc0:
		{
			// multiple operation byte -> byte 
		}
		case 0xc1:
		{
			// multiple operation byte -> qword
			struct asm_operation asm_ops[8]={
				{
					.asm_code =	"rol",
					.argc = 2,
					.has_imm8=true,
				},
				{
					.asm_code = "ror",
					.argc = 2,
					.has_imm8=true,
				},
				{
					.asm_code = "rcl",
					.argc = 2,
					.has_imm8=true,
				},
				{
					.asm_code = "rcr",
					.argc = 2,
					.has_imm8=true,
				},
				{
					.asm_code = "shl",
					.argc = 2,
					.has_imm8=true,
				},
				{
					.asm_code = "shr",
					.argc = 2,
					.has_imm8=true,
				},
				{
					.asm_code = "sal",
					.argc = 2,
					.has_imm8=true,
				},
				{
					.asm_code = "sar",
					.argc = 2,
					.has_imm8=true,
				}
			};
			multiple_operations(rv.colored_hexdump, rv.asm_code, &bytes[instr_size-1], asm_ops);
			break;
		}
		case 0xc3:
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("ret"), bytes[instr_size-1], get_color(""));
			sprintf(rv.asm_code, "ret");
			break;
		}
		case 0xc7:	// mov v4, %r
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("mov"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color(""), bytes[instr_size], get_color(""));
			instr.modrm=parse_modrm(instr,bytes[instr_size++]);
			if (instr.modrm.mod == 3){
				if ( instr.modrm.reg_opcode == 0 ) {
					long unsigned tgt_addr = ptrace(PTRACE_PEEKTEXT, pid, regs.rip+(instr_size), 0);
					unsigned char c[9];
					sprintx4(c, tgt_addr);
					sprintf(rv.colored_hexdump, "%s%s%s%s", 
							rv.colored_hexdump, get_color("int"), 
							c,
							get_color(""));
					sprintf(a, "0x%x", tgt_addr);
					sprintf(b, r64a[instr.modrm.rm]);
					get_modrm_rm(instr, (char*)&b, &bytes[instr_size-1]);
					sprintf(rv.asm_code, "%s%s %s%s%s, %s", get_color("mov"), "mov", get_color("int"), a, get_color(""), b);
				}
			}
			break;
		}
		case 0xe8:	// call
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("call"), bytes[instr_size-1], get_color(""));
			long int v = ptrace(PTRACE_PEEKTEXT, pid, (void*)regs.rip+instr_size, 0);
			unsigned char c[9];
			sprintf(rv.colored_hexdump, "%s%s%i%s", 
					rv.colored_hexdump, get_color("int"), 
					c,
					get_color(""));
			instr_size += 4; // 4 bytes addr
			instr.displacement.s4B = (v);
			sprintf(rv.asm_code, "call .%s%i%s", get_color("int"), instr.displacement.s4B, get_color(""));
			sprintf(rv.comment,"0x%x", regs.rip + instr_size + instr.displacement.s4B);
			break;
		}
		case 0xe9:	// jmp
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("jmp"), bytes[instr_size-1], get_color(""));
			memcpy(&instr.immediate.imm32, &bytes[instr_size], 4);
			sprintf(rv.colored_hexdump, "%s%s%02x%02x%02x%02x%s", rv.colored_hexdump, get_color("int")
					, bytes[instr_size+0]
					, bytes[instr_size+1]
					, bytes[instr_size+2]
					, bytes[instr_size+3]
					, get_color(""));
			instr_size += 4;
			sprintf(rv.asm_code, "%sjmp%s .%s%i%s", get_color("jmp"), get_color(""), get_color("int"), (signed char)instr.immediate.imm8, get_color(""));
			sprintf(rv.comment, "0x%x", regs.rip + instr_size + instr.immediate.imm8);
			break;
		}
		case 0xeb:	// jmp
		{
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("jmp"), bytes[instr_size-1], get_color(""));
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("int"), bytes[instr_size], get_color(""));
			instr.immediate.imm8 = bytes[instr_size++];
			sprintf(rv.asm_code, "%sjmp%s .%s%i%s", get_color("jmp"), get_color(""), get_color("int"), (signed char)instr.immediate.imm8, get_color(""));
			sprintf(rv.comment, "0x%llx", regs.rip + instr_size + instr.immediate.imm8);
			break;
		}
		case 0xff:	// multiple operations
		{
			struct asm_operation op_t[8]=
			{
				{
					.asm_code = "inc",
					.argc = 1,
				},
				{
					.asm_code = "dec",
					.argc = 1,
				},
				{
					.asm_code = "call",
					.argc = 1,
				},
				{
					.asm_code = "call far",
					.argc = 1,
				},
				{
					.asm_code = "jmp qword",
					.argc = 1,
				},
				{
					.asm_code = "jmp far",
					.argc = 1,
				},
				{
					.asm_code ="push",
					.argc = 1,
				},
				{
					.asm_code = "",// pop?
					.argc = 1,
				}
			};
			multiple_operations(rv.colored_hexdump, rv.asm_code, &bytes[instr_size-1], op_t);
			break;
		}
	}
	return rv;
}

//string_replace(target, template

void ndisasm(unsigned char *hexdump)
{
	char ndisasm[256];
	sprintf(ndisasm, "/bin/sh -c '{ xxd --ps -r | ndisasm -b %i - | head -1 | tr -s \\  | cut -d \\  -f3-; } <<<\"%s\" '", 64, hexdump);
	//printf("%s", ndisasm);
	printf("ndisasm: ");fflush(stdout);
	system(ndisasm);fflush(stdout);
}

void capture_code_snipets(unsigned char *code_snippet, unsigned char *code_snippets, long long unsigned address)
{
	int i;
	size_t l=strlen(code_snippets);
	unsigned char line_buf[1<<16];
	int line_buf_pos=0;
	unsigned char field_str[1<<16];
	int field_pos=0;
	int field_address=4;
	int field_count=0;
	char addr_str[20];
	sprintf(addr_str, "%llu", address);
	unsigned char found=false;
	int code_snippet_pos=0;
	code_snippet[code_snippet_pos]=0;
	for (i=0; i<l; i++){
		char c = code_snippets[i];
		line_buf[line_buf_pos++] = c;
		line_buf[line_buf_pos] = 0;
		if (c == '\n'){
			if (found){
				sprintf(code_snippet, "%s%s", code_snippet, line_buf);
				found=0;
			}
			line_buf_pos=0;
			field_count=0;
			field_pos=0;
			continue;
		}
		if (c == ','){// expect to have parsed a field
			field_count++;
			if (field_count==field_address){// if found the field we are looking for
				if ( strcmp(field_str, addr_str) == 0 ) { // match found
					found=true;
				}
			}
			field_pos=0;
			field_str[0]=0;
			continue;
		}
		field_str[field_pos++] = c;
		field_str[field_pos]=0;
	}
}

// TODO change the compiler to include in the snip file the source file name and line number
void print_source_code(long long unsigned address)
{
	char filename[1024];
	sprintf(filename,"%s.snippets.round-3", cmd_options.filename);
	struct stat statbuf;
	if (lstat(filename, &statbuf) == -1){
		//perror("fail to load snippet file");
		return;
	}
	FILE *f=fopen(filename, "r");
	char code_snippets[1 << 16];
	ssize_t n = fread(code_snippets, statbuf.st_size, 1, f);
	char code_snippet[1 << 16];
	code_snippet[0]=0;
	capture_code_snipets(code_snippet, code_snippets, address);
	if (strlen(code_snippet) > 0){ // found snip
		//printf("** FOUND SNIP: \n%s", code_snippet);fflush(stdout);
		char cmd_buf[4096];
		sprintf(cmd_buf, "/bin/sh -c 'echo \"%s\" | cut -d, -f10 | while read l; do echo $l | base64 -d; echo; done'", code_snippet);
		system(cmd_buf);
		//printf("\n%s",cmd_buf);fflush(stdout);
	}
	fclose(f);
}

void print_next_instruction(pid_t pid, long int ic, struct user_regs_struct regs, instruction_info * ptr_parsed_instruction){
	unsigned long addr = regs.rip;
	unsigned char bytes[8];
	print_source_code(addr);
	get_instruction_bytes(pid, addr, (unsigned char *)&bytes);
	if ( ptr_parsed_instruction->asm_code[0] != 0 ){
		unsigned char colored_hexdump[256];
		printf("%sIC:%li|PID:%i|rip:0x%llx|%s|", get_color("gray"),
				ic, pid, regs.rip, ptr_parsed_instruction->colored_hexdump);fflush(stdout);
		int carry_flag = (regs.eflags & (1 << 0));
		int zero_flag = (regs.eflags & (1 << 6));
		/* substr(ptr_parsed_instruction->comment, "{ZF}", zero_flag ? "true" : "false"); */
		printf("%s%s%s|%s\n", get_color("white"), ptr_parsed_instruction->asm_code, get_color("gray"), ptr_parsed_instruction->comment);
		return;
	}
	int ok;
	// failed to detect the instruction, fallback to ndisasm without colors;
	printf("%sIC:%li|PID:%i|rip:0x%llx|%s|", get_color("gray"), ic, pid, regs.rip, ptr_parsed_instruction->hexdump);fflush(stdout);
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

void explain_instr(struct instruction instr)
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
	if (instr.prefix.type == REX){
		printf("REX: %02x: %s%s%s%s\n", instr.prefix.rex.byte, w, r , x, b);
	}
	printf("opcode:\t%02x: %s\n", instr.opcode, (char*)operation_byte[instr.opcode]);
	printf("ModR/M: %02x\n", instr.modrm.byte);
	printf("\tmod=%i;\n", instr.modrm.mod);
	printf("\treg_opcode=%i\n", instr.modrm.reg_opcode);
	printf("\trm=%i\n", instr.modrm.rm);
	if (instr.sib.type != SIB_TYPE_NONE){
		printf("sib: %02x\n", instr.sib.byte);
		printf("\ttype: %x\n", instr.sib.type);
		printf("\tscale: %x\n", instr.sib.scale);
		printf("\tbase: %x\n", instr.sib.base);
		printf("\tindex: %x\n", instr.sib.index);
			printf("\tdisplacement: 0x%lx\n", 
					instr.sib.displacement
			      );
	}
}

/*
* arch_interact_user receives a user input and answer it
*/
void arch_interact_user(pid_t pid, struct user_regs_struct * regs, char * user_input) {
	unsigned char hexstr[30];
	if (strncmp(user_input, "p ", 2) == 0) {
		const char *r=(const char *)&user_input[2];
		printf("%s: 0x%lx\n", r, get_reg_value(r));
	}
	if (strncmp(user_input, "pi ", 3) == 0) {
		long unsigned vaddr;
		sscanf(&user_input[3], "%lx", &vaddr);
		long unsigned v = ptrace(PTRACE_PEEKTEXT, pid, (void*)vaddr, 0);
		sprintx(hexstr, v);
		printf("[0x%s]: %s: %li\n", &user_input[3], hexstr, v);
	}
	if (strncmp(user_input, "px ", 3) == 0) {
		long unsigned vaddr;
		sscanf(&user_input[3], "%lx", &vaddr);
		long unsigned v = ptrace(PTRACE_PEEKTEXT, pid, (void*)vaddr, 0);
		sprintx(hexstr, v);
		printf("[0x%s]: %s\n", &user_input[3], hexstr);
	}
	if (strncmp(user_input, "px-le ", 6) == 0) {
		long unsigned vaddr;
		sscanf(&user_input[6], "%lx", &vaddr);
		long unsigned v = ptrace(PTRACE_PEEKTEXT, pid, (void*)vaddr, 0);
		sprintx_le(hexstr, v);
		printf("[0x%s]: %s\n", &user_input[3], hexstr);
	}
	if (strncmp(user_input, "ps ", 3) == 0) {
		long unsigned vaddr;
		sscanf(&user_input[3], "%lx", &vaddr);
		char buff[4096];
		peek_string_null(pid, (void*)vaddr, buff, true); // filename
		printf("[0x%s]: %s\n", &user_input[3], buff);
	}
	if (strncmp(user_input, "bc ", 3) == 0) {
		char cmd[4096];
		char vars[1024];
		vars[0]=0;
		char var_format[50];
		int i,j;
		for (i=0;i<9;i++){
			const char **rt=*all_registers[i];
			const char *rf = all_registers_print_format[i];
			for (j=0; j<8; j++){
				sprintf(var_format, "%s=%s;", "%s%s", rf);
				sprintf(vars, var_format, vars, rt[j], get_reg_value(rt[j]));
			}
		}
		sprintf(cmd, "/bin/sh -c 'bc <<<\"%s%s\"'", vars, &user_input[3]);
		//printf("bc: %s\n",cmd);fflush(stdout);
		system(cmd);fflush(stdout);
	}
	if ( strcmp(user_input, "explain") == 0 ){
		explain_instr(instr);
	}
	if ( strncmp(user_input, "ndisasm", 7) == 0 ){
		long unsigned vaddr = regs->rip;
		if (strlen(user_input) > 8){
			sscanf(&user_input[8], "%lx", &vaddr);
		}
		long unsigned v = ptrace(PTRACE_PEEKTEXT, pid, (void*)vaddr, 0);
		sprintx(hexstr, v);
		ndisasm(hexstr);
	}
}

void get_current_address(char *s_curr_addr, struct user_regs_struct *regs){
	sprintf(s_curr_addr, "%llx", regs->rip);
}

#endif
