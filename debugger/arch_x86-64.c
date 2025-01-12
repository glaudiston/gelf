#ifndef _ARCH_X86_64_
#define _ARCH_X86_64_
#include "./debugger.h"
#include <sys/stat.h>
#include "isa/x86_64/prefix.h"
#include "./colorscheme.c"
#include "./isa/x86_64/syscall-linux.c"
#include <math.h>

void print_previous_instruction_trace(pid_t pid, unsigned long int ic, struct user_regs_struct regs, instruction_info * ptr_parsed_instruction)
{
	int i;
	for ( i=0; i<ptr_parsed_instruction->print_request_size; i++ ) {
		//printf("here print_request_size %i\n", ptr_parsed_instruction->print_request_size);fflush(stdout);
		struct print_addr_request pr = ptr_parsed_instruction->print_request[i];
		printMemoryValue(pid, pr.addr, 0);
	}
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

void get_instruction_bytes(
		pid_t pid,
		unsigned long addr,
		unsigned char * target){
	long int src;
	int i=0;
	for (i=0; i<4;i++){
		src	= ptrace(PTRACE_PEEKTEXT, pid, (void*)addr+(4*i), 0);
		memcpy(&target[i*4], (void*)&src,4);
		//printf("got bytes:%02x%02x%02x%02x\n",target[i*4], target[i*4+1], target[i*4+2], target[i*4+3]);
	}
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
const char **r64 = (const char *[]){
	"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi",
	"r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
	"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
	"r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
};
const char **r32a = (const char *[]){ "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi" };
const char **r64a = (const char *[]){ "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi" };
const char **r32b = (const char *[]){ "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d" };
const char **r64b = (const char *[]){ "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15" };
const char **r16a = (const char *[]){ "ax", "cx", "dx", "bx", "sp", "bp", "si", "di" };
const char **r16b = (const char *[]){ "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w" };
const char **r8 = (const char *[]){
	"al", "cl", "dl", "bl", "spl", "bpl", "sil", "dil",
	"r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"
};
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
	if (strcmp(r, "rip") == 0) {
		return regs.rip;
	}
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

struct prefix *get_rep_prefix(struct instruction instr){
	if (!instr.prefixes){
		return false;
	}
	struct prefix *p;
	int i=0;
	for(;i<instr.prefix_cnt;i++){
		p=(struct prefix *)&instr.prefixes[i];
		if (p->type == REP){
			return p;
		}
	}
	return false;
}
struct prefix *get_rex_prefix(struct instruction instr){
	if (!instr.prefixes){
		return false;
	}
	struct prefix *p;
	int i=0;
	for(;i<instr.prefix_cnt;i++){
		p=(struct prefix *)&instr.prefixes[i];
		if (p->type == REX){
			return p;
		}
	}
	return false;
}
// Intel Architecture Processor Modes
// Ref: https://www.tomshardware.com/reviews/processor-cpu-apu-specifications-upgrade,3566-5.html
enum e_ia_mode{
	MODE_REAL,	// Aka "8086 Mode"
				// * 16bit
				// * single task with exclusive control
				// * No memory protection or paging;
				// * Only allows access to 1 megabyte of RAM, with some of it being reserved for the BIOS and the frame buffer.
				// * UEFI already setup protected or long mode depending on whether it's a 32 or 64 bit system.
	MODE_UNREAL,	// "Unreal mode"
					// consists of breaking the 64KiB limit of real mode segments (while retaining 16-bit instructions and the segment * 16 + offset addressing mode) by tweaking the descriptor caches.
	MODE_PROTECTED,	// Aka "IA-32 Mode"
					// Normal mode for userland(allows virtual memory and multitask)
					//		* Programs are "protected" from overwriting one another in memory
					//		* A crashed program can be terminated while the rest of the system continues to run unaffected.
					// Is "Protected Mode" the same as "IA-32 Mode"?
					// * Allows memory access either linearly or in segments;
					// * Paging with a virtual address space of 4GB;
					// * Support for either 4GB or 64GB of physical addresses depending on whether the Physical Address Extension (PAE) is enabled, and page-specific memory protections.
	MODE_VIRTUAL_8086,	// aka "virtual real mode"
						// is a protected mode that allow access BIOS functions
						// Real mode applications could run in protected mode thanks to virtual mode which emulated real mode in 32 bit operating systems, but this mode is not available in long mode so you can no longer run any real mode code inside a 64 bit operating system.
						// Was created to allow legacy programs(like MS-DOS target) to run in protected mode.
						// Funny fact: That "Turbo" buttom on old PC's was set to activate this mode(Turbo 8088); which means the processor has the advantage of speed in running any 16-bit programs; So "turbo" make the systems restricted to 1MB.
						// Windows 3.x was the last 16-bit OS
						// Note that any program running in a virtual real mode window can access up to only 1MB of memory, which that program will believe is the first and only megabyte of memory in the system. In other words, if you run a DOS application in a virtual real window, it will have a 640 KB limitation on memory usage. That is because there is only 1 MB of total RAM in a 16-bit environment, and the upper 384KB is reserved for system use. The virtual real window fully emulates an 8088 environment, so that aside from speed, the software runs as if it were on an original real mode–only PC. Each virtual machine gets its own 1 MB address space, an image of the real hardware basic input/output system (BIOS) routines, and emulation of all other registers and features found in real mode.
	MODE_LONG,	// ?? is it the same as IA-32E ?
				// * Long mode removes the ability to use segmented memory;
				// * Offers paging with virtual and physical addresses up to 16 exabytes, though current implementations are usually limited to smaller values like 64 petabytes of virtual address space and 256 terabytes of physical address space.
	MODE_IA_32E_64_BIT,			// Enables a 64-bit operating system to run applications written to access 64-bit address space
								// IA-32e 64-Bit Extension Mode (x64, AMD64, x86-64, EM64T)
								// A-32e mode allows the processor to run in 64-bit mode and compatibility mode, which means you can run both 64-bit and 32-bit applications simultaneously. IA-32e mode includes two submodes:
								//   64-bit mode—Enables a 64-bit OS to run 64-bit applications
								//   Compatibility mode—Enables a 64-bit OS to run most existing 32-bit software
								//   IA-32e 64-bit mode is enabled by loading a 64-bit OS and is used by 64-bit applications. In the 64-bit submode, the following new features are available:
								//       n64-bit linear memory addressing
								//       nPhysical memory support beyond 4GB (limited by the specific processor)
								//       nEight new general-purpose registers (GPRs)
								//       nEight new registers for streaming SIMD extensions (MMX, SSE, SSE2, and SSE3)
								//       n64-bit-wide GPRs and instruction pointers
	MODE_IA_32E_COMPATIBILITY,	// Enables a 64-bit operating system to run most legacy protected mode software unmodified.
								// IE-32e compatibility mode enables 32-bit and 16-bit applications to run under a 64-bit OS. Unfortunately, legacy 16-bit programs that run in virtual real mode (that is, DOS programs) are not supported and will not run, which is likely to be the biggest problem for many users, especially those that rely on legacy business applications or like to run very old games. Similar to 64-bit mode, compatibility mode is enabled by the OS on an individual code basis, which means 64-bit applications running in 64-bit mode can operate simultaneously with 32-bit applications running in compatibility mode.
};

enum e_addressing_mode {
	ADDR_16BIT,
	ADDR_32BIT,
	ADDR_64BIT,
};

enum e_addressing_mode get_addressing_mode()
{
	return ADDR_32BIT;
}

int has_prefix(e_prefix_type pt, struct instruction instr){
	if (!instr.prefixes){
		return false;
	}
	struct prefix *p;
	int i=0;
	for(;i<instr.prefix_cnt;i++){
		p=(struct prefix *)&instr.prefixes[i];
		if (p->type == pt){
			return true;
		}
	}
	return false;
}
int is_16bit_addr_mode(struct instruction instr){
	return has_prefix(asize, instr);
}
int has_prefix_rex(struct instruction instr){
	return has_prefix(REX, instr);
}

const char ** get_reg_map_WR(struct instruction instr)
{
	const char **rt = r32a;
	if (!has_prefix_rex(instr)){
		return rt;
	}

	struct prefix *prefix = get_rex_prefix(instr);
	unsigned char W = prefix && prefix->rex.byte & REX_W;
	unsigned char R = prefix && prefix->rex.byte & REX_R;
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

void get_imm_8_16_32_64(void *instr_ptr, char *target)
{
	struct instruction *instr = instr_ptr;
	switch (instr->immediate.type){
		case IMM_NONE:
			sprintf(target, "");
			break;
		case IMM8:
			sprintf(target, "%i", instr->immediate.value.imm8);
			break;
		case IMM16:
			sprintf(target, "%i", instr->immediate.value.imm16);
			break;
		case IMM32:
			sprintf(target, "%i", instr->immediate.value.imm32);
			break;
		case IMM64:
			sprintf(target, "%i", instr->immediate.value.imm64);
			break;
	}
}
void get_modrm_regopcode(void * instr_ptr, char *s_operand){
	struct instruction *instr = instr_ptr;
	struct prefix *prefix = get_rex_prefix(*instr);
	unsigned char W = (prefix && prefix->rex.W) << 4;
	unsigned char R = (prefix && prefix->rex.R) << 3;
	sprintf(s_operand, r64[ W | R | instr->modrm.reg_opcode]);
	// printf("reg operand: %s\n", s_operand);
	return;
}
void get_modrm_r8(struct instruction instr, char *r, unsigned char *bytes){
	const char **rt = r8a;
	sprintf(r, rt[instr.modrm.rm]);
}
void get_modrm_m8(struct instruction instr, char *m){
	const char **rt = r8a;
	sprintf(m, rt[instr.modrm.rm]);
}
void get_modrm_rm8(void *instr_ptr, char *s_operand)
{
	struct instruction *instr = instr_ptr;
	struct prefix *prefix = get_rex_prefix(*instr);
	unsigned char R = (prefix && prefix->rex.R) << 3;
	sprintf(s_operand, r8[R|instr->modrm.rm]);
}
void get_modrm_rm(void * instr_ptr, char *s_operand){
	struct instruction *instr = instr_ptr;
	struct prefix *prefix = get_rex_prefix(*instr);
	unsigned char W = (prefix && prefix->rex.W) << 4;
	unsigned char B = (prefix && prefix->rex.B) << 3;
	sprintf( s_operand, instr->modrm.mod == 3 ?"%s" : "[%s]",r64[W|B|instr->modrm.rm]);
	char base[100];
	if (instr->modrm.mod == 0){
		switch (instr->modrm.rm & 7){
			case 4:
			{
				// SIB Imm
				switch (instr->sib.type){
					case SIB_TYPE_IMM32:
					case SIB_TYPE_DISPLACEMENT32:
					case SIB_TYPE_REG_SCALE_DISPLACEMENT32:
					{
						sprintf(base, "0x%lx", instr->displacement.value.s4B);
						break;
					}
					default:
						sprintf(base, "..%i..", instr->sib.base);
				}
				bool print_scale = instr->sib.scale > 1;
				bool print_index = (instr->sib.index & 4) != 4; // rbp means to use displacement
				char s_scale[20];
				sprintf(s_scale, "%i", instr->sib.scale);
				sprintf(s_operand, "[%s%s%s%s%s]",
						print_scale ? s_scale : "",
						(print_scale && print_index) ? "*":"",
						print_index ? r64[instr->sib.index] : "",
						print_index ? "+":"",
						base);
				break;
			}
			case 5:
			{
				// SIB
				sprintf(s_operand, "[rel 0x%lx]", instr->displacement.value.s4B);
				break;
			}
		}
	}
	//printf("modrm rm operand: %s\n", s_operand);
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
	char s_operand_1[50],s_operand_2[50];
	char * opmap[8] = {"add","or","adc","ssb","and","sub","xor","cmp"};
	signed char imm8=instr->immediate.value.imm8;
	instr->immediate.value.imm8 = imm8;
	sprintf(s_operand_2, "%i", imm8);
	unsigned char regv=instr->modrm.byte % 8;
	const char **regt = no_rex;
	struct prefix *prefix = get_rex_prefix(*instr);
	if (prefix){
		unsigned char W=prefix->rex.W;
		unsigned char B=prefix->rex.B;
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
	sprintf(s_operand_1,"%s", (char *)regt[regv]);
	char *op_s=opmap[(instr->modrm.byte & 0x38) >> 3]; // The operation is the 3 bits so use "and" over 00111000 and shift right to match the opmap index;
	switch (instr->modrm.byte & 0xc0){
		case 0x00:
			sprintf(instr_info->asm_code, "%s%s %s%s%s, [%s]", get_color(op_s), op_s, get_color("int"), s_operand_1, get_color(""), s_operand_2);
			break;
		case 0xc0:
			sprintf(instr_info->asm_code, "%s%s %s%s%s, %s", get_color(op_s), op_s, get_color("int"), s_operand_1, get_color(""), s_operand_2);
			break;
	}
	sprintf(instr_info->comment, "before: 0x%x", get_reg_value(s_operand_1));
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

struct parsed_info{
	int parsed_bytes;
	char colored_hexdump[256];
	void *ptr;
	int ptr_cnt;
};

struct parsed_info parse_prefixes(struct instruction instr, unsigned char *bytes){
	struct parsed_info parsed_info={
		.parsed_bytes=0,
		.colored_hexdump = "",
		.ptr_cnt = 0,
		.ptr=instr.prefixes,
	};
	struct prefix prefix;
	parsed_info.ptr = realloc(parsed_info.ptr, sizeof(struct prefix) * parsed_info.ptr_cnt);
	while ( (prefix = parse_prefix(bytes[parsed_info.ptr_cnt])).type != PREFIX_NONE ){
		sprintf(parsed_info.colored_hexdump, "%s%02x%s", get_color("prefix"), bytes[parsed_info.parsed_bytes], get_color(""));
		parsed_info.parsed_bytes++;
		parsed_info.ptr_cnt++;
		parsed_info.ptr = realloc(parsed_info.ptr, sizeof(struct prefix) * parsed_info.ptr_cnt);
		void *t = parsed_info.ptr+(sizeof(struct prefix) * (parsed_info.ptr_cnt-1));
		//equivalent to:
		//t = &((struct prefix**)parsed_info.ptr)[parsed_info.ptr_cnt-1];
		memcpy(t, &prefix, sizeof(struct prefix));
		struct prefix *p=parsed_info.ptr;
	}
	return parsed_info;
}

map map_opcode;

int get_opcode_bytesize(enum e_opcode_size opcode_size){
	int key_size;
	switch (opcode_size) {
		case opcode_size_5_bits:
		case opcode_size_8_bits:
			key_size = 1;
			break;
		case opcode_size_12_bits:
		case opcode_size_13_bits:
		case opcode_size_16_bits:
			key_size = 2;
			break;
	}
	return key_size;
}

struct instruction_spec *get_instr_spec_n(unsigned char *bytes, enum e_opcode_size opcode_size)
{
	unsigned char search_key[2];
	search_key[0] = bytes[0] & (
			opcode_size == opcode_size_5_bits ? 0xf8 :
			0xff);
	search_key[1] = bytes[1] & (
			opcode_size == opcode_size_13_bits ? 0xf8 :
			opcode_size == opcode_size_12_bits ? 0xf0 :
			0xff);
	int key_size = get_opcode_bytesize(opcode_size);
	return map_get(&map_opcode, search_key, key_size);
}

struct instruction_spec *get_instr_spec(unsigned char *bytes){
	struct instruction_spec *instr_spec;
	instr_spec = get_instr_spec_n(bytes, opcode_size_8_bits);
	if (instr_spec){
		return instr_spec;
	}
	instr_spec = get_instr_spec_n(bytes, opcode_size_5_bits);
	if (instr_spec){
		return instr_spec;
	}
	instr_spec = get_instr_spec_n(bytes, opcode_size_16_bits);
	if (instr_spec){
		return instr_spec;
	}
	instr_spec = get_instr_spec_n(bytes, opcode_size_13_bits);
	if (instr_spec){
		return instr_spec;
	}
	instr_spec = get_instr_spec_n(bytes, opcode_size_12_bits);
	if (instr_spec){
		return instr_spec;
	}
	//unsigned char multicode[1];
	//multicode[0] = (bytes[0] >> 3) << 3;
	//printf("fail to get instr spec for {%02x,%02x}, trying multi-opcode for %x...", bytes[0], bytes[1], multicode[0]); fflush(stdout);
	//instr_spec = map_get(&map_opcode, (unsigned char*)multicode, 1);
	//printf("got: %p\n", instr_spec);fflush(stdout);
	//return instr_spec;
}

struct opcode parse_opcode(struct instruction_spec *instr_spec, struct instruction instr, void *bytes){
	struct opcode opcode;
	int bytesize = get_opcode_bytesize(instr_spec->opcode.size);
	opcode.bytes[0] = ((char*)bytes)[0];
	if (bytesize >1){
		opcode.bytes[1] = ((char*)bytes)[1];
	}
	//opcode_map.get(opcode_ptr);
	opcode.size = instr_spec->opcode.size;
	if (instr_spec){
		opcode.has_modrm = instr_spec->opcode.has_modrm;
	}
	return opcode;
}

struct modrm parse_modrm(struct instruction instr, unsigned char *bytes){
	if (!instr.opcode.has_modrm){
		return (struct modrm){.byte = 0};
	}
	struct prefix *prefix = get_rex_prefix(instr);
	unsigned char R = 0, B = 0;
	if (prefix){
		R = prefix->rex.R << 3;
		B = prefix->rex.B << 3;
	}
	struct modrm modrm = {
		.byte = bytes[0],
		.mod=((bytes[0] & 192) >> 6),			// 192 == 11000000
		.reg_opcode=R | ((bytes[0] & 56) >> 3),	//  56 == 00111000
		.rm=B | bytes[0] & 7,					//   7 == 00000111
	};
	modrm.has_sib = modrm.mod != 3 && (modrm.rm & 7) == 4, // only for rsp
	modrm.has_displacement = modrm.mod != 3 && (modrm.mod > 0 || (modrm.rm & 7) == 5);
	//printf("modrm.has_displacement = %i\n",modrm.has_displacement);
	return modrm;
}
struct sib parse_sib(struct instruction instr, unsigned char * bytes){
	if (!instr.opcode.has_modrm){ // if no modrm no sib
		return (struct sib){};
	}
	struct sib sib =
	{
		.type = SIB_TYPE_NONE,
		.byte = 0,
		.base = 0,
		.scale = 1,
		.index = 0,
	};
	if (!instr.modrm.has_sib){
		return sib; // no sib
	}
	sib.byte = bytes[0];
	sib.has_displacement = (sib.byte & 7) == 5;

	// 16-bit addressing mode (either BITS 16 with no 67 prefix, or BITS 32 with a 67 prefix)
	// I understand that the x64 processor boots at 16bit mode, can I set 16bit mode at userspace elf file?
	unsigned char is_16bit_addr_mode = false; // TODO implement 16 detection but once the system is booted, BIOS or EFI will set it to 32bit mode then the bootloader will set it to 64bit mode so the default for userspace will be 64bit mode.
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
	}
	struct prefix *prefix = get_rex_prefix(instr);
	unsigned char W = 0, X = 0, B = 0;
	if (prefix){
		W = prefix->rex.W << 4; // W == 64 bit operand size
		//R = prefix->rex.R << 3; // R extension of the ModR/M reg field
		X = prefix->rex.X << 3; // X == Extension of SIB index filed
		B = prefix->rex.B << 3; // B == Extension of the ModR/M r/m field, SIB base field, or Opcode reg field
	}

	//TODO set index and base fields

	if(instr.modrm.rm == 4){
		sib.scale = pow(2, ((sib.byte >> 6) & 3));
		sib.index = W | X | ((sib.byte & 0x38) >> 3 );
		sib.base = W | B | ((sib.byte << 5) >> 5);
		//printf("sib.index=[%i];\nW==%x\n", sib.index, W);
		if (sib.byte & 5 == 5){
			if (((sib.byte >> 3) & 7) == 4){
				sib.type = SIB_TYPE_IMM32;
				memcpy(&instr.displacement.value.s4B, &bytes[1], 4);
				return sib;
			}
			sib.type = SIB_TYPE_REG_SCALE_DISPLACEMENT32;
			memcpy(&instr.displacement.value.s4B, &bytes[1], 4);
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

struct displacement parse_displacement(struct instruction_spec *instr_spec, struct instruction instr, int instr_offset){
	struct displacement d =
	{
		.type = DISPLACEMENT_TYPE_NONE
	};
	// if modrm or sib has displacement
	if (!(instr.modrm.has_displacement || (instr.sib.type != SIB_TYPE_NONE && instr.sib.has_displacement))){
		return d;
	}

	if (is_16bit_addr_mode(instr)){
		// In 16-bit addressing mode (either BITS 16 with no 67 prefix, or BITS 32 with a 67 prefix), the SIB byte is never used. The general rules for mod and r/m (there is an exception, given below) are:
	}
	//
	// The mod field gives the length of the displacement field: 0 means no displacement, 1 means one byte, and 2 means two bytes.
	// The r/m field encodes the combination of registers to be added to the displacement to give the accessed address: 0 means BX+SI, 1 means BX+DI, 2 means BP+SI, 3 means BP+DI, 4 means SI only, 5 means DI only, 6 means BP only, and 7 means BX only.
	switch (instr.modrm.mod){
		case 0:
			if ((instr.modrm.rm & 5) == 5) {
				instr.displacement.type = DISPLACEMENT_TYPE_IMM32;
				memcpy(&instr.displacement.value.s4B,&instr.bytes[1+instr.modrm.has_sib], 4);
			}
			break;
		case 1:
			instr.displacement.type = DISPLACEMENT_TYPE_IMM8;
			instr.displacement.value.s1B=instr.bytes[1+instr.modrm.has_sib];
			break;
		case 2:
			instr.displacement.type = DISPLACEMENT_TYPE_IMM32;
			memcpy(&instr.displacement.value.s4B,&instr.bytes[1+instr.modrm.has_sib], 4);
			break;
		case 3:
			instr.displacement.type = DISPLACEMENT_TYPE_NONE;
			break;
	}
	if (instr.sib.type != SIB_TYPE_NONE && instr.sib.has_displacement){
		instr.displacement.type = DISPLACEMENT_TYPE_IMM32;
		memcpy(&instr.displacement.value.s4B,&instr.bytes[instr_offset], 4);
	}
	return instr.displacement;
}

struct immediate parse_immediate(struct instruction_spec *instr_spec, struct instruction instr, unsigned char *bytes){
	struct immediate imm = {
		.type = IMM_NONE
	};
	if (instr_spec->immediate == IMM_NONE){
		return imm;
	}
	bool no_imm_operators = true;
	int i = 0;
	for (i=0; i<4; i++){
		switch (instr_spec->operands[i].type){
			case operand_imm_8_16_32_64:
			case operand_imm_8_16_32:
			case operand_imm8:
				no_imm_operators = false;
				break;
			default:
				continue;
		}
	}
	if (instr_spec->opcode.has_modrm && instr.modrm.mod==3 && no_imm_operators){
		return imm;
	}
	if (instr_spec->immediate == IMM8){
		imm.type = IMM8;
		imm.value.imm8 = bytes[0];
		return imm;
	}
	if (instr_spec->immediate == IMM32){
/*		struct prefix *prefix = get_rex_prefix(instr);
		if (prefix){
			imm.type = instr_spec->immediate + 1; // extend imm
		}*/
		imm.type = IMM32;
		memcpy(&imm.value.imm32,&bytes[0],4);
		return imm;
	}
	return imm;
}

void default_opcode_fn(struct opcode_fn_args *args)
{
	//printf("ds=%08x\n",regs.ds);
	unsigned char s_operands[2][50];
	instruction_info *rv = args->rv;
	unsigned char *s_asm_instruction = args->instr_spec->s_asm_instruction;
	int n_operands = 0;
	struct operand *operands = args->instr_spec->operands;
	if (operands){
		for (;;){
			struct operand *operand = &operands[n_operands];
			if(operand->type == operand_none)
				break;
			if(operand->type == operand_modrm_rm8)
				get_modrm_rm8(&instr, s_operands[n_operands]);
			if(operand->type == operand_modrm_rm)
				get_modrm_rm(&instr, s_operands[n_operands]);
			if(operand->type == operand_modrm_reg)
				get_modrm_regopcode(&instr, s_operands[n_operands]);
			if(operand->type == operand_imm8)
				sprintf(s_operands[n_operands], "%i", instr.immediate.value.imm8);
			if(operand->type == operand_imm_8_16_32_64){
				int pagesize = 1 << 12; // 4K
				if (instr.immediate.value.b_imm32[3] == 0xff){ // negative number, convert to two complement
					sprintf(s_operands[n_operands], "%i", (signed int)instr.immediate.value.imm32);
				} else if (instr.immediate.value.imm32 > pagesize){
					sprintf(s_operands[n_operands], "0x%x", instr.immediate.value.imm32);
				} else {
					sprintf(s_operands[n_operands], "%i", instr.immediate.value.imm32);
				}
			}
			n_operands++;
		}
	}
	char s_prefixes[50];
	s_prefixes[0] = 0;
	struct prefix *rep_prefix=get_rep_prefix(instr);
	if (rep_prefix){
		sprintf(s_prefixes, "%s%s%s",
			s_prefixes,
			get_color("prefix"),
			"rep ");
	}
	if (n_operands==0){
		sprintf(rv->asm_code,
			"%s%s%s%s",
			s_prefixes,
			get_color("opcode"),
			s_asm_instruction,
			get_color("")
		);
	}
	if (n_operands==1){
		sprintf(rv->asm_code,
			"%s%s %s%s%s",
			get_color("opcode"),
			s_asm_instruction,
			get_color("operand"),
			s_operands[0],
			get_color("")
		);
	}
	if (n_operands==2){
		sprintf(rv->asm_code,
			"%s%s %s%s, %s%s",
			get_color("opcode"),
			s_asm_instruction,
			get_color("operand"),
			s_operands[0],
			s_operands[1],
			get_color("")
		);
	}
}
void x0f05(struct opcode_fn_args *args)
{
	default_opcode_fn(args);
	instruction_info *rv = args->rv;
	detect_friendly_instruction(args->pid,rv->comment);
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
	const char **rt,**rta,**rtb;
	rt=detect_operand_a();
	struct prefix *prefix = get_rex_prefix(instr);
	if (prefix){
		rta = prefix->rex.byte & REX_B ? r64b : r64a;
		rtb = prefix->rex.byte & REX_X ? r64b : r64a;
		rt = rta;
	}
	instr.sib=parse_sib(instr, &bytes[instr_pos]);
	if (instr.modrm.mod == 0){
		if (instr.sib.type == SIB_TYPE_NONE){
			instr.immediate.value.imm8=bytes[++instr_pos];
			sprintf(asm_code,"%s %s%i%s, [%s]", operations[instr.modrm.reg_opcode], get_color("int"),
					instr.immediate.value.imm8, get_color(""),
					rt[instr.modrm.rm]);
			return;
		}
		if (instr.sib.type == SIB_TYPE_REG){
		}
		if (instr.sib.type == SIB_TYPE_IMM32){
		}
		if (instr.sib.type == SIB_TYPE_DISPLACEMENT32){
			if (instr.modrm.rm == 4){
				instr.immediate.value.imm8=bytes[++instr_pos];
				sprintf(asm_code,"%s %s%i%s, [%s+%s]",operations[instr.modrm.reg_opcode], get_color("int"),instr.immediate.value.imm8, get_color(""), rta[instr.sib.index], rtb[instr.sib.base]);
				return;
			}
			if (instr.modrm.rm == 5){
				instr.immediate.value.imm32=*(unsigned int*)&bytes[++instr_pos];
				sprintf(asm_code,"%s %s%i%s, [rel %s]", operations[instr.modrm.reg_opcode],
						get_color("int"),instr.immediate.value.imm32, get_color(""),
						rta[instr.sib.index]);
				return;
			}
		}
	}
	if (instr.modrm.mod == 2){
		if (instr.modrm.rm == 5){
			instr.immediate.value.imm32=*(unsigned int*)&bytes[++instr_pos];
			sprintf(asm_code,"%s %s%i%s, [rel %s]", operations[instr.modrm.reg_opcode],
					get_color("int"),instr.immediate.value.imm32, get_color(""),
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
					instr.immediate.value.imm8=bytes[++instr_pos];
					sprintf(colored_hexdump, "%s%s%02x%s", colored_hexdump,
							get_color("int"), instr.immediate.value.imm8, get_color(""));
					sprintf(asm_code, "%s, %s%i%s", asm_code, get_color("imm8"), instr.immediate.value.imm8, get_color(""));
				}
			}
		}
	}
}

void xeb(struct opcode_fn_args *args)
{
	instruction_info *rv = args->rv;
	sprintf(rv->asm_code, "%sjmp%s .%s%i%s", get_color("jmp"), get_color(""), get_color("int"), (signed char)instr.immediate.value.imm8, get_color(""));
	sprintf(rv->comment, "0x%llx", regs.rip + rv->instr_size + instr.immediate.value.imm8);
}
void x83(struct opcode_fn_args *args)
{
	instruction_info *rv = args->rv;
	// no rex:	(eax,ecx,edx,ebx,esp,ebp,esi,edi)
	// rex.W:	(rax,rcx,rdx,rbx,rsp,rbp,rsi,rdi)
	// rex.R
	// rex.X
	// rex.B:	(r8d-r15d)
	// rex.WB:	(r8-r15)
	rv->instr_size = multiple_one_byte_operation(rv, rv->instr_size, &instr, r32a, r32b,r64a,r64b);
}
void x89(struct opcode_fn_args *args)
{
	instruction_info *rv = args->rv;
	char s_operand_1[50];
	char s_operand_2[50];
	unsigned char * s_asm_instruction=args->instr_spec->s_asm_instruction;
	get_modrm_rm(&instr, (char*)&s_operand_1);
	get_modrm_regopcode(&instr, (char*)&s_operand_2);
	sprintf(rv->asm_code, "%s%s%s %s, %s", get_color(s_asm_instruction), s_asm_instruction, get_color(""), s_operand_1, s_operand_2);
}

void x50(struct opcode_fn_args *args)
{
	instruction_info *rv = args->rv;
	/*
		case 0x50:	// push %rax/r8
		case 0x51:	// push %rcx/r9
		case 0x52:	// push %rdx/r10
		case 0x53:	// push %rbx/r11
		case 0x54:	// push %rsp/r12
		case 0x55:	// push %rbp/r13
		case 0x56:	// push %rsi/r14
		case 0x57:	// push %rdi/r15
	*/
	const char **rt=r64a;
	struct prefix *rex_prefix=get_rex_prefix(instr);
	if (rex_prefix && rex_prefix->rex.B){
		rt=r64b;
	}
	const char *r=rt[instr.opcode.bytes[0]-0x50];
	sprintf(rv->asm_code, "push %s", r);
	sprintf(rv->comment, "0x%x", get_reg_value(r));
}
void x58(struct opcode_fn_args *args)
{
	instruction_info *rv = args->rv;
	/*
	case 0x58:	// pop %rax/r8
	case 0x59:	// pop %rcx/r9
	case 0x5a:	// pop %rdx/r10
	case 0x5b:	// pop %rbx/r11
	case 0x5c:	// pop %rsp/r12
	case 0x5d:	// pop %rbp/r13
	case 0x5e:	// pop %rsi/r14
	case 0x5f:	// pop %rdi/r15
	*/
	const char **rt=r64a;
	struct prefix *rex_prefix=get_rex_prefix(instr);
	if (rex_prefix && rex_prefix->rex.B){
		rt=r64b;
	}
	const char *r=rt[instr.opcode.bytes[0]-0x58];
	sprintf(rv->asm_code, "pop %s", r);
	sprintf(rv->comment, "0x%x", get_reg_value(r));
}

void xff(struct opcode_fn_args *args)
{
	//case 0xff:	// multiple operations
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
	instruction_info *rv = args->rv;
	multiple_operations(rv->colored_hexdump, rv->asm_code, &instr.bytes[rv->instr_size-1], op_t);
}

void x74(struct opcode_fn_args *args)
{
	instruction_info *rv = args->rv;
	//case 0x74:	// jz short
	signed char v = instr.immediate.value.imm8;
	int zero_flag = (regs.eflags & (1 << ZF));
	sprintf(rv->asm_code, "jz .%s%i%s", get_color("int"), v, get_color(""));
	sprintf(rv->comment, "0x%x:%s", regs.rip + rv->instr_size + v, zero_flag ? "zf(true)" : "zf(false)");
}
void x75(struct opcode_fn_args *args)
{
	//	case 0x75:	// jnz short
	signed char v = instr.immediate.value.imm8;
	int zero_flag = (regs.eflags & (1 << ZF));
	instruction_info *rv = args->rv;
	sprintf(rv->asm_code, "jnz .%s%i%s", get_color("int"), v, get_color(""));
	sprintf(rv->comment, "0x%x:%s", regs.rip + rv->instr_size + v, zero_flag ? "false" : "true");
}
void x7c(struct opcode_fn_args *args)
{
	//	case 0x75:	// jnz short
	signed char v = instr.immediate.value.imm8;
	int zero_flag = (regs.eflags & (1 << ZF));
	int sign_flag = (regs.eflags & (1 << SF));
	instruction_info *rv = args->rv;
	sprintf(rv->asm_code, "jl .%s%i%s", get_color("int"), v, get_color(""));
	sprintf(rv->comment, "0x%x:%s", regs.rip + rv->instr_size + v, zero_flag != sign_flag ? "false": "true" );
}

void x80(struct opcode_fn_args *args)
{
	instruction_info *rv = args->rv;
	//case 0x80:
	// 	no rex:	(al,cl,dl,bl,ah,ch,dh,bh)
	// 	rex:	(al,cl,dl,bl,spl,bpl,sil,dil)
	// 	rex.B:	(r8b-r15b)
	rv->instr_size = multiple_one_byte_operation(rv, rv->instr_size, &instr, r8lh, r8b, r8a, r8b);
}

void x84(struct opcode_fn_args *args)
{
	instruction_info *rv = args->rv;
	char a[256];
	char b[256];
	//case 0x84:
	char * s_opcode="test";
	// test al,al;
	get_modrm_r8(instr, (char*)&a, &instr.modrm.byte);
	get_modrm_m8(instr, (char*)&b);
	sprintf(rv->asm_code, "%s%s%s %s, %s", get_color(s_opcode), s_opcode, get_color(""), a, b);
}

void x0f80(struct opcode_fn_args *args)
{
	const char **near_opcodes = (const char *[]){ "jo", "jno", "jc", "jnc", "jz", "jnz", "jna", "ja", "js", "jns", "jpe", "jpo", "jl", "jnl", "jng", "jg"};
	unsigned char idx_opcode = instr.opcode.bytes[1] & 15;
	int zero_flag = (regs.eflags & (1 << ZF));
	sprintf(args->rv->asm_code,"%s%s near%s %i",
		get_color("opcode"),
		near_opcodes[idx_opcode],
		get_color("operand"),
		instr.immediate.value.imm32);
	sprintf(args->rv->comment, "0x%x: %s",
			regs.rip + args->rv->instr_size + instr.immediate.value.imm32,
			zero_flag ? "zf(true)": "zf(false)"
	);
}
void x31(struct opcode_fn_args *args)
{
	instruction_info *rv = args->rv;
	unsigned char *s_asm_instruction = args->instr_spec->s_asm_instruction;
	unsigned char s_operand_1[50];
	unsigned char s_operand_2[50];
	get_modrm_rm(&instr, (char*)&s_operand_1);
	get_modrm_regopcode(&instr, (char*)&s_operand_2);
	sprintf(rv->asm_code, "%s%s%s %s%s, %s", get_color(s_asm_instruction), s_asm_instruction, get_color(""), s_operand_1, get_color(""), s_operand_2);
}

void x0fb8(struct opcode_fn_args *args)
{
	instruction_info *rv = args->rv;
	unsigned char *s_asm_instruction = args->instr_spec->s_asm_instruction;
	unsigned char s_operand_1[50];
	unsigned char s_operand_2[50];
	get_modrm_rm(&instr, (char*)&s_operand_1);
	get_modrm_regopcode(&instr, (char*)&s_operand_2);
	sprintf(rv->asm_code, "%s%s%s %s%s, %s", get_color(s_asm_instruction), s_asm_instruction, get_color(""), s_operand_1, get_color(""), s_operand_2);
}

void x0fbd(struct opcode_fn_args *args)
{
	instruction_info *rv = args->rv;
	unsigned char *s_asm_instruction = args->instr_spec->s_asm_instruction;
	unsigned char s_operand_1[50];
	unsigned char s_operand_2[50];
	get_modrm_regopcode(&instr, (char*)&s_operand_1);
	get_modrm_rm(&instr, (char*)&s_operand_2);
	sprintf(rv->asm_code, "%s%s%s %s%s, %s", get_color(s_asm_instruction), s_asm_instruction, get_color(""), s_operand_1, get_color(""), s_operand_2);
}

void x0f(struct opcode_fn_args *args)
{
	printf("0x0f...%x\n", instr.modrm.byte);
	int zero_flag = (regs.eflags & (1 << ZF));
	instruction_info *rv = args->rv;
	pid_t pid = args->pid;
	//case 0x0f:
	// for ((i=0;i<256;i++)); do { xxd --ps -r | ndisasm -b 64 -; } <<<"0f$( printf %02x $((16#00 + i)))0102030405" | head -1; done
	/*
00000000  0F0001            sldt [rcx]
00000000  0F0101            sgdt [rcx]
00000000  0F0201            lar eax,[rcx]
00000000  0F0301            lsl eax,[rcx]
00000000  0F                db 0x0f
00000000  0F05              syscall
*/
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
	if ( instr.modrm.byte == 0x84 ){
		sprintf(rv->asm_code,"%s %s%i%s", "jz near",
			get_color("int"),instr.immediate.value.imm32, get_color(""));
		char buf[30];
		unsigned char *b4 = (char*)&instr.immediate.value.imm32;
		sprintf(rv->colored_hexdump, "%s%s%02x%02x%02x%02x%s", rv->colored_hexdump, get_color("int")
			, b4[0]
			, b4[1]
			, b4[2]
			, b4[3]
			, get_color(""));
		sprintf(rv->comment, "0x%x: %s", regs.rip + rv->instr_size + instr.immediate.value.imm32, zero_flag ? "true" : "false");
		return;
	}
// 00000000  0F8501020304      jnz near 0x4030207
/*

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
}

void append_hexdump(unsigned char * hd, unsigned char *bytes, int n)
{
	if (n == 0){
		strcpy(hd, bytes);
	} else if (n == 1){
		sprintf((char*)hd, "%02x", bytes[0]);
	} else if (n == 2){
		sprintf((char*)hd, "%02x%02x", bytes[0], bytes[1]);
	} else if (n == 4){
			//sprintx4(c, instr.sib.displacement);
		sprintf((char*)hd, "%02x%02x%02x%02x",
			bytes[0], bytes[1], bytes[2], bytes[3]);
	} else if (n == 8){
		sprintf((char*)hd, "%02x%02x%02x%02x%02x%02x%02x%02x",
			bytes[0], bytes[1], bytes[2], bytes[3],
			bytes[4], bytes[5], bytes[6], bytes[7]);
	}
}
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
		.instr_size = 0,
		.print_request_size = 0,
		.address = regs.rip,
	};
	get_instruction_bytes(pid, regs.rip, (unsigned char*)&rv.bytes[0]);
	memcpy(instr.bytes, rv.bytes, 16);
	unsigned char *bytes=rv.bytes;
	// clean up hexdump
	rv.hexdump[0] = 0;
	rv.colored_hexdump[0] = 0;
	append_hexdump(rv.hexdump, bytes, 8);
	struct parsed_info prefixes = parse_prefixes(instr, bytes);
	rv.instr_size += prefixes.parsed_bytes;
	append_hexdump(rv.colored_hexdump, prefixes.colored_hexdump,0);
	instr.prefixes = prefixes.ptr;
	instr.prefix_cnt = prefixes.ptr_cnt;
	// opcode can have multiple bytes
	struct instruction_spec *instr_spec = get_instr_spec(&bytes[rv.instr_size]);
	if (!instr_spec){
		return rv;
	}
	instr.opcode = parse_opcode(instr_spec, instr,&bytes[rv.instr_size]);
	int opcode_bytesize = get_opcode_bytesize(instr.opcode.size);
	sprintf(rv.asm_code, "");
	sprintf(rv.comment,"");
	rv.instr_size += opcode_bytesize;
	struct print_addr_request print_request[5];
	int print_request_size;
	struct prefix *rex_prefix=get_rex_prefix(instr);
	switch (instr.opcode.size){
		case opcode_size_5_bits:
		case opcode_size_8_bits:
			append_hexdump(rv.hexdump, instr.opcode.bytes,1);
			sprintf(rv.colored_hexdump,
					"%s%s%02x%s",
					rv.colored_hexdump,
					get_color("opcode"),
					instr.opcode.bytes[0],
					get_color(""));
			break;
		case opcode_size_16_bits:
		case opcode_size_13_bits:
		case opcode_size_12_bits:
			//append_hexdump(rv.colored_hexdump, instr.opcode.bytes, 2);
			sprintf(rv.colored_hexdump,
					"%s%s%02x%02x%s",
					rv.colored_hexdump,
					get_color("opcode"),
					instr.opcode.bytes[0],
					instr.opcode.bytes[1],
					get_color(""));
			break;
	}
	if (instr_spec && instr_spec->opcode.has_modrm){
		instr.modrm=parse_modrm(instr,&bytes[rv.instr_size]);
		rv.instr_size += 1;
		append_hexdump(rv.hexdump, &instr.modrm.byte, 1);
		sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("modrm"), instr.modrm.byte, get_color(""));
	}
	char a[256], b[256];
	instr.sib=parse_sib(instr, &bytes[rv.instr_size]);
	unsigned char c[9];
	if (instr.sib.byte != 0){
		/*printf("sib is: s=[%02x] i[%s] b[%s], displ=[%lx]\n",
			instr.sib.scale,
			r64[instr.sib.index],
			r64[instr.sib.base],
			instr.sib.displacement);
		*/
		append_hexdump(rv.hexdump, &instr.sib.byte, 1);
		sprintf(rv.colored_hexdump, "%s%s%02x%s",
				rv.colored_hexdump,
				get_color("sib"),
				instr.sib.byte,
				get_color(""));
		rv.instr_size += 1;
	}
	instr.displacement = parse_displacement(instr_spec, instr, rv.instr_size);
	//printf("detected displacement is %x\n", instr.displacement.type);
	switch (instr.displacement.type){
		case DISPLACEMENT_TYPE_NONE:
			break;
		case DISPLACEMENT_TYPE_IMM8:
			append_hexdump(rv.hexdump, (unsigned char *)&instr.displacement.value.s1B, 1);
			break;
		case DISPLACEMENT_TYPE_IMM32:
			sprintx4(c, instr.displacement.value.s4B);
			append_hexdump(rv.hexdump, (unsigned char *)&instr.displacement.value.s4B, 4);
			sprintf(rv.colored_hexdump, "%s%s%s%s",
					rv.colored_hexdump,
					get_color("displacement"),
					c,
					get_color(""));
			rv.instr_size += 4;
		case DISPLACEMENT_TYPE_IMM64:
	}
	instr.immediate = parse_immediate(instr_spec, instr, &rv.bytes[rv.instr_size]);
	switch (instr.immediate.type) {
		case IMM8:
		{
			rv.instr_size += 1;
			append_hexdump(rv.hexdump, &instr.immediate.value.imm8, 1);
			sprintf(rv.colored_hexdump, "%s%s%02x%s", rv.colored_hexdump, get_color("int"), instr.immediate.value.imm8, get_color(""));
			break;
		}
		case IMM32:
		{
			instr.immediate.value.imm32 = ptrace(PTRACE_PEEKTEXT, pid, regs.rip+rv.instr_size, 0);
			sprintx4(c, instr.immediate.value.imm32);
			append_hexdump(rv.hexdump, (unsigned char*)&instr.immediate.value.imm32, 4);
			sprintf(rv.colored_hexdump, "%s%s%s%s",
					rv.colored_hexdump, get_color("imm32"),
					c,
					get_color(""));
			rv.instr_size += 4;
		}
	}
	if (instr_spec){
		void (*call_opcode_ptr)(struct opcode_fn_args*) = default_opcode_fn;
		if (instr_spec->fn_ptr){
			call_opcode_ptr = instr_spec->fn_ptr;
		}
		struct opcode_fn_args opcode_args = {
			.pid = pid,
			.rv = &rv,
			.instr_spec = instr_spec,
		};
		call_opcode_ptr(&opcode_args);
		return rv;
	}
	printf("not found [0x%02x]\n", instr.opcode.bytes[0]);fflush(stdout);
	switch (instr.opcode.bytes[0]) {
		case 0x00:	// add to 8bit reg
		{
			const char **st=r64a;
			const char **tt=r8lh;
			if (!rex_prefix) {
				if (instr.modrm.mod < 3){
					st=r64a;
					tt=r8lh;
				}
			}
			if (rex_prefix) {
				unsigned char W,R,X,B;
				W = rex_prefix->rex.W;
				R = rex_prefix->rex.R;
				X = rex_prefix->rex.X;
				B = rex_prefix->rex.B;
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
		case 0x3c:	// cmp al, imm8
		{
			sprintf(rv.asm_code, "cmp %s%i%s, %s", get_color("int"), bytes[rv.instr_size], get_color(""), "al");
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
			get_modrm_regopcode(&instr, (char*)&a);
			get_modrm_rm(&instr, (char*)&b);
			instr.immediate.type = IMM8;
			instr.immediate.value.imm8=bytes[rv.instr_size++];
			sprintf(rv.asm_code, "%s %s*%s%i%s, %s", "imul", a, get_color("int"), instr.immediate.value.imm8, get_color(""), b);
			sprintf(rv.comment, "before: 0x%x", get_reg_value(b));
			break;
		}
		case 0x7f:	// jg short
		{
			signed char v = bytes[rv.instr_size++];
			sprintf(rv.asm_code, "jg .%s%i%s", get_color("int"), v, get_color(""));
			sprintf(rv.comment, "0x%x:%s", regs.rip + rv.instr_size + v,
					sign_flag == overflow_flag && zero_flag == 0 ? "true" : "false");
			break;
		}
		case 0x88:	// mov 8 bit regs
		{
			unsigned char b2=bytes[rv.instr_size-1];
			unsigned char b3=bytes[rv.instr_size];
			char * s_opcode="mov";
			instr.modrm = parse_modrm(instr, &bytes[rv.instr_size++]);
			if (rex_prefix && rex_prefix->rex.byte==0x40){
				if (instr.modrm.mod == 3){
					const char *a=r8a[instr.modrm.reg_opcode];
					const char *b=r8a[instr.modrm.rm];
					sprintf(rv.asm_code, "%s%s%s %s, %s", get_color(s_opcode), s_opcode, get_color(""), a, b);
				}
			}
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
			multiple_operations(rv.colored_hexdump, rv.asm_code, &bytes[rv.instr_size-1], asm_ops);
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
	unsigned char bytes[100];
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
	struct prefix *rex_prefix=get_rex_prefix(instr);
	if (rex_prefix){
		sprintf(w, "%sW%s%s",
			rex_prefix->rex.W ? get_color("REX.W") : get_color("gray"),
			rex_prefix->rex.W ? "¹" : "°", get_color(""));
		sprintf(r, "%sR%s%s",
			rex_prefix->rex.R ? get_color("REX.R") : get_color("gray"),
			rex_prefix->rex.R ? "¹" : "°", get_color(""));
		sprintf(x, "%sX%s%s",
			rex_prefix->rex.X ? get_color("REX.X") : get_color("gray"),
			rex_prefix->rex.X ? "¹" : "°", get_color(""));
		sprintf(b, "%sB%s%s",
			rex_prefix->rex.B ? get_color("REX.B") : get_color("gray"),
		rex_prefix->rex.B ? "¹" : "°", get_color(""));
		printf("REX: %02x: %s%s%s%s\n", rex_prefix->rex.byte,w,r,x,b);
	}
	unsigned char W = (rex_prefix && rex_prefix->rex.W) << 4;
	unsigned char R = (rex_prefix && rex_prefix->rex.R);
	unsigned char B = (rex_prefix && rex_prefix->rex.B);
	printf("ModR/M: %02x\n", instr.modrm.byte);
	printf("\tmod=%i;\n", instr.modrm.mod);
	printf("\treg_opcode=%i: %s%i(%s)\n",
			instr.modrm.reg_opcode,
			R ? "REX.R + ": "",
			R ? (instr.modrm.reg_opcode & 7) : 0,
			r64[W | instr.modrm.reg_opcode]);
	printf("\trm=%i: %s%i(%s)\n",
			instr.modrm.rm,
			B ? "REX.B + ": "",
			B ? (instr.modrm.rm & 7) : 0,
			r64[W | instr.modrm.rm]);
	if (instr.sib.type != SIB_TYPE_NONE){
		printf("sib: %02x\n", instr.sib.byte);
		printf("\ttype: %x\n", instr.sib.type);
		printf("\tscale: %x\n", instr.sib.scale);
		printf("\tbase: %x\n", instr.sib.base);
		printf("\tindex: %s\n", r64[instr.sib.index]);
	}
	if (instr.displacement.type != DISPLACEMENT_TYPE_NONE){
		printf("displacement: 0x%lx\n",
			instr.displacement.value
		);
	}
	if (instr.immediate.type != IMM_NONE){
		printf("immediate: 0x%lx\n",
			instr.immediate.value.imm32
		);
	}
}

/*
* arch_interact_user receives a user input and answer it
*/
void arch_interact_user(pid_t pid, struct user_regs_struct * regs, char * user_input) {
	unsigned char hexstr[100];
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
		v = ptrace(PTRACE_PEEKTEXT, pid, (void*)vaddr+8, 0);
		sprintx(&hexstr[16], v);
		ndisasm(hexstr);
	}
}

void get_current_address(char *s_curr_addr, struct user_regs_struct *regs){
	sprintf(s_curr_addr, "%llx", regs->rip);
}

#define instr_spec_list_count 31
struct instruction_spec instr_spec_list[instr_spec_list_count] = {
	{
		.s_asm_instruction = "add",
		.s_asm_fmt = "add %s, %s", // 0x01:	// add
		.description = "Add r64 to r/m64.",
		.opcode = {
			.bytes = {0x01},
			.size = opcode_size_8_bits,
			.has_modrm = MANDATORY,
		},
		.has_sib = OPTIONAL,
		.fn_ptr = NULL,
		.operands = {
			{
			.mode = RW,
			.type = operand_modrm_rm,
			},
			{
			.mode = R,
			.type = operand_modrm_reg,
			},
			{.type = operand_none},
		},
	},
	{
		.s_asm_instruction = "syscall",
		.opcode = {
			.bytes = { 0x0f, 0x05 },
			.size = opcode_size_16_bits,
			.has_modrm = NO,
		},
		.fn_ptr = x0f05,
	},
	{
		.opcode = {
			.bytes = { 0x0f, 0x80 },
			.size = opcode_size_12_bits,
			.has_modrm = NO,
		},
		.immediate = IMM32,
		.fn_ptr = x0f80,
	},
	{
		.s_asm_instruction = "movzx",
		.opcode = {
			.bytes = { 0x0f, 0xb6 }, // b8-bf
			.size = opcode_size_16_bits,
			.has_modrm = MANDATORY,
		},
		.operands = {
			{.type=operand_modrm_reg, .mode=W},
			{.type=operand_modrm_rm8, .mode=R},
			{.type = operand_none},
		},
		.fn_ptr = NULL,
	},
	{
		.s_asm_instruction = "mov",
		.opcode = {
			.bytes = { 0x0f, 0xb8 }, // b8-bf
			.size = opcode_size_13_bits,
			.has_modrm = MANDATORY,
		},
		.fn_ptr = x0fb8,
	},
	{
		.s_asm_instruction = "bsr",
		.opcode = {
			.bytes = { 0x0f, 0xbd }, // b8-bf
			.size = opcode_size_16_bits,
			.has_modrm = MANDATORY,
		},
		.operands = {
			{.type = operand_modrm_reg, .mode=W},
			{.type = operand_modrm_rm, .mode=R},
			{.type = operand_none},
		},
		.fn_ptr = x0fbd,
	},
	{
		.s_asm_instruction = "movsx",
		.opcode = {
			.bytes = {0x0f,0xbe},
			.size = opcode_size_16_bits,
			.has_modrm = MANDATORY,
		},
		.has_sib = OPTIONAL,
		.operands = {
			{.type = operand_modrm_reg, .mode=W},
			{.type = operand_modrm_rm, .mode=R},
			{.type = operand_none},
		},
		.fn_ptr = NULL,
	},
	{
		.s_asm_instruction = "sub",
		.s_asm_fmt = "sub %s, %s", // 0x01:	// add
		.opcode = {
			.bytes = { 0x29 },
			.size = opcode_size_8_bits,
			.has_modrm = MANDATORY,
		},
		.operands = {
			{.type = operand_modrm_rm, .mode=RW},
			{.type = operand_modrm_reg, .mode=R},
			{.type = operand_none},
		},
		.has_sib = OPTIONAL,
		.fn_ptr = NULL,
	},
	{
		.s_asm_instruction = "xor",
		.s_asm_fmt = "xor %s, %s", // 0x01:	// add
		.opcode = {
			.bytes = { 0x31 },
			.size = opcode_size_8_bits,
			.has_modrm = MANDATORY,
		},
		.has_sib = OPTIONAL,
		.fn_ptr = x31,
		.operands = {
			{
			.mode = RW,
			.type = operand_modrm_rm,
			},
			{
			.mode = R,
			.type = operand_modrm_reg,
			},
			{.type = operand_none},
		},
	},
	{
		.s_asm_instruction = "cmp",
		.opcode = {
			.size = opcode_size_8_bits,
			.bytes = { 0x39 },
			.has_modrm = MANDATORY,
		},
		.operands = {
			{.type = operand_modrm_rm, .mode = R},
			{.type = operand_modrm_reg, .mode = R},
			{.type = operand_none},
		},
	},
	{
		.s_asm_opcode = "push",
		.s_asm_fmt = "push %s",
		.opcode = {
			.bytes = {10 << 3}, // 0x50-0x57
			.size = opcode_size_5_bits,
			.has_modrm = NO,
		},
		.has_sib = NO,
		.immediate = IMM_NONE,
		.fn_ptr = x50,
	},
	{
		.s_asm_opcode = "pop",
		.s_asm_fmt = "pop %s",
		.opcode = {
			.bytes = { 11 << 3 }, // 0x58-0x5f; 01011000-01011111
			.size = opcode_size_5_bits,
			.has_modrm = NO,
		},
		.has_sib = NO,
		.immediate = IMM_NONE,
		.fn_ptr = x58,
	},
	{
		.s_asm_instruction = "push",
		.opcode = {
			.bytes = { 0x68 },
			.size = opcode_size_8_bits,
			.has_modrm = NO,
		},
		.operands = {{.type = operand_imm_8_16_32_64}},
		.has_sib = NO,
		.immediate = IMM32,
		.fn_ptr = NULL,
	},
	{
		.s_asm_instruction = "push",
		.opcode = {
			.bytes = { 0x6a },
			.size = opcode_size_8_bits,
			.has_modrm = NO,
		},
		.operands = {{.type = operand_imm8}},
		.immediate = IMM8,
		.fn_ptr = NULL,
	},
	{
		.s_asm_instruction = "imul",
		.opcode = {
			.bytes = { 0x6b },
			.size = opcode_size_8_bits,
			.has_modrm = MANDATORY,
		},
		.operands = {
			{
			.mode = RW,
			.type = operand_modrm_rm,
			},
			{
			.mode = R,
			.type = operand_imm8,
			},
			{.type = operand_none},
		},
		.has_sib = OPTIONAL,
		.immediate = IMM8,
		.fn_ptr = NULL,
	},
	{
		.s_asm_opcode = "jz",
		.s_asm_fmt = "jz .%i",
		.opcode = {
			.bytes = {0x74},
			.size = opcode_size_8_bits,
			.has_modrm = NO,
		},
		.has_sib = NO,
		.immediate = IMM8,
		.fn_ptr = x74,
	},
	{
		.s_asm_opcode = "jnz",
		.s_asm_fmt = "jnz .%i",
		.opcode = {
			.bytes = {0x75},
			.size =	opcode_size_8_bits,
			.has_modrm = NO,
		},
		.has_sib = NO,
		.immediate = IMM8,
		.fn_ptr = x75,
	},
	{
		.s_asm_opcode = "jl",
		.s_asm_fmt = "jl .%i",
		.opcode = {
			.bytes = {0x7c},
			.size = opcode_size_8_bits,
			.has_modrm = NO,
		},
		.has_sib = NO,
		.immediate = IMM8,
		.fn_ptr = x7c,
	},
	{
		.s_asm_opcode = "", // multiple operations
		.s_asm_fmt = "",
		.opcode = {
			.bytes = { 0x80 },
			.size = opcode_size_8_bits,
			.has_modrm = MANDATORY,
		},
		.has_sib = OPTIONAL,
		.immediate = IMM8,
		.fn_ptr = x80,
	},
	{
		.s_asm_opcode="mov",
		.opcode = {
			.bytes = { 0x83 }, // multiple_operations defined by function
			.size = opcode_size_8_bits,
			.has_modrm = MANDATORY,
		},
		.has_sib = NO,
		.fn_ptr = x83,
		.immediate = IMM8,
		.s_asm_fmt = "%s %s, %s",
		.operands = {
			{.type = operand_modrm_rm, .mode = RW},
			{.type = operand_imm8, .mode = R},
			{.type = operand_none}
		},
	},
	{
		.s_asm_opcode="test",
		.opcode = {
			.bytes = { 0x84 }, // multiple_operations defined by function
			.size = opcode_size_8_bits,
			.has_modrm = MANDATORY,
		},
		.has_sib = NO,
		.fn_ptr = x84,
		.immediate = IMM8,
		.s_asm_fmt = "%s %s, %s",
	},
	{
		.intel_manual_opcode = "REX.W + 89 /r",
		.s_asm_instruction="mov",
		.s_asm_fmt = "mov %s, %s",
		.opcode = {
			.bytes = { 0x89 },
			.size = opcode_size_8_bits,
			.has_modrm = MANDATORY,
		},
		.has_sib = OPTIONAL,
		.fn_ptr = x89,
		.operands = {
			{
				.type = operand_modrm_rm,
				.mode = W,
			},
			{
				.type = operand_modrm_reg,
				.mode = R,
			},
			{ .type = operand_none },
		},
	},
	{
		.intel_manual_opcode = "REX.W + 8B /r",
		.s_asm_instruction = "mov",
		.description = "Move r/m64 to r64.",
		.s_asm_fmt = "mov %s, [%s]",
		.opcode = {
			.bytes = {0x8b},
			.size = opcode_size_8_bits,
			.has_modrm = MANDATORY,
		},
		.has_sib = OPTIONAL,
		.fn_ptr = NULL,
		.operands = {
			{.type = operand_modrm_reg, .mode = W},
			{.type = operand_modrm_rm, .mode = R},
			{.type = operand_none},
		},
	},
	{
		.s_asm_instruction = "lea",
		.opcode = {
			.bytes = { 0x8d },
			.size = opcode_size_8_bits,
			.has_modrm = MANDATORY,
		},
		.has_sib = OPTIONAL,
		.operands = {
			{.type = operand_modrm_reg, .mode = W},
			{.type = operand_modrm_rm, .mode = R},
			{.type = operand_none}
		},
	},
	{
		.s_asm_instruction = "movsb",
		.opcode = {
			.bytes = { 0xa4 },
			.size = opcode_size_8_bits,
			.has_modrm = NO,
		},
		.has_sib = NO,
		.operands = { {.type = operand_none } },
		.fn_ptr = NULL,
	},
	{
		.s_asm_instruction = "ret",
		.opcode = {
			.bytes = { 0xc3 },
			.size = opcode_size_8_bits,
			.has_modrm = NO,
		},
	},
	{
		.intel_manual_opcode="C7 /0 id",
		.s_asm_opcode="C7 /0 id",
		.s_asm_fmt = "mov %08x, %s", // mov v4, reg
		.s_asm_instruction = "mov",
		.opcode = {
			.bytes = { 0xc7 },
			.size = opcode_size_8_bits,
			.has_modrm = MANDATORY,
		},
		.has_sib = OPTIONAL,
		.immediate = IMM32,
		.force_modrm_regopcode = true,
		.modrm_regopcode = 0, // /0
		.fn_ptr = NULL, //xc7,
		.operands = {
			{
				.mode = W,
				.type = operand_modrm_rm,
			},
			{
				.mode = R,
				.type = operand_imm_8_16_32_64,
			},
			{.type = operand_none},
		},
	},
	{
		.s_asm_instruction="call",
		.s_asm_fmt = "call .%i",
		.opcode = {
			.bytes = {0xe8},
			.size = opcode_size_8_bits,
			.has_modrm = NO,
		},
		.operands = { {.type = operand_imm_8_16_32_64, .mode = R} },
		.has_sib = NO,
		.immediate = IMM32,
		.fn_ptr = NULL,
	},
	{
		.s_asm_instruction="jmp",
		.opcode = {
			.bytes = {0xe9},
			.size = opcode_size_8_bits,
			.has_modrm = NO,
		},
		.operands = { {.type = operand_imm_8_16_32_64, .mode = R} },
		.has_sib = NO,
		.immediate = IMM32,
		.fn_ptr = NULL,
	},
	{
		.s_asm_opcode="jmp",
		.s_asm_fmt = "jmp .%i",
		.opcode = {
			.bytes = {0xeb},
			.size = opcode_size_8_bits,
			.has_modrm = NO,
		},
		.has_sib = NO,
		.immediate = IMM8,
		.fn_ptr = xeb,
	},
	{
		.s_asm_opcode = "", // multiple operations
		.s_asm_fmt = "",
		.opcode = {
			.bytes = {0xff},
			.size = opcode_size_8_bits,
			.has_modrm = MANDATORY,
		},
		.has_sib = OPTIONAL,
		.immediate = IMM_NONE,
		.fn_ptr = xff,
	},
};

void init_arch(){
	init_colormap();
	map_opcode = map_new();
	int i;
	struct instruction_spec *spec;
	int key_size = 1;
	for (i=0; i<instr_spec_list_count; i++){
		spec = &instr_spec_list[i];
		key_size = get_opcode_bytesize(spec->opcode.size);
		unsigned char *keys = spec->opcode.bytes;
		map_put(&map_opcode, keys, key_size, spec);
	}
}

#endif
