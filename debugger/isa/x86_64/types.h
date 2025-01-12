#ifndef _X86_64_TYPES_
#define _X86_64_TYPES_
#include "./../../debugger.h"
enum {
	NO,
	MANDATORY,
	OPTIONAL,
} required_type;
typedef unsigned char bool;
typedef enum e_prefix_type {
	PREFIX_NONE,
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
} e_prefix_type;
/*
#  REX Bits:
#  |7|6|5|4|3|2|1|0|
#  |0|1|0|0|W|R|X|B|
*/
struct rex {
	unsigned char byte;
	bool W;	// W bit = Operand size 1==64-bits, 0 == legacy, Operand size determined by CS.D (Code Segment)
	bool R;	// R bit = Extends the ModR/M reg field to 4 bits. 0 selects rax-rsi, 1 selects r8-r15
	bool X;	// X bit = extends SIB 'index' field, same as R but for the SIB byte (memory operand)
	bool B;	// B bit = extends the ModR/M r/m or 'base' field or the SIB field
};
struct prefix {
	e_prefix_type type;
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
	unsigned char reg_opcode;	// Register or Opcode
	unsigned char rm;	// RM; when set to RSP or RBP it requires SIB
	bool has_sib;
	bool has_displacement;
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
	bool has_displacement;
};
enum e_opcode_size {
	opcode_size_5_bits,
	opcode_size_8_bits,
	opcode_size_12_bits,
	opcode_size_13_bits,
	opcode_size_16_bits,
};
struct opcode {
	unsigned char bytes[2];
	enum e_opcode_size size;
	bool has_modrm;
};
enum e_immediate_type {
	IMM_NONE,
	IMM8,
	IMM16,
	IMM32,
	IMM64
};
typedef unsigned char bool;
enum e_operand_mode {
	R,
	W,
	RW,
};
struct opcode_fn_args {
	pid_t pid;
	instruction_info *rv;
	struct instruction_spec *instr_spec;
};

enum e_operand_type {
	operand_none,
	operand_modrm_reg,
	operand_modrm_rm,
	operand_modrm_rm8,
	operand_al_ax_eax_rax,
	operand_vex_vvvv,
	operand_evex_vvvv,
	operand_opcode_rd,
	operand_imm_8_16_32_64,
	operand_imm_8_16_32,
	operand_imm8,
};
struct operand {
	enum e_operand_mode mode;
	enum e_operand_type type;
	void (*get)(void *instr, char *bytes);
};
struct instruction_spec{
	unsigned char intel_manual_opcode[50]; // string to search at intel manual for details
	unsigned char description[255];
	unsigned char s_asm_opcode[20];
	unsigned char s_asm_fmt[20];	// asm printf fmt
	unsigned char s_asm_instruction[20];
	struct opcode opcode;
	bool has_sib;
	bool force_modrm_regopcode;
	unsigned char modrm_regopcode;	// force opcode to this value
	enum e_immediate_type immediate;
	unsigned char displacement_size; // size in bytes of displacement address;
	unsigned char imm_size;	// size in bytes of immediate value
	void (*fn_ptr)(struct opcode_fn_args *);
	struct operand operands[4];
};

enum e_displacement_type{
	DISPLACEMENT_TYPE_NONE,
	DISPLACEMENT_TYPE_IMM8,
	DISPLACEMENT_TYPE_IMM32,
	DISPLACEMENT_TYPE_IMM64
};

union u_displacement_value{
	signed char s1B;
	signed long s2B;
	signed long int s4B;
	signed long long int s8B;
};

struct displacement{
	enum e_displacement_type type;
	union u_displacement_value value;
};

union u_immediate{
	unsigned char imm8;	// immediate 8bit value;
	unsigned short imm16;	// immediate 16bit value;
	unsigned int imm32;	// immediate 32bit value;
	unsigned char b_imm32[4];
	unsigned char b_imm64[8];
	unsigned long imm64;	// immediate 64bit value;
};

struct immediate {
	enum e_immediate_type type;
	union u_immediate value;
};

struct instruction {
	int parsed;
	int rv;
	struct prefix **prefixes;
	int prefix_cnt;
	struct opcode opcode; // operator
	struct modrm modrm;	// ModR/M
	struct displacement displacement;
	struct immediate immediate;
	struct sib sib;
	int operand_size;
	unsigned char bytes[32];
};
#endif
