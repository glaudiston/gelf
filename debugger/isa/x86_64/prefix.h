#include "./types.h"
#define REX_B 1
#define REX_X 2
#define REX_R 4
#define REX_W 8

/*
 *  check_prefix should detect and print all instruction prefixes
 */
e_prefix_type prefix_type_of(unsigned char b){
	if (((b << 1 ) >> 5) == 4){
		// The REX prefix is used in 64-bit mode
		// to extend the instruction set to 
		// handle 64-bit operands and additional registers.
		return REX;
	}
	if (b == 0x66){
		// osize: The Operand Size Override Prefix (0x66):
		//	Override the default operand size of an instruction.
		//	When this prefix is present, the instruction operates on 16-bit operands
		//	instead of the default operand size (e.g., 32-bit or 64-bit).
		//	Programmers often think that since Real Mode defaults to 16 bits, that the 32 bit registers are not accessible. This is not true.
		//	All of the 32-bit registers (EAX, ...) are still usable, by simply adding the "Operand Size Override Prefix" (0x66) to the beginning of any instruction. Your assembler is likely to do this for you, if you simply try to use a 32-bit register.
		return osize;
	}
	if (b == 0x67){
		// asize: Address Size Override Prefix (0x67):
		// Override the default address size of an instruction. It can switch between 16-bit and 32/64-bit address sizes.
		return asize;
	}
	if (b == 0xf0) {
		// Lock Prefix (0xF0):
		// 	The lock prefix is used to ensure atomicity of certain memory operations,
		// 	such as atomic read-modify-write instructions like xchg.
		return LOCK;
	}
	if (b == 0xf2 || b == 0xf3){
		// REP/REPE/REPNE Prefixes (0xF2, 0xF3):
		// These prefixes are used with certain string instructions (movs, cmps, scas, lods, stos)
		// to repeat the operation while certain conditions are met (e.g., ECX register is not zero, or the ZF flag is set).
		return REP;
	}
	if (b == 0x2e || b == 0x3e){
		// Branch Hints Prefixes (0x2E, 0x3E):
		// 	These prefixes are used as branch hints for the processor's branch prediction mechanism.
		// 	They hint whether a branch is likely or unlikely to be taken.
		return BRANCH_HINT;
	}
	if (b == 0x26 || b == 0x2e || b == 0x36 || b == 0x3e || b == 0x64 || b == 0x65 ){
		// Segment override (0x26, 0x2E, 0x36, 0x3E, 0x64, 0x65):
		// 	These prefixes override the default segment register used for memory addressing.
		return SEGMENT_OVERRIDE;
	}
	if (b == 0x62){
		// # EVEX (0x62):
		// #	This is an AVX-512 prefix used for instructions operating on 512-bit registers.
		// #	It replaces the REX prefix in AVX-512 intructions.
		return EVEX;
	}
	if (b == 0xc4 || b == 0xc5){
		// VEX (0xC4, 0xC5):
		// These prefixes are used for AVX (Advanced Vector Extensions) instructions.
		return VEX;
	}
	if (b == 0x8f){
		// # XOP (0x8F):
		// #	This prefix is used for XOP (eXtended Operations) instructions,
		// #	which are a set of additional SIMD instructions introduced by AMD.
		return XOP;
	}
	/*
# ssize?:
	*/
	return PREFIX_NONE;
}

struct prefix parse_prefix(char prefix_byte){
	struct prefix prefix;
	prefix.type = prefix_type_of(prefix_byte);
	switch (prefix.type) {
		case REP:
			break;
		case REX:
			prefix.rex.byte=prefix_byte;
			prefix.rex.W = (prefix_byte & (1 << 3)) == (1 << 3);
			prefix.rex.R = (prefix_byte & (1 << 2)) == (1 << 2);
			prefix.rex.X = (prefix_byte & (1 << 1)) == (1 << 1);
			prefix.rex.B = (prefix_byte & (1 << 0)) == (1 << 0);
			char rex_binary_tips[100]="";
			break;
		default:
			prefix.type = PREFIX_NONE;
	}
	return prefix;
}
