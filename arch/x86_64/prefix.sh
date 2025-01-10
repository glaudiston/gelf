#!/bin/bash
if ! declare -F multiple_one_byte_operation >/dev/null; then
. arch/x86_64/registers.sh
. arch/x86_64/rex.sh
# prefix should detect and print all instruction prefixes like:
# rex: Prefix (0x40 - 0x4F):
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
#	It replaces the REX prefix in AVX-512 instructions.
# VEX (0xC4, 0xC5):
#	These prefixes are used for AVX (Advanced Vector Extensions) instructions.
# XOP (0x8F):
#	This prefix is used for XOP (eXtended Operations) instructions,
#	which are a set of additional SIMD instructions introduced by AMD.
prefix(){
	local src="$1";
	local tgt="$2";
	if is_64bit_uint "$tgt" || is_addr_ptr "$tgt" || is_64bit_register "$src" || is_64bit_register "$tgt" || is_8bit_extended_register "$src"; then
		rex "$src" "$tgt";
	fi;
	if is_16bit_register "$src" || is_16bit_register "$tgt"; then
		local osize="66";
		echo -n ${osize};
	fi;
}
fi;
