#!/bin/bash
if ! declare -F rex >/dev/null; then
# THE REX PREFFIX:
#  in 64bit mode the x86 arch specifies register sizes using prefix bytes.
#  For example, the same "0xb8" instruction that loads a 32-bit constant into eax can be used with a "0x66" prefix to load a 16-bit constant, or a "0x48" REX prefix to load a 64-bit constant.
#  REX prefix is optional, without it the code will use 32bit registers.
#  REX prefix determines the addressing size and extensions.
#
#  REX Bits:
# |7|6|5|4|3|2|1|0|
# |0|1|0|0|W|R|X|B|
#  W bit = Operand size 1==64-bits, 0 == legacy, Operand size determined by CS.D (Code Segment)
#  R bit = Extends the ModR/M reg field to 4 bits. 0 selects rax-rsi, 1 selects r8-r15
#  X bit = extends SIB 'index' field, same as R but for the SIB byte (memory operand)
#  B bit = extends the ModR/M r/m or 'base' field or the SIB field
#
. $(dirname $(realpath $BASH_SOURCE))/multi_syntax.sh
rex(){
	local r_m=$1;
	local reg=$2;
	if ! use_intel_syntax; then
		# AT&T syntax;
		reg=$2;
		r_m=$1;
	fi;
	if ! {
		is_addr_ptr "$reg" || 
		is_64bit_register "$r_m" ||
		is_64bit_register "$reg" ||
		is_8bit_extended_register "$r_m";
	}; then
		return;
	fi;
	local W=1;
	local R=0;	# 1 if source is a register from r8 to r15
	local X=0;
	local B=0;	# 1 if target(base) is a register from r8 to r15
	if is_64bit_extended_register "$reg"; then
		R=1;
	fi;
	if is_64bit_extended_register "$r_m"; then
		B=1;
	fi;
	if is_8bit_extended_register "$r_m"; then
		R=1;
	fi;
	if is_8bit_extended_register "$reg" || { is_64bit_extended_register "$reg" && is_8bit_sint "$r_m"; }; then
		B=1;
	fi;
	if is_8bit_extended_register "$r_m" && is_8bit_register "$reg" && ! is_8bit_extended_register "$reg"; then
		W=0;
		R=0;
		B=0;
	fi;
	printf "%02x" $(( (2#0100 << 4) + (W<<3) + (R<<2) + (X<<1) + B ));
}
fi;
