#!/bin/bash
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
. "$(dirname $(realpath $BASH_SOURCE))/../../pragma_once/bash/import_bash.sh";
import_bash <<-EOF
	../../number.sh
	../../utils.sh
	./registers.sh
	./multi_syntax.sh
EOF

# rex receives the r/m (first register or memory address) and reg (second register parameter)
# and defines the prefix of the bytecode
#
# The REX output is 8 bits, the constant 0100 followed to 4 variables (1 bit each):
# REX byte: 0100|W|R|X|B
# Where
# W: Promotes operation to 64-bit width (1) or keeps 32-bit (0)
# R: Extends the ModR/M reg field to access registers r8–r15
# X: Extends the SIB index field to access r8–r15
# B: Extends the ModR/M r/m field to access r8–r15
#
rex() {
	local r_m="$1"  # ModR/M r/m field
	local reg="$2"  # ModR/M reg field
	
	local W=0 R=0 X=0 B=0

	# Only set if 64-bit operand is explicitly required
	if is_64bit_register "$r_m" || is_64bit_register "$reg" || is_64bit_extended_register_ptr "$r_m" || is_64bit_extended_register_ptr "$reg"; then
		W=1
	fi

	if is_extended_register "$reg" || { is_extended_register "$r_m" && is_register_ptr "$reg"; }; then
		R=1
	fi

	# Extends SIB index - requires parsing memory string
	if is_ptr "$r_m" && is_extended_index "$r_m"; then
		X=1
	fi

	# Extends 'r/m' field
	if {
		{ is_extended_register "$r_m" || is_extended_register_ptr "$r_m"; } ||
		{ is_extended_register_ptr "$reg" && ! is_register_ptr "$r_m"; }
	} && ! { is_extended_register "$r_m" && is_register_ptr "$reg" && ! is_extended_register_ptr "$reg"; };
	then
		B=1
	fi
	
	if [[ "$(( W + R + X + B ))" != 0 ]]; then
		printf "%02x" $(( 2#0100<<4 | W<<3 | R<<2 | X<<1 | B ))
	fi
}
