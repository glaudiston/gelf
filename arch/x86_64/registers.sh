#!/bin/bash
if ! declare -F is_register >/dev/null; then
# The x86-64 architecture has a total of 16 general-purpose registers,
# which are named from R0 to r15. The first 8 registers,
# R0 to R7, can be accessed using their traditional names (AX, BX, CX, DX, BP, SI, DI, and SP),
# which have been used since the early days of x86 processors.
#  The prefix E stands for 32bit and R for 64bit. So EAX is 32bit while RAX is 64bit;
# However, the additional registers introduced in the x86-64 architecture
# (r8 to r15) have new names that reflect their expanded capabilities
# and wider use in modern software development.
# These new names are intended to make it easier for programmers
# to distinguish between the older and newer registers and to avoid naming conflicts.
#
# 16 general purpose registers
# Conventions:
#  rax: Accumulator: Used In Arithmetic operations
#  rcx: Counter: Used in loops and shift/rotate instructions
#  rdx: Data: Used in arithmetic operations and I/O operations; target address
#  rbx: Base: Used as a pointer to data
#  rsp: Stack Pointer: Points to top of stack
#  rbp: Stack Base Pointer: Points to base of stack
#  rsi: Points to source in stream operations
#  rdi: Points to destination in streams operations
#  r8-r15: general purpose
# 6 segment registers: points to memory segment addresses (but uses paging instead segmentation)
# 1 flag register: used to support arithmetic functions and debugging.
#  EFLAG(32)
#  RFLAG(64)
#
#Processor Flags
flags=( ID VIP VIF AC VM RF NT IOPL OF DF IF TF SF ZF AF PF CF );
#The x86 processors have a large set of flags that represent the state of the processor, and the conditional jump instructions can key off of them in combination.
#
#ZF - zero flags
#    Set if result is zero; cleared otherwise
#SF - sign flag
#    Set equal to high-order bit of result (0 if positive 1 if negative)
#OF - overflow flag
#    Set if result is too large a positive number or too small a negative number (excluding sign bit) to fit in destination operand; cleared otherwise
#    The Overflow Flag (OF) has only a meaning for signed numbers. It will be set:
# 		if the result of 2 positive numbers results in a negative number
# 		or if the sum of 2 negative numbers result in a positive number.
# 		Below is an example of the sum of 2 positive numbers (bit sign is 0). It results in a negative number (bit sign is 1). In this case, the overflow flag will be set.
#               ┌─────────────┬─────────────┬─────────────┬─────────────┬─────────────┬─────────────┬─────────────┬─────────────┐
#               │ 31 30 29 28 │ 27 26 25 24 │ 23 22 21 20 │ 19 18 17 16 │ 15 14 13 12 │ 11 10 09 08 │ 07 06 05 04 │ 03 02 01 00 │
#┌──────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┤
#│ carry        │  1  1  1  0 │  0  0  0  0 │  0  0  0  0 │  0  0  0  0 │  0  0  0  0 │  0  0  0  0 │  0  0  0  0 │  0  0  0    │
#├──────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┤
#│   0x7020470F │  0  1  1  1 │  0  0  0  0 │  0  0  1  0 │  0  0  0  0 │  0  1  0  0 │  0  1  1  1 │  0  0  0  0 │  1  1  1  1 │
#│ + 0x10000000 │  0  0  0  1 │  0  0  0  0 │  0  0  0  0 │  0  0  0  0 │  0  0  0  0 │  0  0  0  0 │  0  0  0  0 │  0  0  0  0 │
#├──────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┤
#│ = 0x8020470f │  1  0  0  0 │  0  0  0  0 │  0  0  1  0 │  0  0  0  0 │  0  1  0  0 │  0  1  1  1 │  0  0  0  0 │  1  1  1  1 │
#└──────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┼─────────────┤
#               │       8     │      0      │       2     │      0      │      4      │       7     │      0      │       F     │
#               └─────────────┴─────────────┴─────────────┴─────────────┴─────────────┴─────────────┴─────────────┴─────────────┘
#TF - Trap Flag
#DF - Direction Flag
#IF - Interrupt Flag
#AF - Adjust Flag
#PF - Parity Flag
#    Set if low-order eight bits of result contain an even number of "1" bits; cleared otherwise
#CF - Carry Flag
#    Set on high-order bit carry or borrow; cleared otherwise

#
#Here is a table of all the registers in x86_64 with their sizes:
# 8bit(hi,low)	16bits	32bits	64bits	bitval
ah=4;	al=0;	ax=0;	eax=0;	rax=0;	# 000
ch=5;	cl=1;	cx=1;	ecx=1;	rcx=1;	# 001	special because `rep` and others? uses it
dh=6;	dl=2;	dx=2;	edx=2;	rdx=2;	# 010
bh=7;	bl=3;	bx=3;	ebx=3;	rbx=3;	# 011
	spl=4;	sp=4;	esp=4;	rsp=4;	# 100	processor controlled pointing to stack pointer
	bpl=5;	bp=5;	ebp=5;	rbp=5;	# 101
	sil=6;	si=6;	esi=6;	rsi=6;	# 110
	dil=7;	di=7;	edi=7;	rdi=7;	# 111
	r8b=0;	r8w=0;	r8d=0;	r8=0;	# 000
	r9b=1;	r9w=1;	r9d=1;	r9=1;	# 001
	r10b=2;	r10w=2;	r10d=2;	r10=2;	# 010
	r11b=3;	r11w=3;	r11d=3; r11=3;	# 011
	r12b=4;	r12w=4;	r12d=4;	r12=4;	# 100
	r13b=5;	r13w=5;	r13d=5;	r13=5;	# 101
	r14b=6;	r14w=6;	r14d=6;	r14=6;	# 110
	r15b=7;	r15w=7;	r15d=7;	r15=7;	# 111
#		eip	rip		instruction pointer: address of the next instruction to execute.
declare -a r_8bl=( al cl dl bl ah ch dh bh );
declare -a r_64=( rax rcx rdx rbx rsp rbp rsi rdi r8 r9 r10 r11 r12 r13 r14 r15 );
#
# Note that the smallers registers uses the same space as the bigger ones. changing the small will affect the bigger
# These sub-registers are commonly used in instruction encoding and can be useful for optimizing code size.
#
# Extended registers:
#  Register Name	Size (bits)	Description
#  xmm0 - xmm15	128	Extended Multimedia Register (Streaming SIMD Extensions)
#  ymm0 - ymm15	256	Extended Multimedia Register (AVX Advanced Vector Extensions)
#  zmm0 - zmm31	512	Extended Multimedia Register (AVX-512 Advanced Vector Extensions 2)
#
# Note that YMM0-YMM15 are essentially the same as XMM0-XMM15,
# but with support for AVX (Advanced Vector Extensions)
# instructions which operate on 256-bit operands.
# zmm0-zmm31 are registers introduced in AVX-512 which support 512-bit operands.
#

is_8bit_register(){
	local v="$1";
	if [[ "${v,,}" =~ ^(al|cl|dl|bl|spl|bpl|sil|dil|r8b|r9b|r10b|r11b|r12b|r13b|r14b|r15b)$ ]]; then
		return 0;
	fi
	return 1;
}

is_8bit_legacy_register(){
	local v="$1";
	if [[ "${v,,}" =~ ^(al|cl|dl|bl|ah|ch|dh|bh)$ ]]; then
		return 0;
	fi
	return 1;
}

is_16bit_register(){
	local v="$1";
	if [[ "${v,,}" =~ ^(ax|cx|dx|bx|sp|bp|si|di|r8w|r9w|r10w|r11w|r12w|r13w|r14w|r15w)$ ]]; then
		return 0;
	fi
	return 1;
}

is_32bit_register(){
	local v="$1";
	if [[ "${v,,}" =~ ^(eax|ecx|edx|ebx|esp|ebp|esi|edi|r8d|r9d|r10d|r11d|r12d|r13d|r14d|r15d)$ ]]; then
		return 0;
	fi;
	return 1;
}

is_64bit_extended_register(){
	local v="$1";
	if [[ "${v,,}" =~ r([8-9]|1[0-5]) ]]; then
		return 0;
	fi;
	return 1;
}

is_8bit_extended_register(){
	local v="$1";
	if [[ "${v,,}" =~ (spl|bpl|sil|dil) ]]; then
		return 0;
	fi;
	return 1;
}

is_64bit_register(){
	local v="${1,,}";
	if [[ "$v" =~ ^(rax|rcx|rdx|rbx|rsp|rbp|rsi|rdi|r8|r9|r10|r11|r12|r13|r14|r15)$ ]]; then
		return 0
	fi;
	return 1;
}

is_128bit_register(){
	local v="${1,,}";
	if [[ "$v" =~ ^(xmm([0-9]|1[0-5]))$ ]]; then
		return 0
	fi;
	return 1;
}

is_256bit_register(){
	local v="$1";
	if [[ "${v,,}" =~ ^(ymm([0-9]|1[0-5]))$ ]]; then
		return 0
	fi;
	return 1;
}

is_512bit_register(){
	local v="$1";
	if [[ "${v,,}" =~ ^(zmm([12]?[0-9]|3[01]))$ ]]; then
		return 0
	fi;
	return 1;
}

is_register(){
	local v="$1";
	if is_512bit_register "$v" ||
		is_256bit_register "$v" ||
		is_128bit_register "$v" ||
		is_64bit_register "$v" ||
		is_32bit_register "$v" ||
		is_16bit_register "$v" ||
		is_8bit_register "$v"; then
		return 0;
	fi;
	return 1;
}

is_register_ptr(){
	if [[ "$1" =~ ^\(.*\)$ ]]; then
		if is_register $(printf "$1" | tr -d '()'); then
			return 0;
		fi;
	fi;
	return 1;
}

get_8bit_reg(){
	local r="$1";
	printf ${r_8bl[$((r))]};
}

fi;
