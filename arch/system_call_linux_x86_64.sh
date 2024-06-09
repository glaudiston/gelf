#!/bin/bash
#
# Here should be all x86_64 specific code.
#

. arch/system_call_linux_x86.sh

# nasm:
# https://ulukai.org/ecm/doc/insref.htm#iref-ea
#
# System Interrupt call table for 64bit linux:
# http://www.cpu2.net/linuxabi.html
#
# x86 Instruction set
# https://en.wikipedia.org/wiki/X86_instruction_listings#Original_8086.2F8088_instructions
#
# Intel i64 and IA-32 Architectures
# Instruction Set Reference: https://www.intel.com/content/www/us/en/content-details/671143/intel-64-and-ia-32-architectures-software-developer-s-manual-volume-2d-instruction-set-reference.html
# https://software.intel.com/sites/default/files/managed/39/c5/325462-sdm-vol-1-2abcd-3abcd.pdf
# Linux syscall:
# https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
# See Table A-2. One-byte Opcode Map on Intel i64 documentation (page 2626)
# See Table B-13.  General Purpose Instruction Formats and Encodings for Non-64-Bit Modes (Contd.) (page 2658)
# x64:
# The x86-64 architecture has a total of 16 general-purpose registers, 
# which are named from R0 to r15. The first 8 registers, 
# R0 to R7, can be accessed using their traditional names (AX, BX, CX, DX, BP, SI, DI, and SP), 
# which have been used since the early days of x86 processors. 
# However, the additional registers introduced in the x86-64 architecture 
# (r8 to r15) have new names that reflect their expanded capabilities 
# and wider use in modern software development. 
# These new names are intended to make it easier for programmers 
# to distinguish between the older and newer registers and to avoid naming conflicts.
#
# 16 general purpose registers
#  The prefix E stands for 32bit and R for 64bit
#  rax: Accumulator: Used In Arithmetic operations
#  rcx: Counter: Used in loops and shift/rotate instructions
#  rdx: Data: Used in arithmetic operations and I/O operations
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
declare -a r_8bl=( al cl dl bl ah ch dh bh )
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
	local v="$1";
	if [[ "${v,,}" =~ ^(rax|rcx|rdx|rbx|rsp|rsi|rdi|r8|r9|r10|r11|r12|r13|r14|r15)$ ]]; then
		return 0
	fi;
	return 1;
}
is_128bit_register(){
	local v="$1";
	if [[ "${v,,}" =~ ^(xmm([0-9]|1[0-5]))$ ]]; then
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

# THE CS (Code Segment)
# CS is the memory segment address(in address space) set for the code.
# Code and stack are in separated segments;
# the DS register is a special register for defining memory segments?

# THE REX PREFFIX:
#  x86 specifies register sizes using prefix bytes.
#  For example, the same "0xb8" instruction that loads a 32-bit constant into eax can be used with a "0x66" prefix to load a 16-bit constant, or a "0x48" REX prefix to load a 64-bit constant.
#  REX prefix is optional, without it the code will be 32bit.
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
rex(){
	local src=$1;
	local tgt=$2;
	if ! { is_64bit_register "$src" || is_64bit_register "$tgt" || is_8bit_extended_register "$src" ; }; then
		return;
	fi;
	local W=1;
	local R=0;	# 1 if source is a register from r8 to r15
	local X=0;
	local B=0;	# 1 if target(base) is a register from r8 to r15
	if is_64bit_extended_register "$src"; then
		R=1;
	fi;
	if is_64bit_extended_register "$tgt"; then
		B=1;
	fi;
	if is_8bit_extended_register "$src"; then
		R=1;
	fi;
	if is_8bit_extended_register "$tgt"; then
		B=1;
	fi;
	if is_8bit_extended_register "$src" && is_8bit_register "$tgt" && ! is_8bit_extended_register "$tgt"; then
		W=0;
		R=0;
		B=0;
	fi;
	printf "%02x" $(( (2#0100 << 4) + (W<<3) + (R<<2) + (X<<1) + B ));
}

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
	local v1="$1";
	local v2="$2";
	if is_64bit_register "$1" || is_64bit_register "$2" || is_8bit_extended_register "$1"; then
		rex "$v1" "$v2";
	fi;
	if is_16bit_register "$1" || is_16bit_register "$2"; then
		local osize="66";
		echo -n ${osize};
	fi
}

	#    $(( (2#0100 << 4) + (1 << 3) +  ( target_is_64bit_extended_register << 2 ) + ( 0 << 1) + ( source_is_64bit_extended_register ) ))
# SIB byte
#  SIB stands for: Scale Index Base
#  The x64 the ModR/M can not handle all register/memory combinations
#  for example when you try to move the rsp to an memory address,
#  the rsp(100) is set to require an additional field the SIB is this additional field
#
# +------------+--------+--------+------------+
# |   Prefix  | OpCode | ModR/M |    SIB    |
# | (optional) | 	|	 | (optional) |
# +------------+--------+--------+------------+
#
# In the opcode "48 89 C6", the byte C6 is actually the ModR/M byte, which is divided into three fields:
#
#  The ModR/M's mod field indicates the addressing mode.
#    The first 2 bits (11) indicate the addressing mode.  In this case, 11 represents the register addressing mode. It means the instruction operates on registers directly, rather than accessing memory.
#       Check the constants MODRM_MOD_DISPLACEMENT_* below to see the domain
#    The next 3 bits (110) specify the destination register (which in this case is rsi).
#    The last 3 bits (000) specify the source register (which in this case is rax).
#
# So, in summary, the ModR/M byte in the opcode "48 89 C6" indicates that we are using a register-to-register move instruction, with rsi as the destination register and rax as the source register.
# MOV_rsp_rsi="$(prefix rsp rsi | xd2esc)${MOV_R}\x$( printf %x $(( MOVR + (rsi << 3) + rsp )) )"; # move the rsp to rsi #11000110
# MOV__rsp__rsi="$(prefix "(rsp)" rsi | xd2esc)\x8b\x34\x24"; # mov (%rsp), %rsp; # move value resolving pointer
# show_bytecode "MOV %rsi, (%rsp)"
#48893424
# show_bytecode "MOV %rsi, %rsp"
#4889f4

function push(){
	local reg="$1";
	local b2=$(( 16#50 + reg ));
	if is_64bit_extended_register "$reg"; then
		local b1="$((16#41))";
		px "$b1" $SIZE_8BITS_1BYTE;
	fi;
	px "$b2" $SIZE_8BITS_1BYTE;
}

function pop(){
	local reg="$1";
	local b2=$(( 16#58 + reg ));
	if [[ "$reg" =~ R([8-9]|1[0-5]) ]]; then
		b1="$((16#41))";
		printf "%02x%02x" "${b1}" "${b2}";
	else
		printf "%02x" "${b2}";
	fi;
}

# About the "Effective Address":
#
# The offset part of a memory address can be specified directly as a static value (called a displacement) or through an address computation made up of one or more of the following components:
#
# Displacement — An 8-, 16-, or 32-bit value.
# Base — The value in a general-purpose register.
# Index — The value in a general-purpose register.
# Scale factor — A value of 2, 4, or 8 that is multiplied by the index value.
# The offset which results from adding these components is called an effective address. Each of these components can have either a positive or negative (2s complement) value, with the exception of the scaling factor.
#
# EffectiveAddress calculates an effective address using:
#
# Base + (Index*Scale) + Displacement
#
# +------------------------+----------------------------+-----------------------------+
# | Mode                  | Intel                     | AT&T                       |
# +------------------------+----------------------------+-----------------------------+
# | Absolute              | MOV EAX, [0100]           | movl           0x0100, %eax |
# | Register              | MOV EAX, [ESI]            | movl           (%esi), %eax |
# | Reg + Off             | MOV EAX, [EBP-8]          | movl         -8(%ebp), %eax |
# | Reg*Scale + Off       | MOV EAX, [EBX*4 + 0100]   | movl   0x100(,%ebx,4), %eax |
# | Base + Reg*Scale + Off | MOV EAX, [EDX + EBX*4 + 8] | movl 0x8(%edx,%ebx,4), %eax |
# +------------------------+----------------------------+-----------------------------+
#
# https://stackoverflow.com/questions/34058101/referencing-the-contents-of-a-memory-location-x86-addressing-modes/34058400#34058400
#
MODRM_MOD_DISPLACEMENT_REG_POINTER=$(( 0 << 6 ));	# If mod is 00, no displacement follows the ModR/M byte, and the operand is IN a register (like a pointer). The operation will use the address in a register. This is used with SIB for 64bit displacements
MODRM_MOD_DISPLACEMENT_8=$((   1 << 6 ));	# If mod is 01, pointer of [reg+displacement of 8 bits] follows the ModR/M byte.
MODRM_MOD_DISPLACEMENT_32=$((  2 << 6 ));	# If mod is 10, pointer of [reg+displacement of 32 bits] follows the ModR/M byte.
MODRM_MOD_NO_EFFECTIVE_ADDRESS=$(( 3 << 6 ));	# If mod is 11, the operand is a register, and there is no SIB and no displacement. The operation will use the register itself. It can have immediate memory or value, but not an effective address, sib or displacement.
# Here's a table with the 3-bit ModR/M values and their corresponding descriptions, including the value 101 for MOV rax, imm:
# 3-bit	Description
# 000	Register (Direct)
# 001	Register (Indirect w/Disp8)
# 010	Register (Indirect w/Disp32)
# 011	Memory (SIB w/Disp32)
# 100	Register (Direct)
# 101	Immediate to register
# 110	Memory (Direct w/Disp32)
# 111	Register (Direct)

MODRM_OPCODE_ADD=$(( 0 << 3 )) # 000
MODRM_OPCODE_OR=$((  1 << 3 )) # 001
MODRM_OPCODE_ADC=$(( 2 << 3 )) # 010
MODRM_OPCODE_SBB=$(( 3 << 3 )) # 011
MODRM_OPCODE_AND=$(( 4 << 3 )) # 100
MODRM_OPCODE_SUB=$(( 5 << 3 )) # 101
MODRM_OPCODE_XOR=$(( 6 << 3 )) # 110
MODRM_OPCODE_CMP=$(( 7 << 3 )) # 111

MODRM_REG_rax=$(( rax << 3 )); # 000 0
MODRM_REG_rcx=$(( rcx << 3 )); # 001 1
MODRM_REG_rdx=$(( rdx << 3 )); # 010 2
MODRM_REG_rbx=$(( rbx << 3 )); # 011 3
MODRM_REG_rsp=$(( rsp << 3 )); # 100 4
MODRM_REG_rbp=$(( rbp << 3 )); # 101 5
MODRM_REG_rsi=$(( rsi << 3 )); # 110 6
MODRM_REG_rdi=$(( rdi << 3 )); # 111 7
MODRM_REG_r8=$((  r8  << 3 )); # 000 0
MODRM_REG_r9=$((  r9  << 3 )); # 001 1
MODRM_REG_r10=$(( r10 << 3 )); # 010 2
MODRM_REG_r11=$(( r11 << 3 )); # 011 3
MODRM_REG_r12=$(( r12 << 3 )); # 100 4
MODRM_REG_r13=$(( r13 << 3 )); # 101 5
MODRM_REG_r14=$(( r14 << 3 )); # 110 6
MODRM_REG_r15=$(( r15 << 3 )); # 111 7
MOV="$(( MODRM_MOD_DISPLACEMENT_32 ))";	# \x80 Move using memory as source (32-bit)
MOVR="$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS ))";	# \xc0 move between registers

modrm(){
	local v1="$1";
	local v2="$2";
	if [[ "$v1" =~ ^\(.*\)$ ]]; then	# resolve pointer address value
	{
		local v1_r=$( echo $v1 | tr -d '()' );
		local mod_reg=$(( v2 << 3 )); # 000 0
		if is_register "$v1_r"; then
			if is_register "$v2"; then
				local modrm_v=$(( MODRM_MOD_DISPLACEMENT_REG_POINTER | mod_reg | v1_r ));
				px "$modrm_v" $SIZE_8BITS_1BYTE;
				return;
			fi;
		fi;
		if is_valid_number "$v1_r"; then
			if is_register "$v2"; then
				local use_sib=4;
				local modrm_v=$(( MODRM_MOD_DISPLACEMENT_REG_POINTER | mod_reg | use_sib));
				px "$modrm_v" $SIZE_8BITS_1BYTE;
				return;
			fi;
		fi
		error not implemented;
	}
	fi;
	if is_valid_number "$v1"; then
	{
		local mod_reg=0;
		modrm="$(px "$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + mod_reg + v2 ))" $SIZE_8BITS_1BYTE)";
		printf $modrm;
		return;
	}
	fi;
	if is_64bit_register "$v1"; then
	{
		local mod_reg=$(( v1 << 3 ));
		if [[ "$v2" =~ ^\(.*\)$ ]]; then	# resolve pointer address value
		{
			local v2_r=$( echo $v2 | tr -d '()' );
			if is_register "$v2_r"; then
				local mod_reg=$(( v1 << 3 )); # 000 0
				if is_register "$v1"; then
					modrm="$(px "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + mod_reg + v2_r ))" $SIZE_8BITS_1BYTE)";
				fi;
			fi;
			printf "${modrm}";
			return;
		}
		fi;
		if is_register "$v2"; then
			modrm="$(px "$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + mod_reg + v2 ))" $SIZE_8BITS_1BYTE)";
			printf "$modrm";
			return;
		elif is_valid_number "$v2"; then
			# the rsp(100) is set to require an additional field the SIB is this additional field
			local use_sib=4;
			printf "$(px $(( MODRM_MOD_DISPLACEMENT_REG_POINTER + mod_reg + use_sib )) ${SIZE_8BITS_1BYTE} )";
			return;
		fi;
		error not implemented
	}
	fi;
	if is_8bit_register "$v1"; then
	{
		if is_8bit_register "$v2"; then
			local modrm="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + $(( v1 << 3 )) + v2 )) $SIZE_8BITS_1BYTE)";
			printf $modrm;
			return;
		fi;
		if is_valid_number "$v2"; then
		{
			local use_sib=4;
			local modrm_v=$(( MODRM_MOD_DISPLACEMENT_REG_POINTER | $(( v1 << 3 )) | use_sib ))
			local modrm=$(px ${modrm_v} $SIZE_8BITS_1BYTE);
			printf $modrm;
			return;
		}
		fi;
	}
	fi;
	error not implemented;
}

TEST="\x85"; # 10000101
IMM="$(( 2#00111000 ))";
MOV_8BIT="\x88";
#MOV="\x89";
MOV_RESOLVE_ADDRESS="\x8b"; # Replace the address pointer with the value pointed from that address
mov(){
	local v1="$1";
	local v2="$2";
	local code="";
	code="${code}$(prefix "$v1" "$v2")";
	local modrm="";
	if [[ "$v1" =~ ^\(.*\)$ ]]; then	# resolve pointer address value
	{
		local v1_r=$( echo $v1 | tr -d '()' );
		local mov_resolve_address="8b";
		code="${code}${mov_resolve_address}";
		if is_register "$v1_r"; then
			local mod_reg=$(( v2 << 3 )); # 000 0
			if is_register "$v2"; then
				modrm="$(px "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + mod_reg + v1_r ))" $SIZE_8BITS_1BYTE)";
			fi;
		fi;
		if is_valid_number "$v1_r"; then
			if is_register "$v2"; then
				local use_sib=4;
				# sib is a byte:
				#    11    111      111
				# scale^2  4=IMM32
				modrm="$( px $(( MODRM_MOD_DISPLACEMENT_REG_POINTER + (v2 << 3) + use_sib)) $SIZE_8BITS_1BYTE)25$(px $v1_r $SIZE_32BITS_4BYTES)";
			fi;
		fi
		code="${code}${modrm}";
	}
	fi;
	if is_valid_number "$v1"; then
	{
		if is_8bit_uint "$v1" && is_8bit_register "$v2"; then
			code="${code}$(px $(( 16#B0 + v2 )) $SIZE_8BITS_1BYTE)"
			code="${code}$(px "$v1" $SIZE_8BITS_1BYTE)";
			printf "${code}";
			debug "asm: mov $@; # $code"
			return;
		fi;
		local mov_v4_reg="c7";
		local mod_reg=0;
		modrm="$(px "$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + mod_reg + v2 ))" $SIZE_8BITS_1BYTE)";
		code="${code}${mov_v4_reg}${modrm}$(px "$v1" $SIZE_32BITS_4BYTES)";
	}
	fi;
	if is_64bit_register "$v1"; then
	{
		code="${code}89";
		local mod_reg=$(( v1 << 3 ));
		if [[ "$v2" =~ ^\(.*\)$ ]]; then	# resolve pointer address value
		{
			local v2_r=$( echo $v2 | tr -d '()' );
			if is_register "$v2_r"; then
				local mod_reg=$(( v1 << 3 )); # 000 0
				if is_register "$v1"; then
					modrm="$(px "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + mod_reg + v2_r ))" $SIZE_8BITS_1BYTE)";
				fi;
				if [ "$v2_r" == "rsp" ]; then # rsp is a special case where the next byte is sib;
					sib=$(px $(( MODRM_MOD_DISPLACEMENT_REG_POINTER + ( v2_r << 3 ) )) $SIZE_8BITS_1BYTE);
					modrm="$modrm$sib"; 
				fi;
			fi;
			code="${code}${modrm}";
			debug "asm: mov $@; # $code";
			echo -n "$code";
			return;
		}
		fi;
		if is_register "$v2"; then
			modrm="$(px "$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + mod_reg + v2 ))" $SIZE_8BITS_1BYTE)";
			code="${code}${modrm}";
			local rv="$(echo -en "${code}")";
			echo -n $rv;
			debug "mov $@; # $rv";
			return;
		elif is_valid_number "$v2"; then
			# if 32 bits addr
			# MOV %rsp ADDR: 48892425 78100000 ? not tested
			# 48: rex_64bit
			# 89: MOV instruction
			# 24: 00100100 MOD/R
			# 25: 00100101 SIB
			# 78100000: little endian 32bit addr
			# the rsp(100) is set to require an additional field the SIB is this additional field
			local sib=$rsp;
			MOD_RM="$( px $(( MODRM_MOD_DISPLACEMENT_REG_POINTER + mod_reg + sib )) ${SIZE_8BITS_1BYTE} )";
			SIB=$(px $(( 2#00100101 )) ${SIZE_8BITS_1BYTE});
			local v="$(px "$v2" $SIZE_32BITS_4BYTES)";
			code="${code}${INSTR_MOV}${MOD_RM}${SIB}${v}";
		else
			error not implemented
		fi;
		code="${code}${modrm}";
	}
	fi;
	if is_8bit_register "$v1"; then
	{
		if is_8bit_register "$v2"; then
			mov_8bit="88";
			rex="40";
			code="${rex}${mov_8bit}";
			code="${code}$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + $(( v1 << 3 )) + v2 )) $SIZE_8BITS_1BYTE)";
			echo -n "${code}";
			debug "asm: mov $@; # $code"
			return;
		fi;
		if is_valid_number "$v2"; then
		{
			local mov_8bit="88";
			# See Intel Instruction Format manual
			# Table 2-3. 32-Bit Addressing Forms with the SIB Byte (intel ref)
			# https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
			local sib_index_none=4;	# 4 == none (no register because ebp is not allowed)
			local sib_base_none=5;	# 5 == means a disp32 with no base if the MOD is 00B. Otherwise, [*] means disp8 or disp32 + [EBP]. This provides the following address modes
						# MOD bits Effective Address
						# 00 [scaled index] + disp32
						# 01 [scaled index] + disp8 + [EBP]
						# 10 [scaled index] + disp32 + [EBP]
			local scale=$(( 0 << 6 ));
			local index=$(( sib_index_none << 3 ));
			local base=$(( sib_base_none << 0 ));
			local sib=$(px $(( scale | index | base )) $SIZE_8BITS_1BYTE);
			local prefix="";
			local opcode="${mov_8bit}";
			local use_sib=4;
			local modrm=$(px $(( MODRM_MOD_DISPLACEMENT_REG_POINTER + $(( v1 << 3 )) + use_sib )) $SIZE_8BITS_1BYTE);
			local displ32="$(px $v2 $SIZE_32BITS_4BYTES)";
			local instr="${prefix}${opcode}${modrm}${sib}${displ32}";
			echo -n "${instr}";
			debug "asm: mov $@; # $code"
			return;
		}
		fi;
	}
	fi;
	debug mov $@: out [$code];
	echo -n $code;
}
# CMP
cmp(){
	local v1="$1";
	local v2="$2";
	local opcode="";
	local mod_rm="";
	local code="";
	code="${code}$(prefix "$v1" "$v2")";
	if is_8bit_register "$v1"; then
	{
		opcode="38";
		if is_8bit_register "$v2"; then
		{
			mod_rm="$(px $((MODRM_MOD_NO_EFFECTIVE_ADDRESS + (v1 << 3) + v2 )) $SIZE_8BITS_1BYTE)";
			code="${code}${opcode}${mod_rm}";
			echo -en "$code";
			debug "asm: cmp $@; # $code";
			return;
		}
		fi;
		if is_valid_number "$v2"; then
		{
			if [ "$v2" -lt 256 ]; then # TODO not sure if 127 or 256
			{
				imm8="$(px "$v2" $SIZE_8BITS_1BYTE)"; # immediate value with 8 bits
				if [ "$v1" = "al" ]; then
				{
					code="${code}3c$(px "${imm8}" $SIZE_8BITS_1BYTE)"; # only valid to %al: cmp %al, imm8;
					echo -en "$code";
					debug "asm: cmp $@; # $code";
					return;
				}
				fi;
				# byte registers without REX:
				# CMP r/m8, imm8 	Compare imm8 with r/m8
				# 80 /7 ib
				# \xb0 %al/r8b, lb ... \xb7
				#
				#  80F800            cmp al,0x0
				#  80F900            cmp cl,0x0
				#  80FA00            cmp dl,0x0
				#  80FB00            cmp bl,0x0
				#  80FC00            cmp ah,0x0
				#  80FD00            cmp ch,0x0
				#  80FE00            cmp dh,0x0
				#  80FF00            cmp bh,0x0
				#
				# byte registers with REX:
				# they are: AL, BL, CL, DL, DIL, SIL, BPL, SPL, R8B - R15B;
				# but we will not use the ones we can reach without the REX byte;
				# so we expect to use only for DIL, SIL, BPL, SPL, R8B - R15B;
				# 248:00000000  4880F800          o64 cmp al,0x0
				#  4880F800          o64 cmp al,0x0
				#  4880F900          o64 cmp cl,0x0
				#  4880FA00          o64 cmp dl,0x0
				#  4880FB00          o64 cmp bl,0x0
				#  4880FC00          o64 cmp spl,0x0
				#  4880FD00          o64 cmp bpl,0x0
				#  4880FE00          o64 cmp sil,0x0
				#  4880FF00          o64 cmp dil,0x0
				#
				opcode="$( px $(( 16#f8 + v1 )) $SIZE_8BITS_1BYTE)";
				code="${code}80${opcode}${imm8}";
				debug "asm: cmp $@; # $code";
				echo -en "$code";
				return;
			}
			fi;
			error not implemented or allowed?
		}
		fi;
	}
	fi;
	if is_64bit_register "$v1"; then
	{
		if is_valid_number "$v2"; then
		{
			if [ "$v2" -gt -128 -a "$v2" -lt 128 ]; then
			{
				local cmp=83; # only if most significant bit(bit 7) of the next byte is 1 and depending on opcode(bits 6-3) And ModR/M opcode
				local cmp_v1="${cmp}$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + MODRM_OPCODE_CMP + v1 )) $SIZE_8BITS_1BYTE)";
				code="${code}${cmp_v1}$(px $v2 $SIZE_8BITS_1BYTE)";
				local rv=$(echo -en "${code}");
				debug "asm: cmp $@; # $rv"
				echo -n "$rv";
				return;
			}
			fi;
			b1="39";
			b2="$(( 16#04 + (v1 << 3) ))";
			b3="25";
			code="${code}${b1}${b2}${b3}"; # cmp rax v4;
			debub "asm: cmp $@; # $code";
			echo $code;
		}
		fi;
		if is_64bit_register "$v2"; then
			local b1="39";
			local b2="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + (v1 << 3) + v2 )) $SIZE_8BITS_1BYTE)";
			local rv="${code}${b1}${b2}";
			debug "asm: cmp $@; # $rv";
			echo -n "$rv";
			return;
		fi;
	}
	fi;
	error not implemented
}
# perform a bitwise AND using register
test(){
	local v1="$1";
	local v2="$2";
	v2="${v2:=$v1}";
	local prefix="$(prefix "$v1" "$v2")";
	local opcode="";
	debug "test [$v1] [$v2]";
	if is_8bit_legacy_register "$v1" && is_8bit_legacy_register "$v2"; then
		opcode=84;
	else
		opcode=85;
	fi;
	local modrm="$(px $(( 16#c0 + (v1 << 3) + v2 )) $SIZE_8BITS_1BYTE)";
	local sib="";
	local displacement="";
	local immediate="";
	local instr="${prefix}${opcode}${modrm}${sib}${displacement}${immediate}";
	printf $instr;
}
CMP_rax_ADDR4_rdx_8="483904D5";
CMP_rbx_ADDR4_rdx_8="\x48\x39\x1C\xD5";
CMP_ADDR4_rdx_8_rbx="\x48\x3B\x1C\xD5";
CMP_V4_rdx_8_rax="483B04D5";
shlq(){
	local v1=$1;
	local v2=$2;
	local p=$(prefix "$v1" "$v2");
	if is_valid_number "$v1"; then
		local opcode1="C1";
		local opcode2="$( px $(( 16#e0 + v2 )) $SIZE_8BITS_1BYTE )";
		local code="";
		code="${code}${p}${opcode1}${opcode2}$(px $((v1)) $SIZE_8BITS_1BYTE)";
		rv=$(echo -en "${code}");
		debug "shlq $@; # $rv"
		echo -n "$rv";
		return;
	fi;
	if [ "$v1" == "cl" ]; then
		local opcode1="D3";
		local opcode2="$( px $(( 16#e0 + v2 )) $SIZE_8BITS_1BYTE)";
		local code="";
		code="${code}${p}${opcode1}${opcode2}";
		local rv=$(echo -en "${code}");
		debug "shlq $@; # $rv"
		echo -n "$rv"
		return;
	fi;
	error not implemented/supported
}
shrq(){
	local v1=$1;
	local v2=$2;
	local p=$(prefix "$v1" "$v2");
	if is_valid_number "$v1"; then
		local opcode1="c1";
		local opcode2="$( px $(( 16#e8 + v2 )) $SIZE_8BITS_1BYTE)";
		local code="";
		code="${code}${p}${opcode1}${opcode2}$(px $((v1)) $SIZE_8BITS_1BYTE)";
		echo -n "${code}";
		debug "asm: shrq $@; # $code"
		return;
	fi;
	if [ "$v1" == "cl" ]; then
		local opcode1="d3";
		local opcode2="$( px $(( 16#e8 + v2 )) $SIZE_8BITS_1BYTE)";
		local code="";
		code="${code}${p}${opcode1}${opcode2}";
		local rv=$(echo -n "${code}");
		debug "asm: shrq $@; # $rv"
		echo -n $rv;
		return;
	fi;
	error not implemented/supported
}
# JMP
# We have some types of jump
# Relative jumps (short and near):
JMP_V1="eb"; # followed by a 8-bit signed char (-128 to 127) to move relative to BIP.
JMP_V4="e9"; # followed by a 32-bit signed integer(-2147483648 to 2147483647).
# Jump to the full virtual address
JMP_rax="\xff";
JMP_rdi="\xe0";
JNE="0f85"; # The second byte "85" is the opcode for the JNE(Jump if Not Equal) same of JNZ(Jump if Not Zero) instruction. The following four bytes "06 00 00 00" represent the signed 32-bit offset from the current instruction to the target label.
JZ="\x0f\x84";
JNC_BYTE="\x73"; # jae, jnb and jnc are all the same condition code CF = 0.
JZ_BYTE="74"; # follow by a signed byte from FF (-126) to 7f (127)
JNZ_BYTE="\x75";
JNA_BYTE="\x76";
JA_BYTE="\x77"; # CF = 0, ZF = 0
JS_BYTE="\x77";
JL_V1="\x7c";
JG_V1="7F";
JGE_V1="7D";
JNG_V1="7E";
JL_V4="\x0f\x8c";
JGE_V4="\x0f\x8d"; # Jump if greater than or igual to zero flags: SF = OF
JG="0F8F"; # Jump if Greater than zero; flags: SF = OF, ZF = 0
#jbe, jna	CF = 1 or ZF = 1
#jb, jc, jnae	CF = 1
#jle, jng	SF != OF or ZF = 1
#jl, jnge	SF != OF

#js	SF = 1
#jns	SF = 0
#	
#jo	OF = 1
#jno	OF = 0
#	
#jp, jpe (e = even)	PF = 1
#jnp, jpo (o = odd)	PF = 0


#jcxz, jecxz	cx = 0 (16b mode)
#jcxz, jecxz	ecx = 0 (32b mode)

#http://unixwiz.net/techtips/x86-jumps.html
#Instruction 	Description 			signed-ness 	Flags 	short jump 	near jump
#									opcodes		opcodes
#JO		Jump if overflow 			  	OF = 1		70	0F 80
#JNO 		Jump if not overflow 	  			OF = 0	 		71 	0F 81
#JS 		Jump if sign 	  				SF = 1 			78 	0F 88
#JNS 		Jump if not sign 		  		SF = 0 			79 	0F 89
#JE		Jump if equal/
#JZ		Jump if zero					ZF = 1 			74 	0F 84
#JNE
#JNZ	 	Jump if not equal/
#		Jump if not zero 			  	ZF = 0 			75 	0F 85
#JB		Jump if below
#JNAE		Jump if not above or equal
#JC		Jump if carry 	unsigned 			CF = 1 			72 	0F 82
#JNB		Jump if not below/
#JAE		Jump if above or equal/
#JNC 		Jump if not carry		unsigned 	CF = 0 			73 	0F 83
#JBE		Jump if below or equal
#JNA 		Jump if not above		unsigned 	CF = 1 or ZF = 1 	76 	0F 86
#JA		Jump if above
#JNBE 		Jump if not below or equal 	unsigned 	CF = 0 and ZF = 0 	77 	0F 87
#JL 		Jump if less
#JNGE		Jump if not greater or equal 	signed 		SF <> OF 		7C 	0F 8C
#JGE 		Jump if greater or equal
#JNL		Jump if not less 		signed 		SF = OF 		7D 	0F 8D
#JLE	 	Jump if less or equal
#JNG		Jump if not greater 		signed 		ZF = 1 or SF <> OF 	7E 	0F 8E
#JG 		Jump if greater
#JNLE		Jump if not less or equal 	signed 		ZF = 0 and SF = OF 	7F 	0F 8F
#JP		Jump if parity
#JPE 		Jump if parity even 	  			PF = 1 			7A 	0F 8A
#JNP 		Jump if not parity
#JPO		Jump if parity odd 	  			PF = 0 			7B 	0F 8B
#JCXZ		Jump if %CX register is 0
#JECXZ		Jump if %ECX register is 0 	  		%CX = 0 %ECX = 0 	E3
jz(){
	local v="$1";
	local code=""
	code="${code}${JZ_BYTE}";
	code="${code}$(px "$v" $SIZE_8BITS_1BYTE)";
	echo -e "${code}";
}
jg(){
	local v="$1";
	local code=""
	code="${code}${JG_V1}";
	code="${code}$(px "$v" 1)";
	echo -n "${code}";
}
jmp(){
	# JMP_V4="\xe9"; # followed by a 32-bit signed integer(-2147483648 to 2147483647).
	local v1=$1;
	if is_8bit_sint "$v1"; then
	{
		local code="eb";
		code="${code}$(px "${v1}" $SIZE_8BITS_1BYTE)";
		echo -en "${code}";
		debug "asm: jmp .$v1; # $code"
		return;
	}
	fi;
	if is_32bit_sint "$v1"; then
	{
		local code="e9";
		code="${code}$(px "${v1}" $SIZE_32BITS_4BYTES)";
		echo -en "${code}";
		debug "asm: jmp .$v1; # $code"
		return;
	}
	fi;
	debug "asm: jmp .$v1; #  not supported $code: jmp $@"
}

MOV_AL_ADDR4="\x88\x04\x25";
# LEA - Load Effective Address (page 1146)
#LEAQ_RIP_rbx="$(prefix rip rbx | xd2esc)\x8d\x1d\x00\x00\x00\x00";
LEA_rax_rax_4="\x8d\x04\x80";
LEA_V4_rdx="$(prefix v4 rdx | xd2esc)\x8d\x14\x25";
LEA_V4_rax="$(prefix v4 rax | xd2esc)\x8d\x04\x25";
LEA_V4_rcx="$(prefix v4 rcx | xd2esc)\x8d\x0c\x25";
MOV_ADDR4_rdx="$(prefix addr4 rdx | xd2esc)\x8b\x14\x25"; # followed by 4 bytes le;
MOV_ADDR4_rax="$(prefix addr4 rax | xd2esc)\x8b\x04\x25";
MOV_ADDR4_rsi="$(prefix addr4 rsi | xd2esc)\x8b\x34\x25";
MOV_ADDR4_rdi="$(prefix addr4 rdi | xd2esc)\x8b\x3c\x25";
MOV_V4_rax="$(prefix v4 rax | xd2esc)\xc7\xc0";
MOV_V4_rcx="$(prefix v4 rcx | xd2esc)\xc7\xc1";
MOV_V4_rdx="$(prefix v4 rdx | xd2esc)\xc7\xc2"; # MOV value and resolve address, so the content of memory address is set at the register
MOV_V4_rsi="$(prefix v4 rsi | xd2esc)\xc7\xc6";
MOV_V4_rdi="$(prefix v4 rdi | xd2esc)\xc7\xc7";
MOV_V8_rax="$(prefix v8 rax | xd2esc)$( printEndianValue $(( MOV + IMM + rax )) ${SIZE_8BITS_1BYTE} )"; # 48 b8
MOV_V8_rdx="$(prefix v8 rdx | xd2esc)$( printEndianValue $(( MOV + IMM + rdx )) ${SIZE_8BITS_1BYTE} )"; # 48 ba
MOV_V8_rsi="$(prefix v8 rsi | xd2esc)$( printEndianValue $(( MOV + IMM + rsi )) ${SIZE_8BITS_1BYTE} )"; # 48 be
#debug MOV_rsi=$MOV_rsi
MOV_V8_rdi="$(prefix v8 rdi | xd2esc)$( printEndianValue $(( MOV + IMM + rdi )) ${SIZE_8BITS_1BYTE} )"; # 48 bf; #if not prepended with rex(x48) expect 32 bit register (edi: 4 bytes)
MOV_CL_ADDR4_rdi="888F";
MOV_R="\x89";
MOVSB="\xa4"; # move 64bits(8 bytes) from %rsi addr to %rdi addr
#MOVSQ="$(prefix | xd2esc)\xa5"; # move 64bits(8 bytes) from %rsi addr to %rdi addr
REP="\xf3"; # repeat until rcx
#MOVSBL_V4rsp_EAX="\x0F\xBE\x44\x24";
#MOV_rsi_rcx="\x48\x89\xF1";
#MOVSBL_V4rsi_ECX="\x0F\xBE\x4E$(printEndianValue 63 $SIZE_8BITS_1BYTE)";
#MOVZX_DL_rdx="\x48\x0F\xB6\xD2";
#LEA_rdx_rdx="\x48\x8B\x12";
#MOV_rsi_rsi="\x48\x8B\x36";
#MOVZX_SIL_rsi="\x48\x0F\xB6\xF6";
#MOVZX_SIL_rdi="\x48\x0F\xB6\xFE";
MOVZX_DL_rdi="480fb6fa";
SBB_0_EDX="83da00";
MOVSBL_V4_rdx_EDX="0FBE1415";

# show_bytecode "mov %rsp, %rsi"
# 4889e6
MOV_rax_rsi="$(mov rax rsi | xd2esc)"; # xC6 move the rax to rsi #11000110
MOV_rax_rdx="$(mov rax rdx | xd2esc)";
MOV_rax_rdi="$(mov rax rdi | xd2esc)";
MOV_rdx_rcx="$(mov rdx rcx | xd2esc)";
#MOV_rsp_rsi="$(prefix rsp rsi | xd2esc)${MOV_R}\xe6"; # Copy the rsp(pointer address) to the rsp(as a pointer address).
MOV_rsp_rax="$(mov rsp rax | xd2esc)";
MOV_rsp_rsi="$(mov rsp rsi | xd2esc)"; # move the rsp to rsi #11000110
MOV_rsp_rdx="$(mov rsp rdx | xd2esc)"; # move the rsp to rdx #11000010
MOV_rsp_rdi="$(mov rsp rdi | xd2esc)";
MOV_rsi_rax="$(mov rsi rax | xd2esc)"; # move the rsi to rdx #11110010
MOV_rsi_rdx="$(mov rsi rdx | xd2esc)"; # move the rsi to rdx #11110010

# add: given a value or a register on r1, add it to r2
# r1: can be a register id, a integer value or a address value
# 	input: register or "[address]" or integer value
# 	output: not changed
# r2: register result of add r1 and r2
# 	input: register
# 	output: added r1 and r2
ADD_FULL="\x81"; # ADD 32 or 64 bit operand (depend on ModR/M
ADD_M64="$(prefix rax | xd2esc)${ADD_FULL}";
ADD_M64_rdi="${ADD_M64}";
ADD_EAX_EAX="\x01\xc0";
ADD_rsi_rdx="$(prefix rsi rdx | xd2esc)\x01\xF2";
ADD_V4_rdx="$(prefix v4 rdx | xd2esc)\x81\xC2";
ADD_V4_rdi="$(prefix v4 rdi | xd2esc)\x81\xC7";
ADD_r15_r14="$(prefix r15 r14 | xd2esc)\x01\xfe";
ADD_r15_rax="$(prefix r15 rax | xd2esc)\x01\xF8";
ADD_r15_rsi="$(prefix r15 rsi | xd2esc)\x01\xFE";
ADD_rcx_r8="$(prefix rcx r8 | xd2esc)\x01\xc8";
ADD_rdx_r8="$(prefix rdx r8 | xd2esc)\x01\xd0";
ADD_r8_rdi="$(prefix r8 rdi | xd2esc)\x01\xc7";
add(){
	local ADD_SHORT="83"; # ADD 8 or 16 bit operand (depend on ModR/M opcode first bit(most significant (bit 7)) been zero) and the ModR/M opcode
	local r1="$1";
	local r2="$2";
	local code="";
	local p=$(prefix "$r1" "$r2");
	if [ "$r2" = "AL" ]; then
		ADD_AL="04";
		code="${code}${ADD_AL}$(px "$r1" ${SIZE_8BITS_1BYTE})";
		echo -n "${code}";
		debug "asm: add $@; # $(echo -n "$code")"
		return
	fi;
	if is_8bit_register "$r1" && is_8bit_register "$r2"; then
		b1="00";
		b2="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + (r1 << 3) + r2 )) $SIZE_8BITS_1BYTE)";
		code="$p$b1$b2";
		echo -n $code;
		debug "add $@; # $code";
		return;
	fi;
	if is_register "$r1"; then
	{
		if is_register "$r2"; then
		{
			local opadd="${p}01";
			local rv=$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + MODRM_OPCODE_ADD + (${r1,,} << 3) + ${r2,,} ));
			r=$(px $rv $SIZE_8BITS_1BYTE);
			code="${code}${opadd}${r}";
			echo -n "${code}";
			debug "asm: add $@; # $(echo -n "$code")"
			return;
		}
		fi;
	}
	elif is_valid_number "$r1"; then
	{
		if is_register "$r2"; then
			if [ $r1 -lt 128 ]; then
			{
				r=$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + MODRM_OPCODE_ADD + ${r2,,} ))
				code="${code}${p}${ADD_SHORT}$(px $r $SIZE_8BITS_1BYTE)";
				code="${code}$(px $r1 $SIZE_8BITS_1BYTE)";
				debug "asm: add $@; # $(echo -n "$code")"
				echo -n "${code}";
				return;
			}
			fi;
		fi;
	}
	else
	{
		error "mem ref not implemented yet"
	}
	fi;
	error "not implemented: add $@"
}
# SUB
#    28H: SUB with two 8-bit operands.
#    29H: SUB with 32-bit operands (or 64bit registers, depends on ModR/M.
#    2AH: SUB with 8-bit or 16-bit operands.
#    2BH: SUB with 16-bit or 64-bit operands.
#    80H /n: SUB with immediate data and 8-bit operands.
#    81H /n: SUB with immediate data and 16-bit or 32-bit operands.
#    83H /n: SUB with immediate data and sign-extended 8-bit or 32-bit operands.
SUB_R="\x29";
SUB_64bit="\x2B";
SUB_IMM32="\x81";
SUB_IMMSE8="\x83" # This depends on ModR/M OpCode
#SUB_rsp_SHORT="$(prefix v1 rsp | xd2esc)\x83\xec"; # Subtract 1 byte(two complement) value from rsp
SUB_ADDR4_rax_rax="482b04d5";
SUB_rdx_rsi="$(prefix rdx rsi | xd2esc)${SUB_R}${ModRM}";
SUB_rsi_rdx="$(prefix rsi rdx | xd2esc)\x29\xf2";
sub(){
	local v1="$1";
	local v2="$2";
	local p="$(prefix "$v1" "$v2")";
	if is_8bit_register "$v1" && is_8bit_register "$v2"; then
		opcode1="28";
		opcode2="$(px $((MODRM_MOD_NO_EFFECTIVE_ADDRESS + (v1 << 3) + v2 )) $SIZE_8BITS_1BYTE)";
		c="${p}${opcode1}${opcode2}";
		debug "asm: sub $@; # $c";
		echo -n "$c";
		return;
	fi;
	if is_valid_number "$v1" && is_8bit_sint "$v1"; then
	{
		#4883E801          sub rax,byte +0x1
		#48832801          sub qword [rax],byte +0x1
		if is_register "$v2"; then
			opcode1="83";
			opcode2=$(px $(( 16#e8 + v2 )) $SIZE_8BITS_1BYTE);
			c="${p}${opcode1}${opcode2}$(px $v1 $SIZE_8BITS_1BYTE)";
			debug "asm: sub $@; # $c";
			echo -n $c;
			return;
		fi;
	}
	fi;
	if is_64bit_register "$v1"; then
	{
		if is_64bit_register "$v2"; then
		{
			opcode=29;
			modrm="$(px $(( ${MODRM_MOD_NO_EFFECTIVE_ADDRESS} + (v1 << 3) + v2 )) 1)";
			c="${p}${opcode}${modrm}";
			debug "asm: sub $@; # $c";
			echo -n "$c";
			return;
		}
		fi;
	}
	fi;
	error not implemented sub $@
}
is_8bit_uint(){
	local v="$1";
	[ "$(( (v >= 0 && (v < (1 << 8)) ) ))" -eq 1 ];
}
is_8bit_sint(){
	local v="$1";
	[ "$(( (v > - ( 1 << 7 )) && (v < ( 1 << 7 ) -1) ))" -eq 1 ];
}
is_32bit_uint(){
	local v="$1";
	[ "$(( (v >= 0 && (v < (1 << 32)) ) ))" -eq 1 ];
}
is_32bit_sint(){
	local v="$1";
	[ "$(( (v > - ( 1 << 31 )) && (v < ( 1 << 31 ) -1) ))" -eq 1 ];
}
# signed integer multiply
imul(){
	local v1="$1";
	local v2="$2";
	local p="$(prefix "$1" "$2")";
	if is_valid_number "$1"; then
		# 486BF60A	# imul $10,%rsi ; imul rsi,rsi,byte +0xa
		#
		local b1="6b";
		# f0 + target reg + reg mul
		local b2="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + (v2<<3) + v2)) $SIZE_8BITS_1BYTE)";
		local b3="$(px "$v1" $SIZE_8BITS_1BYTE)";
		c="$p$b1$b2$b3";
		echo -n "$c";
		debug "imul $@; # $c"
		return;
	fi;
	if is_register "$1"; then
		# 480fafc2	imul %rdx,%rax
		local b1="0f";
		local b2="af";
		local b3="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + (v1 << 3) + v2)) $SIZE_8BITS_1BYTE)";
		c="$p$b1$b2$b3";
		echo -n "$c";
		debug "imul $@; # $c"
		return;
	fi;
	error not implemented: imul $@
}
dec(){
	local r=$1;
	local p=$(prefix $r);
	local inc_op="ff";
	local reg=$(px $((MODRM_MOD_NO_EFFECTIVE_ADDRESS + ${r,,} + 8)) $SIZE_8BITS_1BYTE);
	echo -n "${p}${inc_op}${reg}";
}
inc(){
	local r=$1;
	local p=$(prefix $r);
	local inc_op="ff";
	local reg=$(px $((MODRM_MOD_NO_EFFECTIVE_ADDRESS + ${r,,})) $SIZE_8BITS_1BYTE);
	echo -n "${p}${inc_op}${reg}";
}

# MOV_RESOLVE_ADDRESS needs the ModR/M mod (first 2 bits) to be 00.
MOV_rcx_rcx="$(prefix "(rcx)" rcx | xd2esc)\x8b\x09";
MODRM="$(printEndianValue "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_rsi + rsi))" $SIZE_8BITS_1BYTE)";
MOV_rsi_rsi="$(mov "(rsi)" rsi | xd2esc)"; # mov (%rsi), %rsi
MODRM="$(printEndianValue "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_rdx + rdx))" $SIZE_8BITS_1BYTE)";
MOV_rdx_rdx="$(prefix "(rdx)" rdx | xd2esc)${MOV_RESOLVE_ADDRESS}${MODRM}";
MODRM="$(printEndianValue "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_rdi + rdi))" $SIZE_8BITS_1BYTE)";
MOV_rdi_rdi="$(prefix "(rdi)" rdi | xd2esc)${MOV_RESOLVE_ADDRESS}${MODRM}";
MOV_rdi_ADDR4="$(prefix rdi addr4 | xd2esc)\x89\x3C\x25";

# show_bytecode "movq (%rsp), %rsi"
# 488b3424
# MOV_VALUE_rsi_rsp="$(rex | b64_2esc)\x8b\x34\x24"; # Copy the rsp(pointer value, not address) to the rsi(as a integer value).

# while $(rex) is used for first 8 register, the last 8 register use \x49
MOV_rax_r8="$(prefix rax r8 | xd2esc)${MOV_R}$(printEndianValue $(( MOVR + MODRM_REG_rax + r8 )) ${SIZE_8BITS_1BYTE})";
MOV_rax_r9="$(prefix rax r9 | xd2esc)\x89\xc1"; # move the size read to r9
MOV_r8_rdi="$(prefix r8 rdi | xd2esc)\x89\xc7";
MOV_r8_rdx="$(prefix r8 rdx | xd2esc)\x89$(printEndianValue $(( MOVR + MODRM_REG_r8 + rdx )) ${SIZE_8BITS_1BYTE})";
MOV_r9_rdi="$(prefix r9 rdi | xd2esc)\x89$(printEndianValue $(( MOVR + MODRM_REG_r9 + rdi )) ${SIZE_8BITS_1BYTE})";
MOV_r9_rdx="$(prefix r9 rdx | xd2esc)\x89$(printEndianValue $(( MOVR + MODRM_REG_r9 + rdx )) ${SIZE_8BITS_1BYTE})";
MOV_V8_r8="$(prefix v8 r8 | xd2esc)\xB8";
MOV_V8_r9="$(prefix v8 r9 | xd2esc)\xB9";
MOV_V8_r10="$(prefix v8 r10 | xd2esc)\xBA";

# XOR is useful to set zero at registers using less bytes in the instruction
# Here's an table with the bytecodes for XORing each 64-bit register with zero:
# Register	Assembly	Bytecode
# rax	xor rax, rax	48 31 C0
# rbx	xor rbx, rbx	48 31 DB
# rcx	xor rcx, rcx	48 31 C9
# rdx	xor rdx, rdx	48 31 D2
# rsi	xor rsi, rsi	48 31 F6
# rdi	xor rdi, rdi	48 31 FF
# rbp	xor rbp, rbp	48 31 E5
# rsp	xor rsp, rsp	48 31 EC
# r8	xor r8, r8	4D 31 C0
# r9	xor r9, r9	4D 31 C9
# r10	xor r10, r10	4D 31 D2
# r11	xor r11, r11	4D 31 DB
# r12	xor r12, r12	4D 31 E4
# r13	xor r13, r13	4D 31 ED
# r14	xor r14, r14	4D 31 F6
# r15	xor r15, r15	4D 31 FF
xor(){
	local v1="$1";
	local v2="$2";
	local p=$(prefix "$v1" "$v2");
	local c="";
	c="$c$p";
	local xor=31;
	c="$c$xor";
	if is_64bit_register "$v1" && is_64bit_register "$v2"; then
		local modrm=$( px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + ( v1 << 3 ) + v2 )) $SIZE_8BITS_1BYTE);
		c="$c${modrm}";
	fi;
	printf "${c}";
	debug "asm: xor $@; # $c";
}

#MOV_DATA_rax="$(prefix v4 rax | xd2esc)\x0f\xb6\x06"; # movzbq (%rsi), %rax
TEST_rax_rax="$(prefix rax rax | xd2esc)\x85\xc0";
IMUL_rdx_rax="$(prefix rdx rax | xd2esc)\x0f\xaf\xc2";
SHR_V1_rax="$(prefix v1 rax | xd2esc)\xc1\xe8";

#Processor Flags
#
#The x86 processors have a large set of flags that represent the state of the processor, and the conditional jump instructions can key off of them in combination.
#
#CF - carry flag
#    Set on high-order bit carry or borrow; cleared otherwise
#PF - parity flag
#    Set if low-order eight bits of result contain an even number of "1" bits; cleared otherwise
#ZF - zero flags
#    Set if result is zero; cleared otherwise
#SF - sign flag
#    Set equal to high-order bit of result (0 if positive 1 if negative)
#OF - overflow flag
#    Set if result is too large a positive number or too small a negative number (excluding sign bit) to fit in destination operand; cleared otherwise 

SYSCALL="$( printEndianValue $(( 16#050f )) $SIZE_16BITS_2BYTES)"
function syscall(){
	printf 0f05
}
SYS_READ=0;
SYS_WRITE=1;
SYS_OPEN=2;
SYS_CLOSE=3;
SYS_STAT=4;
SYS_FSTAT=5;
SYS_MMAP=9;
SYS_PIPE=22;
SYS_DUP2=33;
SYS_FORK=57;
SYS_EXECVE=59;	# 0x3b
SYS_EXIT=60;	# 0x3c
SYS_WAIT4=61;
SYS_GETEUID=107;

sys_close()
{
	mov $SYS_CLOSE rax;
	syscall;
}

# fstat is same as stat but uses file descriptor as input
# /usr/include/asm-generic/stat.h
# 0x00: st_dev (8 bytes)	// Device.
# 0x08: st_ino (8 bytes)	// File serial number.
# 0x10: st_mode (4 bytes)	// File mode.
# 0x14: st_nlink (4 bytes)	// Link count.
# 0x18: st_uid (4 bytes)	// User ID of the file's owner.
# 0x1c: st_gid (4 bytes)	// Group ID of the file's group.
# 0x20: st_rdev (8 bytes)	// Device number, if device.
# 0x28: __pad1 (8 bytes)	//
# 0x30: st_size (8 bytes)	// Size of the file, in bytes.
# 0x38: st_blksize (4 bytes)	// Optional block size for I/O.
# 0x3c: __pad2 (4 bytes)
# 0x40: st_blocks (8 bytes)	// Number 512-byte blocks allocated.
# 0x48: st_atime (16 bytes)	// Time of last access. - struct timespec (st_atime(8 bytes) + st_atime_nsec(8 bytes)
# 0x58: st_mtim (16 bytes)	// Time of last modififcation. - struct timespec (tv_sec + tv_nsec)
# 0x68: st_ctim (16 bytes)	// Time of last status change. - struct timespec (tv_sec + tv_nsec)
# 0x78: __unused[0] (4 bytes)
# 0x80: __unused[1] (4 bytes)
#
#  1 struct stat {
#  2         unsigned long   st_dev;         /* Device.  */
#  3         unsigned long   st_ino;         /* File serial number.  */
#  4         unsigned int    st_mode;        /* File mode.  */
#  5         unsigned int    st_nlink;       /* Link count.  */
#  6         unsigned int    st_uid;         /* User ID of the file's owner.  */
#  7         unsigned int    st_gid;         /* Group ID of the file's group. */
#  8         unsigned long   st_rdev;        /* Device number, if device.  */
#  9         unsigned long   __pad1;
# 10         long            st_size;        /* Size of file, in bytes.  */
# 11         int             st_blksize;     /* Optimal block size for I/O.  */
# 12         int             __pad2;
# 13         long            st_blocks;      /* Number 512-byte blocks allocated. */
# 14         long            st_atime;       /* Time of last access.  */
# 15         unsigned long   st_atime_nsec;
# 16         long            st_mtime;       /* Time of last modification.  */
# 17         unsigned long   st_mtime_nsec;
# 18         long            st_ctime;       /* Time of last status change.  */
# 19         unsigned long   st_ctime_nsec;
# 20         unsigned int    __unused4;
# 21         unsigned int    __unused5;
# 22 };
# 
sys_fstat()
{
	local stat_addr="$1";
	local fd="$2";
	# rdi: File descriptor number
	if [ "${fd}" != "" ]; then
		mov "$fd" rdi;
	else
		# if no fd providen use rax by default
		mov rax rdi;
		# TODO not sure this is a good idea but we will lost rax so for 
		# now we will save it at r8 too
		mov rax r8;
	fi;
 	# rsi: Pointer to a struct stat (will be filled with file information)
	mov "${stat_addr}" rsi;
	# rax: fstat
	mov $SYS_FSTAT rax;
	syscall;
}

# get_read_size receives a stat address and return the bytecode instructions to recover the length to a target register.
# if no target register is provided it puts the value on the rsi
function get_read_size()
{
	local stat_addr="$1";
	local target_register="$2";
	local code="$({
		local st_size=$((16#30)); # in the stuct stat the offset 0x30 is where we have the file size;
		mov $(( stat_addr + st_size )) rsi;
		mov '(rsi)' rsi;
		cmp rsi 0; # 64bit cmp rsi, 00
	})";
	debug "code get_read_size=[${code}]";
	local default_value_code="$(mov "$PAGESIZE" rsi)";
	local BYTES_TO_JUMP="$(px $(echo -en "${default_value_code}" | xcnt) $SIZE_32BITS_4BYTES)";
	code="${code}${JG}${BYTES_TO_JUMP}";
	code="${code}${default_value_code}";
	# TODO
	#if rsi == 0
	#	rsi = pagesize
	#fi
	#
	#if rsi > 0 align it with the next page size multple
	echo -en "${code}";
}

function getpagesize()
{
	
	mov $((16#3f)) rax;	# sys_uname syscall
	# mov rax, 0x3f        ; sysconf syscall number
	mov $((16#18)) rdi;	# _SC_PAGESIZE parameter
	xor rsi, rsi;		# unused third parameter
	# syscall
	#
	# ; Store the result in the pagesizebuf buffer
	# mov qword [pagesizebuf], rax
	
	CODE="${CODE}${MOV_rdi_ADDR4}$(printEndianValue $((16#18)) $SIZE_32BITS_4BYTES)"; # _SC_PAGESIZE
	syscall;
}

PAGESIZE=$(( 4 * 1024 )); # 4KiB
# map a memory region
#|rax|syscall___________________|rdi______________|rsi________________|rdx________________|r10________________|r8_______________|r9________|
#| 9 |sys_mmap                 |unsigned long   |unsigned long len |int prot          |int flags         |int fd          |long off |
# Returns:
#  rax Memory Address
#  r8 FD
#  r9 Size
function sys_mmap()
{
	local size="$1"; # this is the bytecode to detect and update rsi with the size
	local fd="$2";
	local CODE="";
	# ; Map the memory region
	# mov rdi, 0     ; addr (let kernel choose)
	CODE="${CODE}$(xor rdi rdi)";
	# TODO use fstat to detect the size and implement a logic to align it to page memory
	# When using mmap, the size parameter specified in rsi should be aligned to the page size. 
	# This is because the kernel allocates memory in units of pages, 
	# and trying to mmap a region that is not page-aligned could result in undefined behavior. 
	# To ensure that the size is aligned(I don't know a system call that returns the system page size
	# but the default linux uses 4K. libc provides a function getpagesize() to determine 
	# the page size at runtime) and then round up the size parameter 
	# to the nearest multiple of the page size.
	#    mov rsi, size  ; length
	#
	# recover size
	local mmap_size_code="$size";
	# CODE="${CODE}${MOV_rsi}$(printEndianValue ${mmap_size} ${SIZE_64BITS_8BYTES})";
	#if pagesize > size {
	#	pagesize
	#} else {
	#	(1+(requested size / pagesize)) * pagesize
	#}
	#CODE="${CODE}${MOV_rsi}$(printEndianValue ${PAGESIZE} ${SIZE_64BITS_8BYTES})";
	CODE="${CODE}${mmap_size_code}";

	# Protection flag
	# Value	Constant	Description
	# 0	PROT_NONE	No access
	# 1	PROT_READ	Read access
	# 2	PROT_WRITE	Write access
	# 4	PROT_EXEC	Execute access
	#    mov rdx, 3     ; prot (PROT_READ(1) | PROT_WRITE(2) | PROT_EXEC(4))
	PROT_NONE=0;
	PROT_READ=1;
	PROT_WRITE=2;
	PROT_EXEC=4;
	CODE="${CODE}$(mov $(( PROT_READ + PROT_WRITE )) rdx)";
	# man mmap for valid flags
	#    mov r10, 2    ; flags
	MAP_SHARED=1;
	MAP_PRIVATE=2;
	MAP_SHARED_VALIDATE=3;
	MAP_ANONYMOUS=$((2#00100000));
	CODE="${CODE}$({
		mov $MAP_PRIVATE r10;
		# The file descriptor is expected to be at r8,
		# but for virtual files it will fail with a -19 at rax.
		# 
		if [ "$fd" == "rax" ]; then
			mov rax r8;
		elif [ "$fd" != "" ]; then
			mov $fd r8;
		fi;
		#xor r8 r8;
		#    mov r9, 0     ; offset
		mov 0 r9
		#    mov rax, 9    ; mmap system call number
		mov $SYS_MMAP rax;
		syscall;
		# test rax to detect failure
		cmp rax 0; # 64bit cmp rax, 00
	})";
	# if it fails do mmap with  MAP_ANONYMOUS
	local ANON_MMAP_CODE="$({
		mov $(( MAP_PRIVATE + MAP_ANONYMOUS )) r10;
		mov $SYS_MMAP rax;
		syscall;
		# then we need to read the data to that location
		mov r8 rdi;
		system_call_read "" "rsi"; # TODO not sure the best choice here. We should do it better
		# if rax > 0 jump over this code block
		# rax will be less than zero on failure
		mov rax r9;
		# By default the sys_read will move the memory address from rax to rsi.
		mov rsi rax; # restore rax to return the memory address
	})";
	local BYTES_TO_JUMP="$(px $(echo -en "${ANON_MMAP_CODE}" | xcnt) $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${JG}${BYTES_TO_JUMP}"; # The second byte "85" is the opcode for the JNE instruction. The following four bytes "06 00 00 00" represent the signed 32-bit offset from the current instruction to the target label.
	CODE="${CODE}${ANON_MMAP_CODE}";
	echo -en "${CODE}";
}

# Jump short is the fastest and cheaper way to run some code,
# but it has two limitations:
#  * Address distance should fit one byte;
#  * it has no stack control, so be careful
# returns:
#  base 64 encoded bytecode and exit code comma separated;
#  the exit code can be:
#    -1 error: the target address is outside the range scope ( 1 << 8  == -128 to 127 )
#    0 nothing to do (the current address is the same as the target address)
#    2 the jump short instruction byte count 
function bytecode_jump_short()
{
	local relative=$1;
	local code="";
	if [ ! "$(( (relative >= -128) && (relative <= 127) ))" -eq 1 ]; then
		debug "displacement too big to jump short: $relative";
		return;
	fi;
	# debug jump short relative $relative
	local RADDR_V="$(px "$relative" $SIZE_8BITS_1BYTE )";
	# debug jump short to RADDR_V=[$( echo -n "$RADDR_V" | xxd)]
	code="${code}${JMP_V1}${RADDR_V}";
	echo -n "${code}";
	return
}

jump_relative(){
	local relative=$1;
	local short_jump_response=$(bytecode_jump_short "${relative}")
	if [ "$(echo -n "${short_jump_response}" | xcnt)" -gt 0 ];then
		echo -n "${short_jump_response}";
		return;
	fi;
	#bytecode_jump_near
	if [ "$(( (relative >= - ( 1 << 31 )) && (relative <= ( 1 << 31 ) -1) ))" -eq 1 ]; then
		# jump near
		local RADDR_V="$(px "${relative}" $SIZE_32BITS_4BYTES)";
		# debug "jump near relative ( $relative, $RADDR_V )";
		CODE="${CODE}${JMP_V4}${RADDR_V}";
		echo -en "${CODE}";
		return;
	fi;

	error "JMP not implemented for that relative or absolute value: $relative"
	# TODO, another way to move to a location is set the RIP directly
	# something like
	# mov eax, $address
	# mov [rsp], eax
	# mov eip, [rsp]
	return;
}

# jump should receive the target address and the current BIP.
#   It will select the correct approach for each context based on the JMP alternatives
function jump()
{
	local TARGET_ADDR="$1";
	local CURRENT_ADDR="$2";
	local relative=$(( TARGET_ADDR - CURRENT_ADDR ))
	# debug "jump: TARGET_ADDR:[$(printf %x $TARGET_ADDR)], CURRENT_ADDR:[$( printf %x ${TARGET_ADDR})]"
	local OPCODE_SIZE=1;
	local DISPLACEMENT_BITS=32; # 4 bytes
	local JUMP_NEAR_SIZE=$(( OPCODE_SIZE + DISPLACEMENT_BITS / 8 )); # 5 bytes
	jump_relative $relative
}


# call procedure
# Intel Ref: Table B-15.
#
# CALL – Call Procedure (in same segment)
#  direct 1110 1000 : displacement32
#  register indirect 0100 WR00w 1111 1111 : 11 010 reg
#  memory indirect 0100 W0XB w 1111 1111 : mod 010 r/m
# CALL – Call Procedure (in other segment)
#  indirect 1111 1111 : mod 011 r/m
#  indirect 0100 10XB 0100 1000 1111 1111 : mod 011 r/m
function call_procedure()
{
	local TARGET="$1";
	local CURRENT="$2";
	local ARGS_TYPE="$3";
	local retval_addr="$4";
	local code="";
	if [ "$ARGS_TYPE" == $SYMBOL_TYPE_ARRAY ]; then
		local array_code="$(xor r15 r15 | xd2esc)";
		array_code="${array_code}$(add 8 r15 | xd2esc)";
		code="${code}${array_code}";
		array_code_size="$(echo -en "$array_code" | wc -c)";
		CURRENT=$((CURRENT + array_code_size)); # append current bytecode size
	fi;
	# call procedure (in same segment)
	# we don't have a short call in x64.
	# direct has a 32bit displacement to receive the near relative address

	# debug "calling: TARGET:[$TARGET], CURRENT:[${CURRENT}]"
	local OPCODE_SIZE=1;
	local DISPLACEMENT_BITS=32; # 4 bytes
	local CALL_NEAR_SIZE=$(( OPCODE_SIZE + DISPLACEMENT_BITS / 8 )); # 5 bytes
	local RELATIVE=$(( TARGET - CURRENT - CALL_NEAR_SIZE ));
	if [ "$(( (RELATIVE >= - ( 1 << ( DISPLACEMENT_BITS -1 ) )) && (RELATIVE <= ( 1 << ( DISPLACEMENT_BITS -1) ) -1) ))" -eq 1 ]; then
		local OPCODE_CALL_NEAR="\xe8"; #direct call with 32bit displacement
		local NEAR_ADDR_V="$(printEndianValue $RELATIVE $SIZE_32BITS_4BYTES)"; # call addr
		local BYTES="${OPCODE_CALL_NEAR}${NEAR_ADDR_V}";
		code="${code}${BYTES}";
		if [ "$retval_addr" != "" ]; then
			code="${code}$({ 
				#mov "(rdi)" rdi;
				mov rdi $retval_addr; 
			} | xd2esc)";
		fi;
		echo -en "$code" | base64 -w0;
		debug "call_procedure $@: $(echo -ne "$code" | base64 -w0)"
		return;
	fi;
	error "call not implemented for this address size: CURRENT: $CURRENT, TARGET: $TARGET, RELATIVE: $RELATIVE";

	FAR_CALL="\x9a";
	MODRM="$(printEndianValue $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + MODRM_OPCODE_SUB + rsp )) $SIZE_8BITS_1BYTE)";
	addr="$(( 16#000100b8 ))"
	BYTES="\xe8${CALL_ADDR}";
	code="${code}${BYTES}";
	if [ "$retval_addr" != "" ]; then
		#code="${code}$(mov "(rdi)" rdi| xd2esc)";
		code="${code}$(mov rdi $retval_addr | xd2esc)";
	fi;
	echo -en "$code" | base64 -w0;
	debug "call_procedure $@:: $code"
}

function push_v_stack()
{
	local value="$1";
	mov "${value}" rax;
	push rax;
}

function push_stack()
{
	# PUSHA/PUSHAD – Push All General Registers 0110 0000
	
	local PUSH="\x68";
	local ADDR_V="$(printEndianValue )";
	echo -n "${PUSH}${ADDR_V}";
}

function ret()
{
	local symbol_value="$1";
	local symbol_type="$2";
	# Types for return
	# Near return (same segment)
	local NEAR_RET="c3";
	local NEAR_RET_WITH_VALUE="c2"; #pop imm16 bytes from stack
	# Far return (inter segment)
	local FAR_RET="cb";
	local FAR_RET_WITH_VALUE="ca"; #pop imm16 bytes from stack
	# Inter-privilege-level far return

	# currently just need the near return
	# 

	#local LEAVE="\xc9"; #seems leave breaks in a segfault
	if [ "$symbol_value" != "" ]; then
		mov ${symbol_value:=0} rdi;
		if [ "$symbol_type" != $SYMBOL_TYPE_HARD_CODED ]; then
			mov "(rdi)" rdi;
		fi;
	fi;
	# run RET
	printf "${NEAR_RET}";
}

function pop_stack()
{
	# POPA/POPAD – Pop All General Registers 0110 0001
	:
}


function system_call_open()
{
	local filename="$1"
	# mov rax, 2 ; System call for open()
	mov $SYS_OPEN rax
	# mov rdi, filename ; File name
	mov ${filename} rdi;
	# TODO best to use xor when setting rsi to 0
	# mov rsi, 'r' ; Open mode
	#mov $(( 16#72 )) rsi; # mode=r (x72)
	mov 0 rsi;
	# xor rdx, rdx; #  File permissions (ignored when opening)
	syscall;
}

# We have real files and virtual files.

# Steps reading the file
# - open the file
#    When reading a file we need to open the file, getting a file descritor
# - Stat to detect the filesize
#    To read we need to know the size. Some files as virtual fs in /proc and pipes don't
#    allows stat to get the full file size, so for those the best way is to read 4k blocks
#    for others is better to detect the size with stat then do a single read or mmap.
# - read the contents
#    mmap will create a new memory page but read need to have a writable memory section
#    mmap will fail on streams like pipes or /proc virtual filesystems
function read_file()
{
	local TYPE="$1"
	local stat_addr="$2";
	local targetMemory="$3";
	local DATA_LEN="$4";
	if [ "$stat_addr" != "" ]; then
		DATA_LEN="$(get_read_size "${stat_addr}")";
	fi;
	debug DATA_LEN="$DATA_LEN"
	local CODE="";
	# DATA_LEN should be the size(in bytes) we want to write out.
	# We need to stat the file to get the real value
	# Memory address of the stat structure
	# debug read_file 
	if [ "${TYPE}" == "${SYMBOL_TYPE_STATIC}" -o "${TYPE}" == "${SYMBOL_TYPE_HARD_CODED}" ]; then
	{
		# do we have a buffer to read into? should we use it in a mmap?
		# now we create a buffer with mmap using this fd in rax.
		CODE="${CODE}$(sys_mmap "${DATA_LEN}")";
		CODE="${CODE}$(mov rax "$targetMemory")";
		# TODO test sys_mmap return at rax, and if fails(<0) then mmap without the fd
		# TODO once mmap set, if the source file is read only we can just close it.
		# then the fd should be at eax and r8
		#
		# TODO:
		# collect $rax (memory location returned from mmap)
		# use it as argument to write out.
		echo -en "${CODE}" | xd2b64;
		return;
	}
	elif [ "${TYPE}" == ${SYMBOL_TYPE_DYNAMIC} ]; then
	{
		if [ "$(echo -n "${DATA_ADDR_V}" | base64 -d | cut -d, -f1 | base64 -w0)" == "$( echo -n ${ARCH_CONST_ARGUMENT_ADDRESS} | base64 -w0)" ]; then
		{
			# now we create a buffer with mmap using this fd in rax.
			CODE="${CODE}$(sys_mmap | xd2esc)";
			# collect $rax (memory location returned from mmap)
			# use it as argument to write out.
			CODE="$(mov rax "$targetMemory" | xd2esc)";
			CODE="${CODE}${MOV_rax_rsi}";
			CODE="${CODE}${MOV_V8_rax}$(printEndianValue $SYS_WRITE $SIZE_64BITS_8BYTES)";
			STDOUT=1;
			CODE="${CODE}${MOV_V8_rdi}$(printEndianValue $STDOUT $SIZE_64BITS_8BYTES)";
			CODE="${CODE}${MOV_V8_rdx}$(printEndianValue "${DATA_LEN}" $SIZE_64BITS_8BYTES)";
			CODE="${CODE}${SYSCALL}";
			echo -en "${CODE}" | base64 -w0;
		}
		else
		{
			# otherwise we expect all instruction already be in the data_addr_v as base64
			# so just throw it back
			echo -n "$DATA_ADDR_V";
		}
		fi;
		return;
	}
	fi
	error "b Not Implemented path type[$TYPE], DATA_ADDR_V=[$DATA_ADDR_V]";
	return;
}

function system_call_read()
{
	local fd=$1;
	local len="$2";
	local data_addr="$3";
	# by default expect the rdi already have the fd
	if [ "$fd" != "" ]; then
		mov $fd rdi;
	fi
	if [ "$len" == "rsi" ]; then
		mov rsi rdx;
	else
		mov $len rdx;
	fi;
	if [ "$DATA_ADDR" == "" ]; then
		#use rax
		mov rax rsi;
	else
		mov $data_addr rsi;
	fi;
	mov $SYS_READ rax;
	syscall;
}

# given a data address as argument, write it to stdout
function system_call_write_addr()
{
	local out="$1";
	local data_addr_v="$2";
	local data_len="$3";
	mov $SYS_WRITE rax;
	mov "$out" rdi;
	mov "${data_addr_v}" rsi;
	mov "${data_len}" rdx;
	syscall;
}

function detect_argsize()
{
	r_in=rsi;
	r_out=rdx;
	# figure out the data size dynamically.
	# To do it we can get the next address - the current address
	# the arg2 - arg1 address - 1(NULL) should be the data size
	# The last argument need to check the size by using 16 bytes, not 8.
	#   because 8 bytes lead to the NULL, 16 leads to the first env var.
	#
	# to find the arg size, use rdx as rsi
	mov $r_in $r_out;
	# increment rdx by 8
	ARGUMENT_DISPLACEMENT=8
	add $ARGUMENT_DISPLACEMENT $r_out;
	# mov to the real address (not pointer to address)
	mov "($r_out)" $r_out; # resolve pointer to address
	cmp $r_out 0;
	# if rdx is zero, then we the input is the last argument and we are unable to detect size using method;
	# so fallback to string size detection
	push $r_in
	detect_string_length $r_in $r_out
	pop $r_in
	mov "($r_in)" $r_in; # resolve pointer to address
	# and subtract rdx - rsi (resulting in the result(str len) at rdx)
	sub $r_out $r_in;
}

get_8bit_reg(){
	local r="$1";
	printf ${r_8bl[$((r))]};
}

# how dinamically discover the size?
# one way is to increment the pointer, then subtract the previous pointer, this is fast but this is only garanteed to work in arrays of data, where the address are in same memory block. see detect_argsize
# another way is to count the bytes until find \x00. but this will block the possibility of write out the \x00 byte. this is what code does. despite slower and the side effect of not allowing \x00, it is safer.
function detect_string_length()
{
	local r_in="$1";
	r_in=${r_in:=rsi};
	local r_out="$2";
	r_out=${r_out:=rdx};
	local r_tmp_64="$3";
	r_tmp_64=${r_tmp_64:=rax};
	r_tmp=$(get_8bit_reg $r_tmp_64);
	# xor rdx rdx; # ensure rdx = 0
	#mov "(rsi)" rsi;
	# we expect the rsi having the address of the string
	mov "${r_in}" "${r_out}"; # let's use rdx as rsi incrementing it each loop interaction
	# save rip
	# leaq (%rip), %rbx # 
	# LEAQ_RIP_rbx;
	# get the data byte at addr+rdx into rax
	# todo ? USE MOVSB ?
	mov "(${r_out})" $r_tmp_64; # resolve current rdx pointer to rax (al)
	#code="${code}${MOV_DATA_rax}";
	# inc rdx
	inc ${r_out};
	# test data byte
	test ${r_tmp}
	# loop back if not null
	# jnz
	# "ebfe" # jump back 0 bytes
	JUMP_BACK_BYTES="7ff5"; # jg .-7; Jump back 9 bytes (to mov (rdx) rax) only if AL > 0 (f5 == -11, includes the 2 bytes jmp instr)
	printf "${JUMP_BACK_BYTES}";
	dec "${r_out}";
	# sub %rsi, %rdx
	sub ${r_in} ${r_out};
	#JMP_rbx="ff23";
}

# given a dynamic address, write it to OUT;
# if len=0, autodetect by null char;
function system_call_write_dyn_addr()
{
	local out="$1";
	local data_addr_v="$2";
	local data_len="$3";
	# otherwise we expect all instruction already be in the data_addr_v as base64
	if [ "$data_addr_v" == "rax" ]; then
		mov rax rsi;
	else
		mov "($data_addr_v)" rsi;
	fi
	if [ "${data_len}" == "0" ]; then
		detect_string_length rsi rdx rax;
	else
		mov $data_len rdx;
	fi;
	mov $out rdi;
	mov $SYS_WRITE rax;
	syscall;
}

function system_call_write()
{
	local type="$1";
	local OUT="$2";
	local DATA_ADDR_V="$3";
	local DATA_LEN="$4";
	local CURRENT_RIP="$5";

	debug "system_call_write: type is $1; out is $OUT"
	if [ "${type}" == "${SYMBOL_TYPE_STATIC}" ]; then
		system_call_write_addr "${OUT}" "${DATA_ADDR_V}" "${DATA_LEN}";
	elif [ "${type}" == "${SYMBOL_TYPE_HARD_CODED}" ]; then
	{
		push_v_stack "${DATA_ADDR_V}";
		mov $SYS_WRITE rax;
		mov $OUT rdi;
		mov rsp rsi;
		mov 8 rdx;
		syscall;
		pop rax;
	}
	elif [ "${type}" == "${SYMBOL_TYPE_DYNAMIC}" ]; then
	{
		system_call_write_dyn_addr "${OUT}" "${DATA_ADDR_V}" "${DATA_LEN}";
	}
	elif [ "$type" == "${SYMBOL_TYPE_PROCEDURE}" ]; then
	{
		call_procedure ${DATA_ADDR_V} ${CURRENT_RIP} | b64xd;
		mov $SYS_WRITE rax;
		mov r9 rdx;
		mov $OUT rdi;
		syscall;
	}
	else
		error "a Not Implemented path type[$type], DATA_ADDR_V=[$DATA_ADDR_V]"
	fi;
	return
}

function system_call_exit()
{
	local exit_code="$1"
	local symbol_type="$2";
	local code="";
	code="${code}$(mov $SYS_EXIT rax)";
	code="${code}$(mov ${exit_code:=0} rdi)";
	if [ "$symbol_type" != $SYMBOL_TYPE_HARD_CODED ]; then
		code="${code}$(mov "(rdi)" rdi)";
	fi;
	code="${code}$(syscall)"
	echo -n "${code}" | xdr | base64 -w0;
}

function system_call_fork()
{
	mov $SYS_FORK rax;
	syscall;
}

function system_call_pipe()
{
	local pipe_addr="$1";
	mov "${SYS_PIPE}" rax;
	mov "${pipe_addr}" rdi;
	syscall;
}

function system_call_wait4()
{
	mov ${SYS_WAIT4} rax;
	# printEndianValue seems buggy with negative values
	# wait_code="${wait_code}${MOV_V4_rdi}$(printEndianValue -1 ${SIZE_32BITS_4BYTES}) ";# pid_t pid
	# so lets change to decrement rdi
	xor rdi rdi;
	dec rdi;
	xor rsi rsi; # int __user *stat_addr
	xor rdx rdx; # int options
	xor r10 r10; # struct rusage
	syscall;
}

function system_call_dup2()
{
	local old_fd_addr="$1"; # where in memory we have the int value of the fd
	local new_fd="$2";
	mov "${SYS_DUP2}" rax;
	mov "${old_fd_addr}" rdi;
	mov "(rdi)" rdi;
	mov "${new_fd}" rsi;
	syscall;
}

function system_call_exec()
{
	#TODO we need to map some memory, or use a mapped memory space to store the arrays bytes;
	local PTR_ARGS="$1";
	local args=();
	eval "args=( $2 )";
	local static_map=( );
	eval "static_map=( $3 )";
	local PTR_ENV="$4";
	local pipe_addr="$5";
	local pipe_buffer_addr="$6";
	local pipe_buffer_size="$7";
	local code="";
	local stdout=1;
	local dup2_child="";
	local read_pipe="";
	if [ "$pipe_addr" != "" ]; then
		pipe_in="$pipe_addr";
		pipe_out="$((pipe_addr + 4))";
		dup2_child="$(system_call_dup2 "$pipe_out" "$stdout")";
		# read_pipe will run on the parent pid.
		read_pipe="${read_pipe}$({
			mov $SYS_READ rax;
			mov "${pipe_in}" rdi; mov "(edi)" edi; # fd
			mov "${pipe_buffer_addr}" rsi; # buff
			mov rsi "$((pipe_buffer_addr - 8))"; # set the pointer to the buffer allowing concat to work
			mov "${pipe_buffer_size}" rdx; # count
			syscall;
		})";
	fi;

	# set the args array in memory
	local argc=${#args[@]};
	debug "exec args=$argc = [${args[@]}] == [$2]";
	debug "exec staticmap=${#static_map[@]} = [${static_map[@]}] == [$3]";
	local exec_code="$({
		for (( i=0; i<${argc}; i++ ));
		do {
			mov "${args[$i]}" rax;
			if [ "${static_map[$i]}" == 0 ]; then # it's a dynamic command, resolve it
				mov "(rax)" rax;
			fi;
			mov rax "$(( PTR_ARGS + i*8 ))";
		}; done
		xor rax rax;
		mov rax "$(( PTR_ARGS + ${#args[@]} * 8 ))";
		mov ${args[0]} rdi;
		if [ "${static_map[0]}" == 0 ]; then # it's a dynamic command, resolve it
			mov "(rdi)" rdi;
		fi;
		mov ${PTR_ARGS:=0} rsi;
		mov ${PTR_ENV:=0} rdx; # const char *const envp[]
		mov ${SYS_EXECVE} rax; # sys_execve (3b)
		syscall;
	})";
	# end exec code:
	local pipe_code="";
	if [ "$pipe_addr" != "" ]; then
		local pipe_code=$(system_call_pipe "${pipe_addr}");
	fi;
	# start fork code
	local fork_code="$(system_call_fork)";
	# TODO: CMP ? then (0x3d) rAx, lz
	local TWOBYTE_INSTRUCTION_PREFIX="0f"; # The first byte "0F" is the opcode for the two-byte instruction prefix that indicates the following instruction is a conditional jump.
	fork_code="${fork_code}$(cmp rax 0)"; # 64bit cmp rax, 00
	# rax will be zero on child, on parent will be the pid of the forked child
	# so if non zero (on parent) we will jump over the sys_execve code to not run it twice,
	# and because it will exit after run
	CODE_TO_JUMP="$(px "$(echo -en "${dup2_child}${exec_code}"| xcnt)" ${SIZE_32BITS_4BYTES})"; # 45 is the number of byte instructions of the syscall sys_execve (including the MOV (%rdi), %rdi.
	fork_code="${fork_code}${JNE}${CODE_TO_JUMP}"; # The second byte "85" is the opcode for the JNE instruction. The following four bytes "06 00 00 00" represent the signed 32-bit offset from the current instruction to the target label.
	# end fork code
	local wait_code="$(system_call_wait4)";
	debug wait_code="$wait_code";

	code="${pipe_code}${fork_code}${dup2_child}${exec_code}${wait_code}${read_pipe}";
	echo -en "${code}" | xd2b64;
}

# The base pointer integer value is by convention the argc(argument count)
# In x86_64 is the rsp with integer size.
# It can be recovered in gdb by using 
# (gdb) print *((int*)($rsp))
# 
# But given it is a runtime only value, we don't have that value at build time, 
# so we need to create a dynamic ref that can be evaluatet at runtime.
# 
# My strategy is to set the constant _ARG_CNT_ then I can figure out latter that is means "rsp Integer"
# Probably should prefix it with the jump sort instruction to make sure those bytes will not affect
# the program execution. But not a issue now.

function get_arg_count()
{
	# I don't need the bytecode at this point
	# I do need to store the value result form the bytecode to a memory address and set it to a var
	# because in inner functions I will be able to recover it using a variable
	#
	# # TODO HOW TO ALLOCATE A DYNAMIC VARIABLE IN MEMORY?
	# 	This function should receive the variable position (hex) to set 
	# 	This function should copy the pointer value currently set at rsp and copy it to the address
	local addr="$1"; # memory where to put the argc count
	local code="";
	code="${code}$(mov rsp r14)";
	code="${code}$(add r15 r14)"; # this allows set r15 as displacement and use this code in function get args
	code="${code}$(mov "(r14)" r14)";
	code="${code}$(mov "r14" $addr)";
	echo -en "${code}";
}

function get_arg()
{
	local addr="$1";
	local argn="$2";
	# MOV %rsp %rsi
	mov rsp rsi;
	add $(( 8 * (1 + argn) )) rsi; # "1 +" the first 8 bytes are the argc
	add r15 rsi;
	# RESOLVE rsi (Copy pointer address content to rsi)
	# TODO: detect string size:
	push rsi
	push rdx
	#detect_argsize
	pop rdx
	pop rsi
	mov "(rsi)" rsi;
	#detect_string_length rsi rdx; # rdx has the string size
	# if multiple of 8; set it to addr and we are done;
	# modulus8(int, int):
	#        mov    edx, edi
	#        sar     edx, 31
	#        shr     edx, 29
	#        lea     eax, [rdi+rdx]
	#        and     eax, 7
	#        sub     eax, edx
	#        ret
	# if not multiple of 8; we need to pad zeros to align 64 bits;
	# 	otherwise we will have issues with bsr and other number functions on registers
	# TODO: move string to memory:
	# 	because we need to zero higher bits in byte, avoiding further issues with bsr
	# TODO: set me address to the target address
	# MOV rsi addr
	mov rsi "$addr";
}

ARCH_CONST_ARGUMENT_ADDRESS="_ARG_ADDR_ARG_ADDR_";

# concat_symbol_instr set addr to dyn_addr or static
# in the first item(idx=1) r8 will be cleared and the appended size will be add in r8 for each call
concat_symbol_instr(){
	#TODO can be improved to use MOVSQ
	local addr="$1";
	local dyn_addr="$2";
	local size="$3";
	local idx="$4";
	local code="";
	local mmap_size_code="$(mov $(( 4 * 1024 )) rsi)";
	local mmap_code="$(sys_mmap "${mmap_size_code}" | xd2esc)"
	# unable to move addr to addr;
	# so let's mov addr to a reg,
	# then reg to addr;
	if [ "$idx" == 1 ]; then # on first item zero r8 to accum the size
		code="${code}$({
			xor r8 r8;
			push r8;	# create zeroed target space at stack;
			mov rsp $dyn_addr;
		} | xd2esc)";
	fi;
	if [ "$size" -eq -1 ]; then
		code="${code}$({
			mov "(${addr})" rsi; # source addr
			detect_string_length rsi rdx rax; # the return is set at rdx
			mov rdx rcx;
		} | xd2esc)"; # but we need it on rcx because REP decrements it
	elif [ "$size" -eq -2 ]; then # procedure pointer
		code="${code}$({
			mov "($addr)" rsi; # source addr
			# TODO: how to manage to con
			# the return is set at rdx
			mov rdx rcx;
		} | xd2esc)"; # but we need it on rcx because REP decrements it
		echo -en "${code}" | base64 -w0;
		return;
	else
		code="${code}$({
			mov "$addr" rsi; # source addr
			mov $size rcx;
		} | xd2esc)";
	fi;
	code="${code}$(mov rsp rdi | xd2esc)"; # target addr
	#code="${code}${MOV_rax_rdi}";
	code="${code}${ADD_r8_rdi}";
	code="${code}${ADD_rcx_r8}";

	# if addr is 0 allocate some address to it.
	# cmp rdi
	# jg .(alloc mem instr len)
	# alloc mem
	code="${code}${REP}${MOVSB}";
	echo -en "${code}" | base64 -w0;
}

compare()
{
	local a="$1";
	local b="$2";
	local type_a="$3";
	local type_b="$4";
	# types can be hardcoded, static or dynamic
	local code="";
	if [ "${type_a}" == "$SYMBOL_TYPE_HARD_CODED" ]; then
		code="${code}${MOV_V4_rax}$(printEndianValue "$a" "${SIZE_32BITS_4BYTES}")";
	fi;
	if [ "${type_b}" == "$SYMBOL_TYPE_HARD_CODED" ]; then
		code="${code}${MOV_V4_rcx}$(printEndianValue "$b" "${SIZE_32BITS_4BYTES}")";
	fi;
	if [ "${type_a}" == "$SYMBOL_TYPE_STATIC" ]; then
		code="${code}${MOV_V4_rax}$(printEndianValue "$a" "${SIZE_32BITS_4BYTES}")";
	fi;
	if [ "${type_b}" == "$SYMBOL_TYPE_STATIC" ]; then
		code="${code}${MOV_V4_rcx}$(printEndianValue "$b" "${SIZE_32BITS_4BYTES}")";
	fi;
	if [ "${type_a}" == "$SYMBOL_TYPE_DYNAMIC" ]; then
		code="${code}${LEA_V4_rax}$(printEndianValue "$a" "${SIZE_32BITS_4BYTES}")";
		code="${code}$(mov "(rax)" rax | xd2esc)";
	fi;
	if [ "${type_b}" == "$SYMBOL_TYPE_DYNAMIC" ]; then
		code="${code}${LEA_V4_rcx}$(printEndianValue "$b" "${SIZE_32BITS_4BYTES}")";
		code="${code}${MOV_rcx_rcx}";
	fi;
	code="${code}$(cmp rax rcx | xd2esc)";
	echo -en "${code}" | base64 -w0;
}

set_increment()
{
	local addr=$1;
	local value=$2;
	local value_type=$3;
	local code="";
	code="${code}${MOV_V4_rdx}$(printEndianValue "${addr}" "${SIZE_32BITS_4BYTES}")";
	code="${code}${MOV_rdx_rdx}";
	if [ "$value" == 1 ]; then
		code="${code}$(inc rdx | xd2esc)";
	elif [ "$value" -gt -128 -a "$value" -lt 128 ]; then
		code="${code}$(add "${value}" rdx | xd2esc)";
	elif [ "$value_type" == $SYMBOL_TYPE_HARD_CODED ]; then
		code="${code}${ADD_V4_rdx}$(printEndianValue "${value}" "${SIZE_32BITS_4BYTES}")";
	else
		code="${code}$(xor rsi rsi | xd2esc)";
		code="${code}${MOV_V4_rsi}$(printEndianValue "${value}" "${SIZE_32BITS_4BYTES}")";
		code="${code}${MOV_rsi_rsi}";
		code="${code}${ADD_rsi_rdx}";
	fi;
	code="${code}$(mov rdx "$addr" | xd2esc)";
	echo -en "${code}" | base64 -w0;
}

jump_if_equal(){
	local code="";
	local target_offset="$1";
	local current_offset="$2";
	local jump_instr_size=6; # 2 bytes for jz and 4 bytes for addr
	CODE_TO_JUMP="$(printEndianValue "$(( target_offset - current_offset - jump_instr_size ))" ${SIZE_32BITS_4BYTES})";
	code="${code}${JZ}${CODE_TO_JUMP}"; # The second byte is the opcode for the JE instruction. The following four bytes represent the signed 32-bit offset from the current instruction to the target label.
	echo -en "${code}" | base64 -w0;
}

function bind()
{
	# I have found this shell code only and it seems to be a BIND exploit
	# I believe it can be useful to learn how to listen a port:
	local code="";
	code="${code}$(xor rax rax | xd2esc)";
	code="${code}${MOV_rax_rdx}";
	code="${code}${MOV_rax_rsi}";
	code="${code}$(prefix rdi | xd2esc)\x8d\x3d\x04\x00\x00\x00";# lea rdi,[rel 0xb]
	code="${code}$(add ${SYS_EXECVE} al | xd2esc)";
	code="${code}${SYSCALL}";
	code="${code}\x2f\x62\x69\x6e\x2f\x73\x68\x00\xcc\x90\x90\x90";
#  https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.
#
# https://www.exploit-db.com/exploits/41128
#  "$(prefix | xd2esc)\x31\xc0"
#  "$(prefix | xd2esc)\x31\xd2"
#  "$(prefix | xd2esc)\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f"
#  "\x0f\x05"
#  "$(prefix | xd2esc)\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a"
#  "\x0f\x05"
#  "\x5e\x6a\x32\x58"
#  "\x0f\x05"
#  "\x6a\x2b\x58"
#  "\x0f\x05"
#  "$(prefix | xd2esc)\x97\x6a\x03\x5e\xff\xce\xb0\x21"
#  "\x0f\x05"
#  "\x75\xf8\xf7\xe6\x52$(rex)\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53$(rex)\x8d\x3c\x24\xb0\x3b"
#  "\x0f\x05";
  :
}
init_bloc(){
	local code="";
	#code="${code}$(mov 8 r15 | xd2esc)";
	#code="${code}${mov rsp rbp | xd2esc)";
	echo -en "${code}" | base64 -w0;
}
init_prog(){
	init_bloc;
}
end_bloc(){
	pop EBP;
}

array_add(){
	local array_addr="$1";
	local array_size="$2";
	local item_addr="$3";
	local item_type="$4";
	local item_value="$5";
	local code="";
	if [ "$item_addr" == "" ]; then
		push_v_stack $item_value;
	else
		mov "$item_addr" rax;
		push rax;
	fi;
}
array_end(){
	local array_addr="$1";
	local array_size="$2";
	# save the array addr outside the stack(in the main memory)
	mov rsp rax;
	add $(( array_size * 8 -8)) rax;
	mov rax "$array_addr";
	# put the array size in the stack
	push_v_stack $array_size;
}

sys_geteuid(){
	local addr="$1";
	mov $SYS_GETEUID rax;
	syscall;
	mov rax "$addr";
}


div10(){
	local code="";
	# 0xcccccccd is the float value for 0.1;
	# ba cd cc cc cc       	mov   $0xcccccccd,%edx
	local float_by_10="\xcd\xcc\xcc\xcc";
	MOV_V4_EDX="\xba";
	code="${code}${MOV_V4_EDX}${float_by_10}";
	code="${code}$(imul rdx rax | xd2esc)";
	echo -ne "$code" | base64 -w0;
}

mod10(){
	local code="";
	code="${code}$(div10 | b64_2esc)";
	# shr    $0x23,%rax
	code="${code}${SHR_V1_rax}\x23";
	# lea    (%rax,%rax,4),%eax
	code="${code}${LEA_rax_rax_4}";
	# add    %eax,%eax
	code="${code}${ADD_EAX_EAX}";
	echo -en "$code" | base64 -w0;
}

# log do a log operation over a base on rax and put the result in the register passed as arg $2
# the result is float 
log(){
	# CVTSI2SD Convert Signed Integer to Scalar Double Precision Floating-Point
	#F20F2AC6 	cvtsi2sd %esi,%xmm0
	# CVTTSD2SI — Convert With Truncation Scalar Double Precision Floating-Point Value to SignedInteger
	:
	CVTTSD2SI_XMM0_ESI="\xF2\x0F\x2C\xF0";
}


# get the most significant bit index from r1 value and put the result in r2
bsr(){
	local r1="$1";
	local r2="$2";
	local code="";
	local modrm="$MODRM_MOD_NO_EFFECTIVE_ADDRESS";
	if [ "$r1" == "(rax)" ]; then
		modrm="$MODRM_MOD_DISPLACEMENT_REG_POINTER";
	fi
	local rc=$(( modrm + ( ${r2,,} << 3 ) + ( ${r1,,} ) ));
	BSR="$(prefix $r2 $r1)0FBD$(px ${rc} $SIZE_8BITS_1BYTE)";
	code="${code}${BSR}";
	echo -n "$code";
}

# ilog10 returns the integer log base 10 of the value in r1 register.
# 	Step 1: Get the guess value from ilog_guess_map using the bit index(aka ilog2/bsr);
# 	Step 2: Subtract 1 from guess when the value is less than the power value recovered using the guess.
# returns:	integer truncated on rdi
# registers need: 2
# r1: value
# 	input: value to process;
# 	behavior: used to count bits with bsr instruction
# 	output: no change;
# r2: bit count
# 	input: unused;
# 	behavior: is a work register where the bsr will set the bit count
# 	output: will return the count bits of the value
# r3: ilog_guess_map address / integer log base 10
# 	input: address value pointer to to max_bit_val_ilog10
# 	behavior: will be incremented by the number of bits to point at the log10 integer value;
# 		echo "[$(for (( i=0; i<63; i++)); do [ $i -gt 0 ] && echo -n ,; v=$(( 2 ** i )); l=$(echo "scale=1;l($v)/l(10)" | bc -l); l=${l/.*/}; echo -n ${l:=0}; done )]";
#		[0,0,0,0,1,1,1,2,2,2,3,3,3,3,4,4,4,5,5,5,6,6,6,6,7,7,7,8,8,8,9,9,9,9,10,10,10,11,11,11,12,12,12,12,13,13,13,14,14,14,15,15,15,15,16,16,16,17,17,17,18,18,18]
# 	output: log10 integer value at base 10
ilog10_guess_map_size=31;
ilog10(){
	local r1="$1"; # source value register or integer value
	local r2="$2"; # target register to put the bit count
	local guess_map_addr="$3"; # register pointing to address of array_max_bit_val_ilog10 or address value
	local ret_addr="$4";
	local code="";
	local retcode="";
	if [ "$r1" == "" ]; then
		# when called directly act like a function,
		# so the number will be rsp + n, move it to rax where n can be:
		# 	0 = rsp = (return addr)
		# 	8 = 2 ( argc )
		# 	16 = ilog10 addr
		# 	24 = first arg
		# so we want n=24
		code="${code}$(mov rsp rax)";
		code="${code}$(add 24 rax)";
		code="${code}$(mov "(rax)" rax)";
		#code="${code}$(movsb "(rax)" rax)"
		# should be the same as: movsbl 0x18(%rsp), %eax
		# BUT it is not, because mobsb copy string.
		#code="${code}${MOVSBL_V4rsp_EAX}$(printEndianValue 24 $SIZE_8BITS_1BYTE)";
		retcode="$(ret)";
	fi;
	r1="${r1:=rax}";
	r2="${r2:=rdx}";
	# bsr rbx, esi		# count bits into rbx
	code="${code}$(bsr "$r1" "$r2")";
	# movzx   eax, BYTE PTR array_max_bit_val_ilog10[1+rax] # movzx (zero extend, set the byte and fill with zeroes the remaining bits)
	#${MOV_rsi_rcx}$(add 63 rcx | b64_2esc)
	#code="${code}${MOVSBL_V4rsi_ECX}";
	#code="${code}$(add $r2 $r3 | b64_2esc)";
	# 483B04D5 	cmp 0x0(,%rdx,8),%rax
	# 1 0000 0FBE1415 	movsbl 0x010018(,%rdx,),%edx
	#movsbl guess_map_addr(rdx), %edx
	code="${code}${MOVSBL_V4_rdx_EDX}$(px $guess_map_addr $SIZE_32BITS_4BYTES)";
	local power_map_addr=$((guess_map_addr + ilog10_guess_map_size));
	code="${code}${CMP_V4_rdx_8_rax}$(px $power_map_addr $SIZE_32BITS_4BYTES)";
	code="${code}${SBB_0_EDX}";
	if [ "$ret_addr" != "" ]; then
		#code="${code}${MOV_rsi_rsi}";
		#1 0000 480FB6FA 	movzx %dl,%rdi
		code="${code}${MOVZX_DL_rdi}";
		#code="${code}$(mov rsi $ret_addr | xd2esc)";
	fi;
	echo -en "${code}${retcode}";
}

# s2i string to integer
# given a string address convert it to integer
s2i(){
	local reg_str_addr="rax";
	local reg_str_8="al";
	local reg_tmp_s="rsi";
	local reg_tmp_s8="sil";
	local reg_int_addr="rdi";
	local reg_tmp_i="rcx";
	local reg_tmp_i8="cl";
	local c="";
	local init=""
	# tmp code start
	#
	init="${init}$(mov rsp $reg_str_addr)";
	init="${init}$(add 24 $reg_str_addr)";
	init="${init}$(mov "(${reg_str_addr})" $reg_str_addr)";	# load the first 8 bytes at the tmp register
	init="${init}$(mov "(${reg_str_addr})" $reg_str_addr)";	# load the first 8 bytes at the tmp register
	init="${init}$(mov "(${reg_str_addr})" $reg_str_addr)";	# load the first 8 bytes at the tmp register
	#
	# tmp code end
	init="${init}$(xor $reg_tmp_i $reg_tmp_i)";	# clean up target int reg
	init="${init}$(xor $reg_tmp_s $reg_tmp_s)";	# clean up target int reg
	local loop="";
	loop="${loop}$(mov ${reg_str_8} $reg_tmp_s8)";	# load the first 8 bytes at the tmp register
	loop="${loop}$(cmp $reg_str_8 0)";
	local r="";
	r="${r}$(sub 48 $reg_tmp_s8)";		# convert to int
	r="${r}$(imul 10 $reg_tmp_i)";		# multiply target by 10;
	r="${r}$(add $reg_tmp_s $reg_tmp_i)";	# add to target int
	r="${r}$(shrq 8 $reg_str_addr)";		# get next byte
	local ss=$(( $(echo $loop$r | xcnt) +4 )); # TODO: why +4 ?
	r="${r}$(jmp $(( - ss)))";	# jump back to loop start
	local rs=$(echo -n "$r"| xcnt);
	loop="${loop}$(jz $rs)"; 		# if found null the string is over;
	loop="${loop}${r}";
	local done="";
	done="${done}$(mov $reg_tmp_i rdi)";	# record the value at target address
	#
	# this should work only for 8 bytes string, more than 8 needs another logic;
	#
	code="${code}${init}";
	code="${code}${loop}";
	code="${code}${done}";
	code="${code}$(ret)";
	echo -n ${code};

	return;

	# if the string is not aligned with 8 bytes,
	# 	then we need to ensure it is zero on higher bits in last string byte;
	#
	# 	how to know if the string is less than 8 bytes?
	# 		check for byte "00"; we can:
	c="${c}$(mov rax rdi)";	# mov %rax, %rdi;	# backup the value in another register;
	local c1="";
	c1="${c1}$(cmp dil 0)";		# cmp %dil, 0;		# check low 8 bits for 0x00;
	local c2="";
	c2="${c2}$(shrq 8 rdi)"; # - shift right 8 bits
	c2="${c2}$(cmp rcx 7)"; # loop test
	c2="${c2}$(inc rcx)";
	local c2s="$(echo -en "$c2" | xcnt)";
	local jmp_size=2;
	c1="${c1}$(jz $(( c2s + jmp_size )))"; # if true rcx is the strlen
	c1="${c1}${c2}"
	local c1s="$(echo -en "$c1" | xcnt)";
	c="${c}${c1}";
	# rcx should be < 8 if small string;
	c="${c}$(jmp $(( - c1s - jmp_size )))";
	c="${c}$(mov "(rax)" rax)";
	c="${c}$(shlq 3 cl)"; # mov 3 bits left == multiply per 8;
	c="${c}$(mov 64 dl)";
	c="${c}$(sub cl dl)";
	c="${c}$(mov dl cl)";
	c="${c}$(shlq cl rax)";
	c="${c}$(shrq cl rax)";
	# 				- shl 64 - %rcx * 8, %rax; # shift left rcx bits on rax;
	# 				- shr 64 - %rcx * 8, %rax; # shift right
	# 			or we can:
	# 				- check the next pointer (rsp+8);
	# 				- subtract it to the current;
	# 				- if < 8:
	# 				- 	use it to shift left
	# 				- 	use it to sift right to zero bits;
	# 				BUT IDK if it is portable or useful for other than start call
	# 	because bsr will fail to detect the correct bit size
	# 	- we can use the next rsp value (+32) to subtract the current (+24) and find it out
	# 	- then we can test and 
	# 	- if less than 8bytes, 
	# 		- clean up (not rsp) with the exceeding bits
	echo -en "$c";
}

# i2s integer to string
# registers:
# rsp: stack changed and restored
# rax: number to convert
# rcx: digit value
# rdx: decrement by power(10, digit) until less than zero
# rdi: used by ilog10; strlen position
# rsi: used by ilog10
i2s(){
	local int_symbol_value="$1";
	local int_symbol_type="$2";
	local str_addr="$3";# return address(stored pointer)
	debug "i2s to store at $(printf 0x%x $str_addr)";
	local ilog10_addr="$4";
	local power10_addr="$5";
	local CURRENT_RIP="$6";
	local init_code="$({
		if [ "$int_symbol_type" == $SYMBOL_TYPE_DYNAMIC ]; then
			mov "${int_symbol_value}" rax;
		elif [ "$int_symbol_type" == $SYMBOL_TYPE_HARD_CODED ]; then
			mov "${int_symbol_value}" rax;
		else
			:
			# expect to have the value on rax already;
		fi;
		mov rsp rax;
		add 24 rax;
		mov "(rax)" rax;
		mov "(rax)" rax;
		cmp rax 0;
		local return_if_zero="$({
			add 48 rax; # 0x30
			mov al "$str_addr";
			mov "$str_addr" rdi;
			ret;
		})";
		local displacement=$(echo -n "$return_if_zero" | xcnt);
		jg $displacement;
		printf "${return_if_zero}";
	})";
	printf "${init_code}";
	# now rax has the int value
	local ilog10_skip_stack=10; # expected to skip first part of ilog10 code, so it will not try to recover the value from stack. This will break at any change on ilog10 begin code
	local init_codesize=$(echo -n "${init_code}" | xcnt);
	local displacement=$(( CURRENT_RIP + init_codesize -ilog10_skip_stack ));
	call_procedure ${ilog10_addr} ${displacement} | b64xd;
	# at this point rdx == 3 (log 10 (n))
	# rax is the value (0x3e8==1000)
	# rdx is the remaining digit count(base 10) from ilog10
	# rdi is the digit count (base 10) (used to select the memory target to put the digit om str_addr)
	# rcx is the digit asc value
	xor rdi rdi;
	#for_init_code=$({});
	#for_cond_code=$({ asc_digit_count < ilog10_v });
	#for_code="$for_init_code; $for_cond_code; $for_impl_code; $for_step_code";

	# The loop repeats while rax > 0 
	# the loop substract from rax the value of the power10 ** rdx
	local codepart2="$({
		xor rcx rcx; # clean up digit asc value each interaction
		local dec_power_code="$({
			# This will run at bottom
			printf "${SUB_ADDR4_rax_rax}$(px $power10_addr $SIZE_32BITS_4BYTES)";
			inc rcx;
		})";
		local loopcode="$({
			# cmp %rax, $power10_addr(,%rdx,8);
			printf "${CMP_rax_ADDR4_rdx_8}$(px "$power10_addr" $SIZE_32BITS_4BYTES)";
			local append_asc_digit="$({
				add $(printf %d \'0) rcx; # add the zero asc value (0x30)
				printf "${MOV_CL_ADDR4_rdi}$(px $str_addr $SIZE_32BITS_4BYTES)"; # append the rcx low byte to str addr
				inc rdi;
				#rdx=$((rdx-1));
				dec rdx;
				# $rdx -lt 0 ] && break;
				cmp rdx 0;
			})";
			local parse_next_digit="$({
				local dec_power_codesize=$(echo -en "${dec_power_code}"| xcnt);
				local xor_size=3;
				local cmp_size=9; # size of cmp rax power_10_addr+rdx*8
				local jng_size=2; # size of jmp before this code;
				printf "${JGE_V1}$(px $(( 0 - $(xcnt <<<"$append_asc_digit") - xor_size - cmp_size - jng_size -1 )) $SIZE_8BITS_1BYTE)"; # TODO: why -1 ?
				local jmpv1_size=2; # it is not in dec_power_code yet because it depends on this block size
				printf "${JMP_V1}$(px $(( dec_power_codesize + jmpv1_size)) $SIZE_8BITS_1BYTE)";
				# continue; # jump back to "xor %rcx, %rcx"
			})";
			jmpsize=$(xcnt <<<"${append_asc_digit}${parse_next_digit}");
			printf "${JNG_V1}$(px ${jmpsize} $SIZE_8BITS_1BYTE)"; # if rax <= power10[rdx] then (quit loop) (goto after_loop)
			printf "${append_asc_digit}";
			printf "${parse_next_digit}"
		})";
		# jg loopcode
		printf "${loopcode}";
		# fix the stack
		# sub power10(rax), rax
		printf "${dec_power_code}";
	})";
	printf "${codepart2}";
	# jmp back
	printf "${JMP_V1}$(px $(( - $(xcnt <<<"${codepart2}") +1 )) $SIZE_8BITS_1BYTE )"; # TODO: why +1 ?
	# code "after_loop"
	# TODO code="${code}${MOV_v0_ADDR4_rdi}$(printEndianValue $str_addr $SIZE_32BITS_4BYTES)"; # append the 00 to close the string
	mov $str_addr rdi;
	ret;
}
