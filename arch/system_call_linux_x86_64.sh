#!/bin/bash
#
# Here should be all x86_64 specific code.
#

. arch/system_call_linux_x86.sh

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
# 8bit(high,low)	16bits	32bits	64bits	bitval
ah=0;	al=0;		ax=0;	eax=0;	rax=0;	# 000
ch=0;	cl=1;		cx=1;	ecx=1;	rcx=1;	# 001	special because `rep` and others? uses it
dh=0;	dl=2;		dx=2;	edx=2;	rdx=2;	# 010
bh=0;	bl=3;		bx=3;	ebx=3;	rbx=3;	# 011
spl=4;	sp=4;	esp=4;	rsp=4;	# 100	processor controlled pointing to stack pointer
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
#		eip	rip		instruction pointer: address of the next instruction to execute.
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
#  |7|6|5|4|3|2|1|0|
#  |0|1|0|0|W|R|X|B|
#  W bit = Operand size 1==64-bits, 0 == legacy, Operand size determined by CS.D (Code Segment)
#  R bit = Extends the ModR/M reg field to 4 bits. 0 selects rax-rsi, 1 selects r8-r15
#  X bit = extends SIB 'index' field, same as R but for the SIB byte (memory operand)
#  B bit = extends the ModR/M r/m or 'base' field or the SIB field
#
rex(){
	debug "rex $@"
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
	local v=$(printf "%02x" $(( (2#0100 << 4) + (W<<3) + (R<<2) + (X<<1) + B )) );
	code=$(echo -ne $v | xxd --ps -r | base64 -w0);
	echo -ne "$code";
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
	local code="";
	if is_64bit_register "$1" || is_64bit_register "$2" || is_8bit_extended_register "$1"; then
		code="${code}$(rex "$v1" "$v2" | b64_to_hex_dump)";
	fi;
	if is_16bit_register "$1" || is_16bit_register "$2"; then
		local osize="\x66";
		code="${code}${osize}";
	fi
	echo -en "$code" | base64 -w0;
}

	#    $(( (2#0100 << 4) + (1 << 3) +  ( target_is_64bit_extended_register << 2 ) + ( 0 << 1) + ( source_is_64bit_extended_register ) ))
# SIB byte
#  SIB stands for: Scale Index Base
#  The x64 the ModR/M can not handle all register/memory combinations
#  for example when you try to move the rsp to an memory address,
#  the rsp(100) is set to require an additional field the SIB is this additional field

#In the opcode "48 89 C6", the byte C6 is actually the ModR/M byte, which is divided into three fields:
#
#  The ModR/M's mod field indicates the addressing mode.
#    The first 2 bits (11) indicate the addressing mode.  In this case, 11 represents the register addressing mode. It means the instruction operates on registers directly, rather than accessing memory.
#       Check the constants MODRM_MOD_DISPLACEMENT_* below to see the domain
#    The next 3 bits (110) specify the destination register (which in this case is rsi).
#    The last 3 bits (000) specify the source register (which in this case is rax).
#
# So, in summary, the ModR/M byte in the opcode "48 89 C6" indicates that we are using a register-to-register move instruction, with rsi as the destination register and rax as the source register.
# MOV_rsp_rsi="$(prefix rsp rsi | b64_to_hex_dump)${MOV_R}\x$( printf %x $(( MOVR + (rsi << 3) + rsp )) )"; # move the rsp to rsi #11000110
# MOV__rsp__rsi="$(prefix "(rsp)" rsi| b64_to_hex_dump)\x8b\x34\x24"; # mov (%rsp), %rsp; # move value resolving pointer
# show_bytecode "MOV %rsi, (%rsp)"
#48893424
# show_bytecode "MOV %rsi, %rsp"
#4889f4

function push(){
	local reg="$1";
	local b2=$(( 16#50 + reg ));
	if is_64bit_extended_register "$reg"; then
		b1="$((16#41))";
		printf "%02x%02x" "${b1}" "${b2}" | xxd --ps -r | base64 -w0;
	else
		printf "%02x" "${b2}" | xxd --ps -r | base64 -w0;
	fi;
}
function pop(){
	local reg="$1";
	local b2=$(( 16#58 + reg ));
	if [[ "$reg" =~ R([8-9]|1[0-5]) ]]; then
		b1="$((16#41))";
		printf "%02x%02x" "${b1}" "${b2}" | xxd --ps -r | base64 -w0;
	else
		printf "%02x" "${b2}" | xxd --ps -r | base64 -w0;
	fi;
}
MODRM_MOD_DISPLACEMENT_REG_POINTER=$(( 0 << 6 ));	# If mod is 00, no displacement follows the ModR/M byte, and the operand is IN a register (like a pointer). The operation will use the address in a register. This is used with SIB for 64bit displacements
MODRM_MOD_DISPLACEMENT_8=$((   1 << 6 ));	# If mod is 01, a displacement of 8 bits follows the ModR/M byte.
MODRM_MOD_DISPLACEMENT_32=$((  2 << 6 ));	# If mod is 10, a displacement of 32 bits follows the ModR/M byte.
MODRM_MOD_DISPLACEMENT_REG=$(( 3 << 6 ));	# If mod is 11, the operand is a register, and there is no displacement. The operation will use the register itself.
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
MOVR="$(( MODRM_MOD_DISPLACEMENT_REG ))";	# \xc0 move between registers

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
SUB_rsp_SHORT="$(prefix v1 rsp| b64_to_hex_dump)\x83\xec"; # Subtract 1 byte(two complement) value from rsp
TEST="\x85"; # 10000101
IMM="$(( 2#00111000 ))";
MOV_8BIT="\x88";
#MOV="\x89";
MOV_RESOLVE_ADDRESS="\x8b"; # Replace the address pointer with the value pointed from that address
mov(){
	local v1="$1";
	local v2="$2";
	local modrm="";
	local code="";
	code="${code}$(prefix "$v1" "$v2" | b64_to_hex_dump)";
	if is_valid_number "$v1"; then
		local mov_v4_reg="\xc7";
		local mod_reg=0;
		modrm="$(printEndianValue "$(( MODRM_MOD_DISPLACEMENT_REG + mod_reg + v2 ))" $SIZE_8BITS_1BYTE)";
		code="${code}${mov_v4_reg}${modrm}$(printEndianValue "$v1" $SIZE_32BITS_4BYTES)";
	fi;
	if [[ "$v1" =~ ^\(.*\)$ ]]; then	# resolve pointer address value
		local v1_r=$( echo $v1 | tr -d '()' );
		code="${code}${MOV_RESOLVE_ADDRESS}";
		if is_register "$v1_r"; then
			local mod_reg=$(( v2 << 3 )); # 000 0
			if is_register "$v2"; then
				modrm="$(printEndianValue "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + mod_reg + v1_r ))" $SIZE_8BITS_1BYTE)";
			fi;
		fi;
		code="${code}${modrm}";
	fi;
	if is_64bit_register "$v1"; then
		code="${code}\x89";
		local mod_reg=$(( v1 << 3 ));
		if is_register "$v2"; then
			modrm="$(printEndianValue "$(( MODRM_MOD_DISPLACEMENT_REG + mod_reg + v2 ))" $SIZE_8BITS_1BYTE)";
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
			MOD_RM="$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG_POINTER + mod_reg + sib )) ${SIZE_8BITS_1BYTE} )";
			SIB=$(printEndianValue $(( 2#00100101 )) ${SIZE_8BITS_1BYTE});
			local v="$(printEndianValue "$v2" $SIZE_32BITS_4BYTES)";
			code="${code}${INSTR_MOV}${MOD_RM}${SIB}${v}";
		else
			error not implemented
		fi;
		code="${code}${modrm}";
	fi;
	if is_8bit_register "$v1"; then
		mov_8bit="\x88";
		code="${code}${mov_8bit}";
	fi;
	out=$(echo -en "${code}" | base64 -w0);
	debug mov $@: out [$out];
	echo -n $out;
}
cmp(){
	debug cmp $@
	local v1="$1";
	local v2="$2";
	local opcode="";
	local mod_rm="";
	local code="";
	code="${code}$(prefix "$v1" "$v2" | b64_to_hex_dump)";
	if is_8bit_register "$v1"; then
	{
		opcode="\x38";
		if is_8bit_register "$v2"; then
		{
			mod_rm="$(printf '\\x%02x' $((MODRM_MOD_DISPLACEMENT_REG + (v1 << 3) + v2 )))";
			code="${code}${opcode}${mod_rm}";
			echo -en "$code" | base64 -w0;
			return;
		}
		fi;
		if is_valid_number "$v2"; then
		{
			if [ "$v2" -lt 256 ]; then # TODO not sure if 127 or 256
			{
				imm8="$(printf '\\x%02x' "$v2")"; # immediate value with 8 bits
				if [ "$v1" = "al" ]; then
				{
					code="${code}\x3c$(printf '\\x%02x' ${imm8})"; # only valid to %al: cmp %al, imm8;
					echo -en "$code" | base64 -w0;
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
				opcode="$( printf '\\x%02x' $(( 16#f8 + v1 )) )";
				code="${code}\x80${opcode}${imm8}";
				echo -en "$code" | base64 -w0;
				return;
			}
			fi;
			error not implemented or allowed?
		}
		fi;
	}
	fi;
	error not implemented
}
jg(){
	local v="$1";
	local code=""
	code="${code}${JG_V1}";
	code="${code}$(printf '\\x%02x' "$v")";
	echo -en "${code}" | base64 -w0;
}

MOV_AL_ADDR4="\x88\x04\x25";
# LEA - Load Effective Address (page 1146)
#LEAQ_RIP_rbx="$(prefix rip rbx| b64_to_hex_dump)\x8d\x1d\x00\x00\x00\x00";
LEA_rax_rax_4="\x8d\x04\x80";
LEA_V4_rdx="$(prefix v4 rdx | b64_to_hex_dump)\x8d\x14\x25";
LEA_V4_rax="$(prefix v4 rax | b64_to_hex_dump)\x8d\x04\x25";
LEA_V4_rcx="$(prefix v4 rcx | b64_to_hex_dump)\x8d\x0c\x25";
MOV_ADDR4_rdx="$(prefix addr4 rdx | b64_to_hex_dump)\x8b\x14\x25"; # followed by 4 bytes le;
MOV_ADDR4_rax="$(prefix addr4 rax | b64_to_hex_dump)\x8b\x04\x25";
MOV_ADDR4_rsi="$(prefix addr4 rsi | b64_to_hex_dump)\x8b\x34\x25";
MOV_ADDR4_rdi="$(prefix addr4 rdi | b64_to_hex_dump)\x8b\x3c\x25";
MOV_V4_rax="$(prefix v4 rax | b64_to_hex_dump)\xc7\xc0";
MOV_V4_rcx="$(prefix v4 rcx | b64_to_hex_dump)\xc7\xc1";
MOV_V4_rdx="$(prefix v4 rdx | b64_to_hex_dump)\xc7\xc2"; # MOV value and resolve address, so the content of memory address is set at the register
MOV_V4_rsi="$(prefix v4 rsi | b64_to_hex_dump)\xc7\xc6";
MOV_V4_rdi="$(prefix v4 rdi | b64_to_hex_dump)\xc7\xc7";
MOV_V8_rax="$(prefix v8 rax | b64_to_hex_dump)$( printEndianValue $(( MOV + IMM + rax )) ${SIZE_8BITS_1BYTE} )"; # 48 b8
MOV_V8_rdx="$(prefix v8 rdx | b64_to_hex_dump)$( printEndianValue $(( MOV + IMM + rdx )) ${SIZE_8BITS_1BYTE} )"; # 48 ba
MOV_V8_rsi="$(prefix v8 rsi | b64_to_hex_dump)$( printEndianValue $(( MOV + IMM + rsi )) ${SIZE_8BITS_1BYTE} )"; # 48 be
#debug MOV_rsi=$MOV_rsi
MOV_V8_rdi="$(prefix v8 rdi | b64_to_hex_dump)$( printEndianValue $(( MOV + IMM + rdi )) ${SIZE_8BITS_1BYTE} )"; # 48 bf; #if not prepended with rex(x48) expect 32 bit register (edi: 4 bytes)
MOV_CL_ADDR4_rdi="\x88\x8F";
MOV_R="\x89";
MOVSB="\xa4"; # move 64bits(8 bytes) from %rsi addr to %rdi addr
#MOVSQ="$(prefix | b64_to_hex_dump)\xa5"; # move 64bits(8 bytes) from %rsi addr to %rdi addr
XOR_rbx_rbx="\x48\x31\xDB";
CMP_rax_ADDR4_rdx_8="\x48\x39\x04\xD5";
CMP_rbx_ADDR4_rdx_8="\x48\x39\x1C\xD5";
CMP_ADDR4_rdx_8_rbx="\x48\x3B\x1C\xD5";
CMP_V4_rdx_8_rax="\x48\x3B\x04\xD5";
CMP_rax_rcx="$(prefix rax rcx | b64_to_hex_dump)\x39\xc1";
CMP_rax_V4="\x48\x39\x04\x25";
REP="\xf3"; # repeat until rcx
#MOVSBL_V4rsp_EAX="\x0F\xBE\x44\x24";
#MOV_rsi_rcx="\x48\x89\xF1";
#MOVSBL_V4rsi_ECX="\x0F\xBE\x4E$(printEndianValue 63 $SIZE_8BITS_1BYTE)";
#MOVZX_DL_rdx="\x48\x0F\xB6\xD2";
#LEA_rdx_rdx="\x48\x8B\x12";
#MOV_rsi_rsi="\x48\x8B\x36";
#MOVZX_SIL_rsi="\x48\x0F\xB6\xF6";
#MOVZX_SIL_rdi="\x48\x0F\xB6\xFE";
MOVZX_DL_rdi="\x48\x0f\xb6\xfa";
SBB_0_EDX="\x83\xda\x00";
MOVSBL_V4_rdx_EDX="\x0F\xBE\x14\x15";

# show_bytecode "mov %rsp, %rsi"
# 4889e6
MOV_rax_rsi="$(mov rax rsi | b64_to_hex_dump)"; # xC6 move the rax to rsi #11000110
MOV_rax_rdx="$(mov rax rdx | b64_to_hex_dump)";
MOV_rax_rdi="$(mov rax rdi | b64_to_hex_dump)";
MOV_rdx_rcx="$(mov rdx rcx | b64_to_hex_dump)";
#MOV_rsp_rsi="$(prefix rsp rsi | b64_to_hex_dump)${MOV_R}\xe6"; # Copy the rsp(pointer address) to the rsp(as a pointer address).
MOV_rsp_rax="$(mov rsp rax | b64_to_hex_dump)";
MOV_rsp_rsi="$(mov rsp rsi | b64_to_hex_dump)"; # move the rsp to rsi #11000110
MOV_rsp_rdx="$(mov rsp rdx | b64_to_hex_dump)"; # move the rsp to rdx #11000010
MOV_rsp_rdi="$(mov rsp rdi | b64_to_hex_dump)";
MOV_rsi_rax="$(mov rsi rax | b64_to_hex_dump)"; # move the rsi to rdx #11110010
MOV_rsi_rdx="$(mov rsi rdx | b64_to_hex_dump)"; # move the rsi to rdx #11110010
SUB_V1_rax="$(prefix v1 rax | b64_to_hex_dump)\x83\xe8";
SUB_ADDR4_rax_rax="\x48\x2b\x04\xd5";

# add: given a value or a register on r1, add it to r2
# r1: can be a register id, a integer value or a address value
# 	input: register or "[address]" or integer value
# 	output: not changed
# r2: register result of add r1 and r2
# 	input: register
# 	output: added r1 and r2
ADD_FULL="\x81"; # ADD 32 or 64 bit operand (depend on ModR/M
ADD_M64="$(prefix rax | b64_to_hex_dump)${ADD_FULL}";
ADD_M64_rdi="${ADD_M64}";
ADD_EAX_EAX="\x01\xc0";
ADD_rsi_rdx="$(prefix rsi rdx | b64_to_hex_dump)\x01\xF2";
ADD_V4_rdx="$(prefix v4 rdx | b64_to_hex_dump)\x81\xC2";
ADD_V4_rdi="$(prefix v4 rdi | b64_to_hex_dump)\x81\xC7";
ADD_r15_r14="$(prefix r15 r14 | b64_to_hex_dump)\x01\xfe";
ADD_r15_rax="$(prefix r15 rax | b64_to_hex_dump)\x01\xF8";
ADD_r15_rsi="$(prefix r15 rsi | b64_to_hex_dump)\x01\xFE";
ADD_rcx_r8="$(prefix rcx r8 | b64_to_hex_dump)\x01\xc8";
ADD_rdx_r8="$(prefix rdx r8 | b64_to_hex_dump)\x01\xd0";
ADD_r8_rdi="$(prefix r8 rdi | b64_to_hex_dump)\x01\xc7";
add(){
	local ADD_SHORT="\x83"; # ADD 8 or 16 bit operand (depend on ModR/M opcode first bit(most significant (bit 7)) been zero) and the ModR/M opcode
	local r1="$1";
	local r2="$2";
	local code="";
	local p=$(prefix "$r1" "$r2" | b64_to_hex_dump);
	if [ "$r2" = "AL" ]; then
		ADD_AL="\x04";
		code="${code}${ADD_AL}$(printEndianValue "$r1" ${SIZE_8BITS_1BYTE})";
		echo -en "${code}" | base64 -w0;
		return
	fi;
	if is_register "$r1"; then
	{
		if is_register "$r2"; then
		{
			local opadd="${p}\x01";
			local rv=$(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_ADD + (${r1,,} << 3) + ${r2,,} ));
			r=$(printEndianValue $rv $SIZE_8BITS_1BYTE);
			code="${code}${opadd}${r}";
			echo -en "${code}" | base64 -w0;
			return;
		}
		fi;
	}
	elif is_valid_number "$r1"; then
	{
		if is_register "$r2"; then
			if [ $r1 -lt 128 ]; then
				r=$(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_ADD + ${r2,,} ))
				code="${code}${p}${ADD_SHORT}$(printEndianValue $r $SIZE_8BITS_1BYTE)";
				code="${code}$(printEndianValue $r1 $SIZE_8BITS_1BYTE)";
				debug "add $@: $(echo -en "$code" | base64 -w0)"
				echo -en "${code}" | base64 -w0;
				return;
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
inc(){
	local r=$1;
	local p=$(prefix $r | b64_to_hex_dump);
	local inc_op="\xff";
	local reg=$(printEndianValue $((MODRM_MOD_DISPLACEMENT_REG + ${r,,})) $SIZE_8BITS_1BYTE);
	echo -en "${p}${inc_op}${reg}" | base64 -w0;
}

INC_rdx="$(inc rdx | b64_to_hex_dump)";
DEC_rdx="$(prefix rdx| b64_to_hex_dump)\xff\xca";
DEC_rdi="$(prefix rdi| b64_to_hex_dump)\xff\xcf";
MOV_V4_r14="$(prefix v4 r14 | b64_to_hex_dump)\xC7\xC6";
XOR_r15_r15="\x4D\x31\xFF";
MOV_rsp_r14="$(prefix rsp r14 | b64_to_hex_dump)\x89\xe6";
MOV_r14_ADDR4="$(prefix r14 addr4| b64_to_hex_dump)\x89\x34\x25";
# MOV_RESOLVE_ADDRESS needs the ModR/M mod (first 2 bits) to be 00.
MOV_rcx_rcx="$(prefix "(rcx)" rcx | b64_to_hex_dump)\x8b\x09";
MODRM="$(printEndianValue "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_rsi + rsi))" $SIZE_8BITS_1BYTE)";
MOV_rsi_rsi="$(mov "(rsi)" rsi| b64_to_hex_dump)"; # mov (%rsi), %rsi
MODRM="$(printEndianValue "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_rdx + rdx))" $SIZE_8BITS_1BYTE)";
MOV_rdx_rdx="$(prefix "(rdx)" rdx| b64_to_hex_dump)${MOV_RESOLVE_ADDRESS}${MODRM}";
MODRM="$(printEndianValue "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_rdi + rdi))" $SIZE_8BITS_1BYTE)";
MOV_rdi_rdi="$(prefix "(rdi)" rdi| b64_to_hex_dump)${MOV_RESOLVE_ADDRESS}${MODRM}";
MOV_rdi_ADDR4="$(prefix rdi addr4| b64_to_hex_dump)\x89\x3C\x25";

# show_bytecode "movq (%rsp), %rsi"
# 488b3424
# MOV_VALUE_rsi_rsp="$(rex | b64_to_hex_dump)\x8b\x34\x24"; # Copy the rsp(pointer value, not address) to the rsi(as a integer value).

# while $(rex | b64_to_hex_dump) is used for first 8 register, the last 8 register use \x49
MOV_rax_r8="$(prefix rax r8| b64_to_hex_dump)${MOV_R}$(printEndianValue $(( MOVR + MODRM_REG_rax + r8 )) ${SIZE_8BITS_1BYTE})";
MOV_rax_r9="$(prefix rax r9| b64_to_hex_dump)\x89\xc1"; # move the size read to r9
MOV_r8_rdi="$(prefix r8 rdi | b64_to_hex_dump)\x89\xc7";
MOV_r8_rdx="$(prefix r8 rdx | b64_to_hex_dump)\x89$(printEndianValue $(( MOVR + MODRM_REG_r8 + rdx )) ${SIZE_8BITS_1BYTE})";
MOV_r9_rdi="$(prefix r9 rdi | b64_to_hex_dump)\x89$(printEndianValue $(( MOVR + MODRM_REG_r9 + rdi )) ${SIZE_8BITS_1BYTE})";
MOV_r9_rdx="$(prefix r9 rdx | b64_to_hex_dump)\x89$(printEndianValue $(( MOVR + MODRM_REG_r9 + rdx )) ${SIZE_8BITS_1BYTE})";
MOV_V8_r8="$(prefix v8 r8 | b64_to_hex_dump)\xB8";
MOV_V8_r9="$(prefix v8 r9 | b64_to_hex_dump)\xB9";
MOV_V8_r10="$(prefix v8 r10 | b64_to_hex_dump)\xBA";

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
XOR_rax_rax="$(prefix rax rax | b64_to_hex_dump)\x31\xc0";
XOR_rcx_rcx="$(prefix rcx rcx | b64_to_hex_dump)\x31\xC9";
XOR_rdx_rdx="$(prefix rdx rdx | b64_to_hex_dump)\x31\xd2";
XOR_rsi_rsi="$(prefix rsi rsi | b64_to_hex_dump)\x31\xf6";
XOR_rdi_rdi="$(prefix rdi rdi | b64_to_hex_dump)\x31\xff";
XOR_r8_r8="$(prefix r8 r8 | b64_to_hex_dump)\x31\xc0";
XOR_r10_r10="$(prefix r10 r10 | b64_to_hex_dump)\x31\xd2";

# CMP
CMP="\x83"; # only if most significant bit(bit 7) of the next byte is 1 and depending on opcode(bits 6-3) And ModR/M opcode
CMP_rax_V1="$(prefix rax v1 | b64_to_hex_dump)${CMP}$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_CMP + rax )) $SIZE_8BITS_1BYTE)";
CMP_rbx_V1="$(prefix rbx v1 | b64_to_hex_dump)${CMP}$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_CMP + rbx )) $SIZE_8BITS_1BYTE)";
CMP_rdx_V1="$(prefix rdx v1 | b64_to_hex_dump)${CMP}$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_CMP + rdx )) $SIZE_8BITS_1BYTE)";
CMP_rsi_V1="$(prefix rsi v1 | b64_to_hex_dump)${CMP}$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_CMP + rsi )) $SIZE_8BITS_1BYTE)";


SUB_rsp="$(prefix rsp | b64_to_hex_dump)${SUB_IMMSE8}${MODRM}\x28" # sub rsp, x28
SUB_rdx_rsi="$(prefix rdx rsi | b64_to_hex_dump)${SUB_R}${ModRM}";
#MOV_DATA_rax="$(prefix v4 rax | b64_to_hex_dump)\x0f\xb6\x06"; # movzbq (%rsi), %rax
TEST_rax_rax="$(prefix rax rax | b64_to_hex_dump)\x85\xc0";
SUB_rsi_rdx="$(prefix rsi rdx | b64_to_hex_dump)\x29\xf2";
IMUL_rdx_rax="$(prefix rdx rax | b64_to_hex_dump)\x0f\xaf\xc2";
SHR_V1_rax="$(prefix v1 rax | b64_to_hex_dump)\xc1\xe8";

# JMP
# We have some types of jump
# Relative jumps (short and near):
JMP_V1="\xeb"; # followed by a 8-bit signed char (-128 to 127) to move relative to BIP.
JMP_V4="\xe9"; # followed by a 32-bit signed integer(-2147483648 to 2147483647).
# Jump to the full virtual address
JMP_rax="\xff";
JMP_rdi="\xe0";
JNE="\x0f\x85"; # The second byte "85" is the opcode for the JNE(Jump if Not Equal) same of JNZ(Jump if Not Zero) instruction. The following four bytes "06 00 00 00" represent the signed 32-bit offset from the current instruction to the target label.
JZ="\x0f\x84";
JNC_BYTE="\x73"; # jae, jnb and jnc are all the same condition code CF = 0.
JZ_BYTE="\x74"; # follow by a signed byte from FF (-126) to 7f (127)
JNZ_BYTE="\x75";
JNA_BYTE="\x76";
JA_BYTE="\x77"; # CF = 0, ZF = 0
JS_BYTE="\x77";
JL_V1="\x7c";
JG_V1="\x7F";
JGE_V1="\x7D";
JNG_V1="\x7E";
JL_V4="\x0f\x8c";
JGE_V4="\x0f\x8d"; # Jump if greater than or igual to zero flags: SF = OF
JG="\x0F\x8F"; # Jump if Greater than zero; flags: SF = OF, ZF = 0
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
SYS_READ=0;
SYS_WRITE=1;
SYS_OPEN=2;
SYS_CLOSE=3;
SYS_STAT=4;
SYS_FSTAT=5;
SYS_MMAP=9;
SYS_EXECVE=59;	# 0x3b
SYS_EXIT=60;	# 0x3c

sys_close()
{
	CODE="";
	CODE="${CODE}${MOV_V4_rax}$(printEndianValue $SYS_CLOSE ${SIZE_32BITS_4BYTES})";
	CODE="${CODE}${SYSCALL}";
	echo -en "${CODE}" | base64 -w0;
}

# stat get information of a file
sys_stat()
{
	local CODE="";
	local FD="$1";
	if [ "$FD" != "" ]; then
		CODE="${CODE}${MOV_V4_rax}$(printEndianValue $FD ${SIZE_32BITS_4BYTES})";
	else
		# ; we will default to use rax as input. (normally used after a open, so)
		# mov rdi, rax        ; File descriptor returned by the open syscall
		CODE="${CODE}${MOV_rax_rdi}"
	fi
	# mov rax, 0x9c       ; System call number for fstat
	CODE="${CODE}${MOV_V4_rax}$(printEndianValue $((16#9c)) ${SIZE_32BITS_4BYTES})"
	# syscall             ; Call the kernel
	CODE="${CODE}${SYSCALL}";
	# mov rsi, qword [rsp + 8]    ; Get the file size from the stat struct
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
	local CODE="";
	# rdi: File descriptor number
	if [ "${fd}" != "" ]; then
		CODE="${CODE}$(mov "$fd" rdi | b64_to_hex_dump)";
	else
		# if no fd providen use rax by default
		CODE="${CODE}$(mov rax rdi | b64_to_hex_dump)";
		# TODO not sure this is a good idea but we will lost rax so for 
		# now we will save it at r8 too
		CODE="${CODE}$(mov rax r8 | b64_to_hex_dump)";
	fi;
 	# rsi: Pointer to a struct stat (will be filled with file information)
	CODE="${CODE}$(mov "${stat_addr}" rsi | b64_to_hex_dump)";
	# rax: fstat
	CODE="${CODE}$(mov $SYS_FSTAT rax | b64_to_hex_dump)";
 	CODE="${CODE}${SYSCALL}";
	echo -ne "${CODE}" | base64 -w0;
	return;
}

# get_read_size receives a stat address and return the bytecode instructions to recover the length to a target register.
# if no target register is provided it puts the value on the rsi
function get_read_size()
{
	local stat_addr="$1";
	local target_register="$2";
	local st_size=16#30;
	local code="";
	code="${code}$(mov $(( STAT_ADDR + st_size )) rsi | b64_to_hex_dump)";
	code="${code}$(mov '(rsi)' rsi | b64_to_hex_dump)";
	local default_value_code="$(mov "$PAGESIZE" rsi | b64_to_hex_dump)";
	code="${code}${CMP_rsi_V1}\x00"; # 64bit cmp rsi, 00
	local BYTES_TO_JUMP="$(printEndianValue $(echo -en "${default_value_code}" | wc -c) $SIZE_32BITS_4BYTES)";
	code="${code}${JG}${BYTES_TO_JUMP}";
	code="${code}${default_value_code}";
	# TODO
	#if rsi == 0
	#	rsi = pagesize
	#fi
	#
	#if rsi > 0 align it with the next page size multple
	echo -en "${code}" | base64 -w0;
	return
}

function getpagesize()
{
	# mov rax, 0x3f        ; sysconf syscall number
	# mov rdi, 0x18        ; _SC_PAGESIZE parameter
	# xor rsi, rsi         ; unused third parameter
	# syscall
	#
	# ; Store the result in the pagesizebuf buffer
	# mov qword [pagesizebuf], rax
	
	local CODE="";
	CODE="${CODE}$(mov $((16#3f)) rax)"; # sys_uname syscall
	CODE="${CODE}${MOV_rdi_ADDR4}$(printEndianValue $((16#18)) $SIZE_32BITS_4BYTES)"; # _SC_PAGESIZE
	CODE="${CODE}${XOR_rsi_rsi}"; # zeroes unused rsi
	CODE="${CODE}${SYSCALL}"; # 
	return;
}

PAGESIZE=$(( 4 * 1024 )); # 4KiB
# map a memory region
#|rax|syscall___________________|rdi______________|rsi________________|rdx________________|r10________________|r8_______________|r9________|
#| 9 |sys_mmap                  |unsigned long    |unsigned long len  |int prot           |int flags          |int fd           |long off  |
# Returns:
#  rax Memory Address
#  r8 FD
#  r9 Size
function sys_mmap()
{
	local size="$1";
	local fd="$2";
	local CODE="";
	# ; Map the memory region
	# mov rdi, 0     ; addr (let kernel choose)
	CODE="${CODE}${XOR_rdi_rdi}";
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
	local mmap_size_code="$(echo "$size" | b64_to_hex_dump)";
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
	CODE="${CODE}$(mov $(( PROT_READ + PROT_WRITE )) rdx | b64_to_hex_dump)";
	# man mmap for valid flags
	#    mov r10, 2    ; flags
	MAP_SHARED=1;
	MAP_PRIVATE=2;
	MAP_SHARED_VALIDATE=3;
	MAP_ANONYMOUS=$((2#00100000));
	CODE="${CODE}${MOV_V8_r10}$(printEndianValue $(( MAP_PRIVATE )) ${SIZE_64BITS_8BYTES})";
	
	# The file descriptor is expected to be at r8,
	# but for virtual files it will fail with a -19 at rax.
	# 
	if [ "$fd" == "rax" ]; then
		CODE="${CODE}${MOV_rax_r8}";
	elif [ "$fd" != "" ]; then
		CODE="${CODE}${MOV_V8_r8}$(printEndianValue $fd ${SIZE_64BITS_8BYTES})";
	fi;
	#CODE="${CODE}${XOR_r8_r8}";
	#    mov r9, 0     ; offset
	CODE="${CODE}${MOV_V8_r9}$(printEndianValue 0 ${SIZE_64BITS_8BYTES})";
	#    mov rax, 9    ; mmap system call number
	CODE="${CODE}${MOV_V8_rax}$(printEndianValue $SYS_MMAP ${SIZE_64BITS_8BYTES})";
	CODE="${CODE}${SYSCALL}";
	# test rax to detect failure
	CODE="${CODE}${CMP_rax_V1}\x00"; # 64bit cmp rax, 00
	# if it fails do mmap with  MAP_ANONYMOUS
	local ANON_MMAP_CODE="${MOV_V8_r10}$(printEndianValue $(( MAP_PRIVATE + MAP_ANONYMOUS )) ${SIZE_64BITS_8BYTES})";
	ANON_MMAP_CODE="${ANON_MMAP_CODE}${MOV_V8_rax}$(printEndianValue $SYS_MMAP ${SIZE_64BITS_8BYTES})";
	ANON_MMAP_CODE="${ANON_MMAP_CODE}${SYSCALL}";
	# then we need to read the data to that location
	ANON_MMAP_CODE="${ANON_MMAP_CODE}${MOV_r8_rdi}";
	ANON_MMAP_CODE="${ANON_MMAP_CODE}$(system_call_read "" "rsi" | b64_to_hex_dump)"; # TODO not sure the best choice here. We should do it better
	# if rax > 0 jump over this code block
	# rax will be less than zero on failure
	ANON_MMAP_CODE="${ANON_MMAP_CODE}${MOV_rax_r9}";
	# By default the sys_read will move the memory address from rax to rsi.
	ANON_MMAP_CODE="${ANON_MMAP_CODE}${MOV_rsi_rax}"; # restore rax to return the memory address
	local BYTES_TO_JUMP="$(printEndianValue $(echo -en "${ANON_MMAP_CODE}" | wc -c) $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${JG}${BYTES_TO_JUMP}"; # The second byte "85" is the opcode for the JNE instruction. The following four bytes "06 00 00 00" represent the signed 32-bit offset from the current instruction to the target label.
	CODE="${CODE}${ANON_MMAP_CODE}";
	echo -en "${CODE}" | base64 -w0;
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
		debug "displacement too big to jump short.";
		return;
	fi;
	# debug jump short relative $relative
	local RADDR_V="$(printEndianValue "$relative" $SIZE_8BITS_1BYTE )";
	# debug jump short to RADDR_V=[$( echo -n "$RADDR_V" | xxd)]
	code="${code}${JMP_V1}${RADDR_V}";
	echo -ne "$(echo -en "${code}" | base64 -w0)";
	return
}

jump_relative(){
	local relative=$1;
	local short_jump_response=$(bytecode_jump_short "${relative}")
	if [ "$(echo -n "${short_jump_response}" | base64 -d | wc -c)" -gt 0 ];then
		echo -n "${short_jump_response}";
		return;
	fi;
	#bytecode_jump_near
	if [ "$(( (relative >= - ( 1 << 31 )) && (relative <= ( 1 << 31 ) -1) ))" -eq 1 ]; then
		# jump near
		local RADDR_V;
		RADDR_V="$(printEndianValue "${relative}" $SIZE_32BITS_4BYTES)";
		# debug "jump near relative ( $relative, $RADDR_V )";
		CODE="${CODE}${JMP_V4}${RADDR_V}";
		echo -ne "$(echo -en "${CODE}" | base64 -w0)";
		return;
	fi;

	error "JMP not implemented for that relative or absolute value: $relative"
	# TODO, another way to move to a location is set the RIP directly
	# something like
	# mov eax, $address
	# mov [rsp], eax
	# mov eip, [rsp]
	echo -ne ",0"
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
		local array_code="$XOR_r15_r15";
		array_code="${array_code}$(add 8 r15 | b64_to_hex_dump)";
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
			code="${code}${MOV_rdi_ADDR4}$(printEndianValue $retval_addr $SIZE_32BITS_4BYTES)";
		fi;
		echo -en "$code" | base64 -w0;
		return;
	fi;
	error "call not implemented for this address size: CURRENT: $CURRENT, TARGET: $TARGET, RELATIVE: $RELATIVE";

	FAR_CALL="\x9a";
	MODRM="$(printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_SUB + rsp )) $SIZE_8BITS_1BYTE)";
	addr="$(( 16#000100b8 ))"
	BYTES="\xe8${CALL_ADDR}";
	code="${code}${BYTES}";
	if [ "$retval_addr" != "" ]; then
		code="${code}${MOV_rdi_ADDR4}$(printEndianValue $retval_addr $SIZE_32BITS_4BYTES)";
	fi;
	echo -en "$code" | base64 -w0;
}

function push_v_stack()
{
	local value="$1";
	local code="";
	code="${code}${MOV_V4_rax}$(printEndianValue "${value}" "${SIZE_32BITS_4BYTES}")";
	code="${code}$(push rax | b64_to_hex_dump)";
	echo -en "${code}" | base64 -w0
}

function push_stack()
{
	# PUSHA/PUSHAD – Push All General Registers 0110 0000
	
	local PUSH="\x68";
	local ADDR_V="$(printEndianValue )";
	echo -n "${PUSH}${ADDR_V}";
}

function bytecode_ret()
{
	local symbol_value="$1";
	local symbol_type="$2";
	local code="";
	# Types for return
	# Near return (same segment)
	local NEAR_RET="\xc3";
	local NEAR_RET_WITH_VALUE="\xc2"; #pop imm16 bytes from stack
	# Far return (inter segment)
	local FAR_RET="\xcb";
	local FAR_RET_WITH_VALUE="\xca"; #pop imm16 bytes from stack
	# Inter-privilege-level far return

	# currently just need the near return
	# 

	#local LEAVE="\xc9"; #seems leave breaks in a segfault
	if [ "$symbol_value" != "" ]; then
		code="${code}${MOV_V4_rdi}$(printEndianValue ${symbol_value:=0} $SIZE_32BITS_4BYTES)"
		if [ "$symbol_type" != $SYMBOL_TYPE_HARD_CODED ]; then
			code="${code}${MOV_rdi_rdi}";
		fi;
	fi;
	# run RET
	code="${code}${NEAR_RET}";
	echo -en "${code}" | base64 -w0;
}

function pop_stack()
{
	# POPA/POPAD – Pop All General Registers 0110 0001
	:
}


function system_call_open()
{
	local filename="$1"
	local CODE="";
	# mov rax, 2 ; System call for open()
	CODE="${CODE}${MOV_V8_rax}$(printEndianValue ${SYS_OPEN} "${SIZE_64BITS_8BYTES}")";
	# mov rdi, filename ; File name
	local FILENAME_ADDR="$(printEndianValue "${filename}" "${SIZE_64BITS_8BYTES}" )";
	CODE="${CODE}${MOV_V8_rdi}${FILENAME_ADDR}";
	# TODO best to use xor when setting rsi to 0
	# mov rsi, 'r' ; Open mode
	CODE="${CODE}${MOV_V8_rsi}$(printEndianValue $(( 16#0 )) "${SIZE_64BITS_8BYTES}")"; # mode=r (x72)
	# xor rdx, rdx ; File permissions (ignored when opening)
	#CODE="${CODE}${XOR}${rdx}${rdx}"
	CODE="${CODE}${SYSCALL}";
	echo -ne "${CODE}" | base64 -w0;
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
	local STAT_ADDR="$2";
	local targetMemory="$3";
	local DATA_LEN="$4";
	if [ "$STAT_ADDR" != "" ]; then
		DATA_LEN="$(get_read_size "${STAT_ADDR}")";
	fi;
	# debug DATA_LEN="$DATA_LEN"
	local CODE="";
	# DATA_LEN should be the size(in bytes) we want to write out.
	# We need to stat the file to get the real value
	# Memory address of the stat structure
	# debug read_file 
	if [ "${TYPE}" == "${SYMBOL_TYPE_STATIC}" -o "${TYPE}" == "${SYMBOL_TYPE_HARD_CODED}" ]; then
		# do we have a buffer to read into? should we use it in a mmap?
		# now we create a buffer with mmap using this fd in rax.
		CODE="${CODE}$(sys_mmap "${DATA_LEN}" | b64_to_hex_dump)";
		CODE="${CODE}$(mov rax "$targetMemory" | b64_to_hex_dump)";
		# TODO test sys_mmap return at rax, and if fails(<0) then mmap without the fd
		# TODO once mmap set, if the source file is read only we can just close it.
		# then the fd should be at eax and r8
		#
		# TODO:
		# collect $rax (memory location returned from mmap)
		# use it as argument to write out.
		echo -en "${CODE}" | base64 -w0;
		return;
	elif [ "${TYPE}" == ${SYMBOL_TYPE_DYNAMIC} ]; then
		if [ "$(echo -n "${DATA_ADDR_V}" | base64 -d | cut -d, -f1 | base64 -w0)" == "$( echo -n ${ARCH_CONST_ARGUMENT_ADDRESS} | base64 -w0)" ]; then
			# now we create a buffer with mmap using this fd in rax.
			CODE="${CODE}$(sys_mmap | b64_to_hex_dump)";
			# collect $rax (memory location returned from mmap)
			# use it as argument to write out.
			CODE="$(mov rax "$targetMemory" | b64_to_hex_dump)";
			CODE="${CODE}${MOV_rax_rsi}";
			CODE="${CODE}${MOV_V8_rax}$(printEndianValue $SYS_WRITE $SIZE_64BITS_8BYTES)";
			STDOUT=1;
			CODE="${CODE}${MOV_V8_rdi}$(printEndianValue $STDOUT $SIZE_64BITS_8BYTES)";
			CODE="${CODE}${MOV_V8_rdx}$(printEndianValue "${DATA_LEN}" $SIZE_64BITS_8BYTES)";
			CODE="${CODE}${SYSCALL}";
			echo -en "${CODE}" | base64 -w0;
		else
			# otherwise we expect all instruction already be in the data_addr_v as base64
			# so just throw it back
			echo -n "$DATA_ADDR_V";
		fi;
		return;
	fi
	error "b Not Implemented path type[$TYPE], DATA_ADDR_V=[$DATA_ADDR_V]";
	return;
}

function system_call_read()
{
	local FD=$1;
	local len="$2";
	local DATA_ADDR="$3";
	local CODE="";
	# by default expect the rdi already have the fd
	if [ "$FD" != "" ]; then
		CODE="${CODE}${MOV_V8_rdi}$(printEndianValue $FD $SIZE_64BITS_8BYTES)";
	fi
	if [ "$len" == "rsi" ]; then
		CODE="${CODE}${MOV_rsi_rdx}";
	else
		CODE="${CODE}${MOV_V8_rdx}$(printEndianValue ${len} $SIZE_64BITS_8BYTES)";
	fi;
	if [ "$DATA_ADDR" == "" ]; then
		#use rax
		CODE="${CODE}${MOV_rax_rsi}";
	else
		CODE="${CODE}${MOV_V8_rsi}$(printEndianValue "$DATA_ADDR" "$SIZE_64BITS_8BYTES" )";
	fi;
	CODE="${CODE}${MOV_V8_rax}$(printEndianValue $SYS_READ $SIZE_64BITS_8BYTES)";
	CODE="${CODE}${SYSCALL}";
	echo -en "${CODE}" | base64 -w0;
}

# given a data address as argument, write it to stdout
function system_call_write_addr()
{
	local OUT="$1";
	local DATA_ADDR_V="$2";
	local DATA_LEN="$3";
	local DATA_ADDR="$(printEndianValue "$DATA_ADDR_V" "$SIZE_64BITS_8BYTES")";
	local CODE="";
	CODE="${CODE}${MOV_V8_rax}$(printEndianValue $SYS_WRITE $SIZE_64BITS_8BYTES)";
	CODE="${CODE}${MOV_V8_rdi}$(printEndianValue $OUT $SIZE_64BITS_8BYTES)";
	CODE="${CODE}${MOV_V8_rsi}${DATA_ADDR}";
	CODE="${CODE}${MOV_V8_rdx}$(printEndianValue "${DATA_LEN}" $SIZE_64BITS_8BYTES)";
	CODE="${CODE}${SYSCALL}";
	echo -en "${CODE}" | base64 -w0;
}

function detect_argsize()
{
	local CODE="";
	# figure out the data size dynamically.
	# To do it we can get the next address - the current address
	# the arg2 - arg1 address - 1(NULL) should be the data size
	# The last argument need to check the size by using 16 bytes, not 8.
	#   because 8 bytes lead to the NULL, 16 leads to the first env var.
	#
	# to find the arg size, use rdx as rsi
	CODE="${CODE}${MOV_rsi_rdx}";
	# increment rdx by 8
	ARGUMENT_DISPLACEMENT=8
	CODE="${CODE}$(add $ARGUMENT_DISPLACEMENT rdx | b64_to_hex_dump)";
	# mov to the real address (not pointer to address)
	ModRM=$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_REG_rsi + rdx )) ${SIZE_8BITS_1BYTE} )
	CODE="${CODE}${MOV_rsi_rsi}"; # resolve pointer to address
	CODE="${CODE}${MOV_rdx_rdx}"; # resolve pointer to address
	# and subtract rdx - rsi (resulting in the result(str len) at rdx)
	CODE="${CODE}${SUB_rdx_rsi}";
	echo -n "${CODE}";
}

# how dinamically discover the size?
# one way is to increment the pointer, then subtract the previous pointer, this is fast but this is only garanteed to work in arrays of data, where the address are in same memory block. see detect_argsize
# another way is to count the bytes until find \x00. but this will block the possibility of write out the \x00 byte. this is what bash does. despite slower and the side effect of not allowing \x00, it is safer.
function detect_string_length()
{
	local code="";
	#code="${code}${XOR_rdx_rdx}"; # ensure rdx = 0
	code="${code}$(mov rsi rdx | b64_to_hex_dump)"; # let's use rdx as rsi incrementing it each loop interaction
	# save rip
	# leaq (%rip), %rbx # 
	#code=${code}${LEAQ_RIP_rbx};
	# get the data byte at addr+rdx into rax
	code="${code}$(mov "(rdx)" rax | b64_to_hex_dump)"; # resolve current rdx pointer to rax
	#code="${code}${MOV_DATA_rax}";
	# inc rdx
	code="${code}${INC_rdx}";
	# test data byte
	TEST_AL="\x84\xc0";
	# loop back if not null
	code="${code}${TEST_AL}";
	# jz
	# "ebfe" # jump back 0 bytes
	JUMP_BACK_BYTES="\x7f\xf5"; # jg .-9; Jump back 9 bytes only if AL > 0 (f5 == -11, includes the 2 bytes jmp instr)
	code="${code}${JUMP_BACK_BYTES}";
	code="${code}${DEC_rdx}";
	# sub %rsi, %rdx
	code="${code}${SUB_rsi_rdx}";
	#JMP_rbx="\xff\x23";
	echo -n "$code";
}

# given a dynamic address, write it to OUT;
# if len=0, autodetect by null char;
function system_call_write_dyn_addr()
{
	local OUT="$1";
	local DATA_ADDR_V="$2";
	local DATA_LEN="$3";
	local CODE="";
	# otherwise we expect all instruction already be in the data_addr_v as base64
	local code="";
	if [ "$DATA_ADDR_V" == "rax" ]; then
		code="${code}${MOV_rax_rsi}";
	else
		code="${code}${MOV_ADDR4_rsi}$(printEndianValue ${DATA_ADDR_V} ${SIZE_32BITS_4BYTES})";
	fi
	if [ "${DATA_LEN}" == "0" ]; then
		code="${code}$(detect_string_length)";
	else
		local MOV_V_rdx="${MOV_V8_rdx}$(printEndianValue "${DATA_LEN}" ${SIZE_64BITS_8BYTES})";
		code="${code}${MOV_V_rdx}";
	fi;
	code="${code}${MOV_V8_rdi}$(printEndianValue $OUT $SIZE_64BITS_8BYTES)";
	code="${code}${MOV_V8_rax}$(printEndianValue $SYS_WRITE $SIZE_64BITS_8BYTES)";
	code="${code}${SYSCALL}";
	echo -ne "${code}" | base64 -w0;
	return;
}

function system_call_write()
{
	local TYPE="$1";
	local OUT="$2";
	local DATA_ADDR_V="$3";
	local DATA_LEN="$4";
	local CURRENT_RIP="$5";
	local code="";
	if [ "${TYPE}" == "${SYMBOL_TYPE_STATIC}" ]; then
		echo -n "$(system_call_write_addr "${OUT}" "${DATA_ADDR_V}" "${DATA_LEN}")";
	elif [ "${TYPE}" == "${SYMBOL_TYPE_HARD_CODED}" ]; then
	{
		code="${code}$(push_v_stack "${DATA_ADDR_V}" | b64_to_hex_dump)";
		code="${code}${MOV_V4_rax}$(printEndianValue $SYS_WRITE $SIZE_32BITS_4BYTES)";
		code="${code}${MOV_V4_rdi}$(printEndianValue $OUT $SIZE_32BITS_4BYTES)";
		code="${code}${MOV_rsp_rsi}";
		code="${code}${MOV_V4_rdx}$(printEndianValue "8" $SIZE_32BITS_4BYTES)";
		code="${code}${SYSCALL}";
		code="${code}$(pop rax | b64_to_hex_dump)";
		echo -ne "${code}" | base64 -w0;
	}
	elif [ "${TYPE}" == "${SYMBOL_TYPE_DYNAMIC}" ]; then
	{
		echo -n "$(system_call_write_dyn_addr "${OUT}" "${DATA_ADDR_V}" "${DATA_LEN}")";
	}
	elif [ "$TYPE" == "${SYMBOL_TYPE_PROCEDURE}" ]; then
	{
		local code="";
		code="${CODE}$(call_procedure ${DATA_ADDR_V} ${CURRENT_RIP} | b64_to_hex_dump)";
		code="${code}${MOV_V8_rax}$(printEndianValue $SYS_WRITE $SIZE_64BITS_8BYTES)";
		code="${code}${MOV_r9_rdx}"
		code="${code}${MOV_V8_rdi}$(printEndianValue $OUT $SIZE_64BITS_8BYTES)";
		code="${code}${SYSCALL}";
		echo -ne "${code}" | base64 -w0;
	}
	else
		error "a Not Implemented path type[$TYPE], DATA_ADDR_V=[$DATA_ADDR_V]"
	fi;
	return
}

function system_call_exit()
{
	local exit_code="$1"
	local symbol_type="$2";
	local code="";
	code="${code}${MOV_V4_rax}$(printEndianValue $SYS_EXIT $SIZE_32BITS_4BYTES)";
	code="${code}$(mov ${exit_code:=0} rdi | b64_to_hex_dump)";
	if [ "$symbol_type" != $SYMBOL_TYPE_HARD_CODED ]; then
		code="${code}${MOV_rdi_rdi}";
	fi;
	code="${code}${SYSCALL}"
	echo -en "${code}" | base64 -w0;
}

function system_call_fork()
{
	local SYS_FORK=57
	local CODE="";
	CODE="${CODE}${MOV_V4_rax}$(printEndianValue ${SYS_FORK} ${SIZE_32BITS_4BYTES})";
	CODE="${CODE}${SYSCALL}";
	echo -en "${CODE}" | base64 -w0;
	echo -en ",$(echo -en "${CODE}" | wc -c )";
}

function system_call_pipe()
{
	local pipe_addr="$1";
	local sys_pipe=22;
	local code="";
	code="${code}${MOV_V4_rax}$(printEndianValue "${sys_pipe}" "$SIZE_32BITS_4BYTES")";
	code="${code}${MOV_V4_rdi}$(printEndianValue "${pipe_addr}" "$SIZE_32BITS_4BYTES")";
	code="${code}${SYSCALL}";
	echo -en "${code}" | base64 -w0;
}

function system_call_wait4()
{
	local sys_wait4=61;
	local code="";
	code="${code}${MOV_V4_rax}$(printEndianValue ${sys_wait4} ${SIZE_32BITS_4BYTES})"
	# printEndianValue seems buggy with negative values
	#wait_code="${wait_code}${MOV_V4_rdi}$(printEndianValue -1 ${SIZE_32BITS_4BYTES}) ";# pid_t pid
	# so lets change to decrement rdi
	code="${code}${XOR_rdi_rdi}${DEC_rdi}";
	code="${code}${XOR_rsi_rsi}";# int __user *stat_addr
	code="${code}${XOR_rdx_rdx}";# int options
	code="${code}${XOR_r10_r10}";# struct rusage
	code="${code}${SYSCALL}";
	echo -en "${code}" | base64 -w0;
}

function system_call_dup2()
{
	local old_fd_addr="$1"; # where in memory we have the int value of the fd
	local new_fd="$2";
	local sys_dup2=33;
	local code="";
	code="${code}${MOV_V4_rax}$(printEndianValue "${sys_dup2}" "${SIZE_32BITS_4BYTES}")";
	code="${code}${MOV_V4_rdi}$(printEndianValue "${old_fd_addr}" "${SIZE_32BITS_4BYTES}")";
	code="${code}${MOV_rdi_rdi}";
	code="${code}${MOV_V4_rsi}$(printEndianValue "${new_fd}" "${SIZE_32BITS_4BYTES}")";
	code="${code}${SYSCALL}";
	echo -en "${code}" | base64 -w0;
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
		dup2_child="$(system_call_dup2 "$pipe_out" "$stdout" | b64_to_hex_dump)";
		# read_pipe will run on the parent pid.
		read_pipe="${read_pipe}${MOV_V4_rax}$(printEndianValue "${SYS_READ}" "${SIZE_32BITS_4BYTES}")";
		read_pipe="${read_pipe}${MOV_V4_rdi}$(printEndianValue "${pipe_in}" "${SIZE_32BITS_4BYTES}")$(mov "(edi)" edi | b64_to_hex_dump)"; # fd
		read_pipe="${read_pipe}${MOV_V4_rsi}$(printEndianValue "${pipe_buffer_addr}" "${SIZE_32BITS_4BYTES}")"; # buff
		read_pipe="${read_pipe}$(mov rsi "$((pipe_buffer_addr - 8))" | b64_to_hex_dump )"; # set the pointer to the buffer allowing concat to work
		read_pipe="${read_pipe}${MOV_V4_rdx}$(printEndianValue "${pipe_buffer_size}" "${SIZE_32BITS_4BYTES}")"; # count
		read_pipe="${read_pipe}${SYSCALL}";
	fi;

	local exec_code="";
	# set the args array in memory
	local argc=${#args[@]};
	debug "exec args=$argc = [${args[@]}] == [$2]";
	debug "exec staticmap=${#static_map[@]} = [${static_map[@]}] == [$3]";
	for (( i=0; i<${argc}; i++ ));
	do {
		exec_code="${exec_code}${MOV_V8_rax}$(printEndianValue "${args[$i]}" "${SIZE_64BITS_8BYTES}")";
		if [ "${static_map[$i]}" == 0 ]; then # it's a dynamic command, resolve it
			exec_code="${exec_code}$(mov "(rax)" rax | b64_to_hex_dump)";
		fi;
		exec_code="${exec_code}$(mov rax "$(( PTR_ARGS + i*8 ))" | b64_to_hex_dump)";
	}; done
	exec_code="${exec_code}${XOR_rax_rax}";
	exec_code="${exec_code}$(mov rax "$(( PTR_ARGS + ${#args[@]} * 8 ))" | b64_to_hex_dump)";
	exec_code="${exec_code}${MOV_V8_rdi}$(printEndianValue ${args[0]} ${SIZE_64BITS_8BYTES})";
	if [ "${static_map[0]}" == 0 ]; then # it's a dynamic command, resolve it
		exec_code="${exec_code}${MOV_rdi_rdi}";
	fi;

	exec_code="${exec_code}${MOV_V8_rsi}$(printEndianValue ${PTR_ARGS:=0} ${SIZE_64BITS_8BYTES})";

	exec_code="${exec_code}${MOV_V8_rdx}$(printEndianValue ${PTR_ENV:=0} ${SIZE_64BITS_8BYTES})"; # const char *const envp[]

	exec_code="${exec_code}${MOV_V8_rax}$(printEndianValue ${SYS_EXECVE} ${SIZE_64BITS_8BYTES})"; # sys_execve (3b)

	exec_code="${exec_code}${SYSCALL}";
	# end exec code:
	
	local pipe_code="";
	if [ "$pipe_addr" != "" ]; then
		local pipe_code=$(system_call_pipe "${pipe_addr}"| b64_to_hex_dump);
	fi;
	# start fork code
	local fork_code="$(system_call_fork | cut -d, -f1 | b64_to_hex_dump)";
	# TODO: CMP ? then (0x3d) rAx, lz
	local TWOBYTE_INSTRUCTION_PREFIX="\0f"; # The first byte "0F" is the opcode for the two-byte instruction prefix that indicates the following instruction is a conditional jump.
	fork_code="${fork_code}${CMP_rax_V1}\x00"; # 64bit cmp rax, 00
	# rax will be zero on child, on parent will be the pid of the forked child
	# so if non zero (on parent) we will jump over the sys_execve code to not run it twice,
	# and because it will exit after run
	CODE_TO_JUMP="$(printEndianValue "$(echo -en "${dup2_child}${exec_code}" | wc -c)" ${SIZE_32BITS_4BYTES})"; # 45 is the number of byte instructions of the syscall sys_execve (including the MOV (%rdi), %rdi.
	fork_code="${fork_code}${JNE}${CODE_TO_JUMP}"; # The second byte "85" is the opcode for the JNE instruction. The following four bytes "06 00 00 00" represent the signed 32-bit offset from the current instruction to the target label.
	# end fork code
	local wait_code="$(system_call_wait4 | b64_to_hex_dump)";

	code="${pipe_code}${fork_code}${dup2_child}${exec_code}${wait_code}${read_pipe}";
	echo -en "${code}" | base64 -w0;
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
	code="${code}${MOV_rsp_r14}";
	code="${code}${ADD_r15_r14}"; # this allows set r15 as displacement and use this code in function get args
	code="${code}${MOV_r14_ADDR4}$(printEndianValue $addr $SIZE_32BITS_4BYTES)";
	echo -en "${code}" | base64 -w0;
}

function get_arg()
{
	local ADDR="$1";
	local ARGN="$2";
	local CODE="";
	# MOV %rsp %rsi
	CODE="${CODE}${MOV_rsp_rsi}";
	# ADD rsi 8
	CODE="${CODE}$(add $(( 8 * (1 + ARGN) )) rsi | b64_to_hex_dump)";
	CODE="${CODE}${ADD_r15_rsi}";
	# RESOLVE rsi (Copy pointer address content to rsi)
	CODE="${CODE}${MOV_rsi_rsi}";
	# MOV rsi ADDR
	CODE="${CODE}$(mov rsi "$ADDR" | b64_to_hex_dump)";
	echo -en "${CODE}" | base64 -w0;
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
	local mmap_size_code="$( echo -en "${MOV_V4_rsi}$(printEndianValue $(( 4 * 1024 )) ${SIZE_32BITS_4BYTES})" | base64 -w0)";
	local mmap_code="$(sys_mmap "${mmap_size_code}" | b64_to_hex_dump)"
	# unable to move addr to addr;
	# so let's mov addr to a reg,
	# then reg to addr;
	if [ "$idx" == 1 ]; then # on first item zero r8 to accum the size
		code="${code}${XOR_r8_r8}";
		code="${code}$(push r8 | b64_to_hex_dump)"; # create zeroed target space at stack;
		code="${code}$(mov rsp $dyn_addr | b64_to_hex_dump)";
	fi;
	if [ "$size" -eq -1 ]; then
		code="${code}${MOV_ADDR4_rsi}$(printEndianValue "${addr}" "${SIZE_32BITS_4BYTES}")"; # source addr
		code="${code}$(detect_string_length)"; # the return is set at rdx
		code="${code}${MOV_rdx_rcx}"; # but we need it on rcx because REP decrements it
	elif [ "$size" -eq -2 ]; then # procedure pointer
		code="${code}${MOV_ADDR4_rsi}$(printEndianValue "${addr}" "${SIZE_32BITS_4BYTES}")"; # source addr
		# TODO: how to manage to con
		#code="${code}${}"; # the return is set at rdx
		code="${code}${MOV_rdx_rcx}"; # but we need it on rcx because REP decrements it
		echo -en "${code}" | base64 -w0;
		return;
	else
		code="${code}${MOV_V4_rsi}$(printEndianValue "$addr" "${SIZE_32BITS_4BYTES}")"; # source addr
		code="${code}${MOV_V4_rcx}$(printEndianValue "$size" ${SIZE_32BITS_4BYTES})";
	fi;
	code="${code}${MOV_rsp_rdi}"; # target addr
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
		code="${code}$(mov "(rax)" rax | b64_to_hex_dump)";
	fi;
	if [ "${type_b}" == "$SYMBOL_TYPE_DYNAMIC" ]; then
		code="${code}${LEA_V4_rcx}$(printEndianValue "$b" "${SIZE_32BITS_4BYTES}")";
		code="${code}${MOV_rcx_rcx}";
	fi;
	code="${code}${CMP_rax_rcx}";
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
		code="${code}${INC_rdx}";
	elif [ "$value" -gt -128 -a "$value" -lt 128 ]; then
		code="${code}$(add "${value}" rdx | b64_to_hex_dump)";
	elif [ "$value_type" == $SYMBOL_TYPE_HARD_CODED ]; then
		code="${code}${ADD_V4_rdx}$(printEndianValue "${value}" "${SIZE_32BITS_4BYTES}")";
	else
		code="${code}${XOR_rsi_rsi}";
		code="${code}${MOV_V4_rsi}$(printEndianValue "${value}" "${SIZE_32BITS_4BYTES}")";
		code="${code}${MOV_rsi_rsi}";
		code="${code}${ADD_rsi_rdx}";
	fi;
	code="${code}$(mov rdx "$addr" | b64_to_hex_dump)";
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
	code="${code}${XOR_rax_rax}";
	code="${code}${MOV_rax_rdx}";
	code="${code}${MOV_rax_rsi}";
	code="${code}$(prefix rdi | b64_to_hex_dump)\x8d\x3d\x04\x00\x00\x00";# lea rdi,[rel 0xb]
	code="${code}$(add ${SYS_EXECVE} AL | b64_to_hex_dump)";
	code="${code}${SYSCALL}";
	code="${code}\x2f\x62\x69\x6e\x2f\x73\x68\x00\xcc\x90\x90\x90";
#  https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.
#
# https://www.exploit-db.com/exploits/41128
#  "$(prefix | b64_to_hex_dump)\x31\xc0"
#  "$(prefix| b64_to_hex_dump)\x31\xd2"
#  "$(prefix | b64_to_hex_dump)\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f"
#  "\x0f\x05"
#  "$(prefix | b64_to_hex_dump)\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a"
#  "\x0f\x05"
#  "\x5e\x6a\x32\x58"
#  "\x0f\x05"
#  "\x6a\x2b\x58"
#  "\x0f\x05"
#  "$(prefix | b64_to_hex_dump)\x97\x6a\x03\x5e\xff\xce\xb0\x21"
#  "\x0f\x05"
#  "\x75\xf8\xf7\xe6\x52$(rex | b64_to_hex_dump)\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53$(rex | b64_to_hex_dump)\x8d\x3c\x24\xb0\x3b"
#  "\x0f\x05";
  :
}
init_bloc(){
	local code="";
	#code="${code}$(mov 8 r15 | b64_to_hex_dump)";
	#code="${code}${mov rsp rbp | b64_to_hex_dump)";
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
		code="${code}$(push_v_stack $item_value | b64_to_hex_dump)";
	else
		code="${code}${MOV_V4_rax}$(printEndianValue "${item_addr}" $SIZE_32BITS_4BYTES)";
		code="${code}$(push rax | b64_to_hex_dump)";
	fi;
	echo -ne "${code}" | base64 -w0;
}
array_end(){
	local array_addr="$1";
	local array_size="$2";
	local code="";
	# save the array addr outside the stack(in the main memory)
	code="${code}${MOV_rsp_rax}";
	code="${code}$(add $(( array_size * 8 -8)) rax | b64_to_hex_dump)";
	code="${code}$(mov rax "$array_addr" | b64_to_hex_dump)";
	# put the array size in the stack
	code="${code}$(push_v_stack $array_size | b64_to_hex_dump)";
	echo -ne "${code}" | base64 -w0;
}
sys_geteuid(){
	local addr="$1";
	local code="";
	local SYS_GETEUID=107;
	code="${code}${MOV_V4_rax}$(printEndianValue "$SYS_GETEUID" $SIZE_32BITS_4BYTES)"
	code="${code}${SYSCALL}";
	code="${code}$(mov rax "$addr" | b64_to_hex_dump)";
	echo -en "${code}" | base64 -w0;
}


div10(){
	local code="";
	# 0xcccccccd is the float value for 0.1;
	# ba cd cc cc cc       	mov    $0xcccccccd,%edx
	local float_by_10="\xcd\xcc\xcc\xcc";
	MOV_V4_EDX="\xba";
	code="${code}${MOV_V4_EDX}${float_by_10}";
	# 48 0f af c2          	imul   %rdx,%rax
	code="${code}${IMUL_rdx_rax}";
	echo -ne "$code" | base64 -w0;
}

mod10(){
	local code="";
	code="${code}$(div10 | b64_to_hex_dump)";
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
	local modrm="$MODRM_MOD_DISPLACEMENT_REG";
	if [ "$r1" == "(rax)" ]; then
		modrm="$MODRM_MOD_DISPLACEMENT_REG_POINTER";
	fi
	local rc=$(( modrm + ( ${r2,,} << 3 ) + ( ${r1,,} ) ));
	BSR="$(prefix $r2 $r1 | b64_to_hex_dump)\x0F\xBD$(printEndianValue ${rc} $SIZE_8BITS_1BYTE)";
	code="${code}${BSR}";
	echo -ne "$code" | base64 -w0;
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
		code="${code}${MOV_rsp_rax}";
		code="${code}$(add 24 rax | b64_to_hex_dump)";
		code="${code}$(mov "(rax)" rax | b64_to_hex_dump)";
		# should be the same as: movsbl 0x18(%rsp), %eax
		#code="${code}${MOVSBL_V4rsp_EAX}$(printEndianValue 24 $SIZE_8BITS_1BYTE)";
		retcode="$(bytecode_ret | b64_to_hex_dump)";
	fi;
	r1="${r1:=rax}";
	r2="${r2:=rdx}";
	# bsr rbx, esi		# count bits into rbx
	code="${code}$(bsr "$r1" "$r2" | b64_to_hex_dump)";
	# movzx   eax, BYTE PTR array_max_bit_val_ilog10[1+rax] # movzx (zero extend, set the byte and fill with zeroes the remaining bits)
	#${MOV_rsi_rcx}$(add 63 rcx | b64_to_hex_dump)
	#code="${code}${MOVSBL_V4rsi_ECX}";
	#code="${code}$(add $r2 $r3 | b64_to_hex_dump)";
	# 483B04D5 	cmp 0x0(,%rdx,8),%rax
	# 1 0000 0FBE1415 	movsbl 0x010018(,%rdx,),%edx
	#movsbl guess_map_addr(rdx), %edx
	code="${code}${MOVSBL_V4_rdx_EDX}$(printEndianValue $guess_map_addr $SIZE_32BITS_4BYTES)";
	local power_map_addr=$((guess_map_addr + ilog10_guess_map_size));
	code="${code}${CMP_V4_rdx_8_rax}$(printEndianValue $power_map_addr $SIZE_32BITS_4BYTES)";
	code="${code}${SBB_0_EDX}";
	if [ "$ret_addr" != "" ]; then
		#code="${code}${MOV_rsi_rsi}";
		#1 0000 480FB6FA 	movzx %dl,%rdi
		code="${code}${MOVZX_DL_rdi}";
		#code="${code}$(mov rsi $ret_addr | b64_to_hex_dump)";
	fi;
	echo -en "${code}${retcode}" | base64 -w0;
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
	local ilog10_addr="$4";
	local power10_addr="$5";
	local CURRENT_RIP="$6";
	local code="";
	local codepart1="";
	if [ "$int_symbol_type" == $SYMBOL_TYPE_DYNAMIC ]; then
		codepart1="${codepart1}${MOV_ADD4_rax}$(printEndianValue "${int_symbol_value}" $SIZE_32BITS_4BYTES)";
	elif [ "$int_symbol_type" == $SYMBOL_TYPE_HARD_CODED ]; then
		codepart1="${codepart1}$(mov "${int_symbol_value}" rax | b64_to_hex_dump)";
	else
		:
		# expect to have the value on rax already;
	fi;
	codepart1="${codepart1}$(mov rsp rax | b64_to_hex_dump)";
	codepart1="${codepart1}$(add 24 rax | b64_to_hex_dump)";
	codepart1="${codepart1}$(mov "(rax)" rax | b64_to_hex_dump)";
	# TODO: Problem: if the string is not aligned with 8 bytes,
	# 	 	then we need to ensure it is zero on higher bits in last string byte;
	# TODO: 	how to know if the string is less than 8 bytes?
	# 		check for byte "00"; How ?
	# 			we can:
	codepart1="${codepart1}$(mov "(rax)" rdi | b64_to_hex_dump)";	# mov %rax, %rsi;	# backup the value in another register;
	codepart1="${codepart1}$(cmp sil 0 | b64_to_hex_dump)";		# cmp %dl, 0;		# check low 8 bits for 0x00;
	#codepart1="${codepart1}$(jg 3 | b64_to_hex_dump)"; # jg ...; if true rcx is the strlen
	# 				- shift right 8 bits
	# 				- cmp %rcx, 3; # loop test
	# 				- jl ...; # jump back to check 3 times;
	# 				- mov %rsi, %rax; # restore the value;
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
	codepart1="${codepart1}$(mov "(rax)" rax | b64_to_hex_dump)";
	codepart1="${codepart1}${CMP_rax_V1}$(printEndianValue 0 $SIZE_8BITS_1BYTE)";
	local codeforzero="";
	codeforzero="${codeforzero}$(add 48 rax| b64_to_hex_dump)";
	codeforzero="${codeforzero}${MOV_AL_ADDR4}$(printEndianValue $str_addr $SIZE_32BITS_4BYTES)";
	codeforzero="${codeforzero}${MOV_V4_rdi}$(printEndianValue $str_addr $SIZE_32BITS_4BYTES)";
	codeforzero="${codeforzero}$(bytecode_ret | b64_to_hex_dump)";
	codepart1="${codepart1}${JG_V1}$(printEndianValue $( echo -en "$codeforzero" | wc -c) $SIZE_8BITS_1BYTE)";
	codepart1="${codepart1}${codeforzero}";
	codepart1="${codepart1}$(push rax | b64_to_hex_dump)";
	codepart1="${codepart1}$(push rax | b64_to_hex_dump)";
	codepart1="${codepart1}$(push rax | b64_to_hex_dump)";
	codepart1="${codepart1}$(call_procedure ${ilog10_addr} $(( CURRENT_RIP + $( echo -en "${codepart1}" | wc -c) )) | b64_to_hex_dump)";
	# at this point rdx == 3 (log 10 (n))
	# rax is the value (1000)
	codepart1="${codepart1}${XOR_rdi_rdi}";
	codepart1="${codepart1}";
	code="${code}${codepart1}";
	local codepart2="";
	codepart2="${codepart2}${XOR_rcx_rcx}";
	local code_dec_part="";
	code_dec_part="${code_dec_part}${SUB_ADDR4_rax_rax}$(printEndianValue $power10_addr $SIZE_32BITS_4BYTES)";
	code_dec_part="${code_dec_part}$(inc rcx | b64_to_hex_dump)";
	local loopcode="";
	# cmp %rax, $power10_addr(,%rdx,8);
	loopcode="${loopcode}${CMP_rax_ADDR4_rdx_8}$(printEndianValue "$power10_addr" $SIZE_32BITS_4BYTES)";
		local printDigitCode="";
		printDigitCode="${printDigitCode}$(add $(printf %d \'0) rcx | b64_to_hex_dump)"; # add the zero asc value (0x30)
		printDigitCode="${printDigitCode}${MOV_CL_ADDR4_rdi}$(printEndianValue $str_addr $SIZE_32BITS_4BYTES)"; # append the rcx low byte to str addr
		printDigitCode="${printDigitCode}$(inc rdi | b64_to_hex_dump)";
		#⤚·······rdx=$((rdx-1));
		printDigitCode="${printDigitCode}${DEC_rdx}";
		# $rdx -lt 0 ] && break;
		printDigitCode="${printDigitCode}${CMP_rdx_V1}$(printEndianValue 0 $SIZE_8BITS_1BYTE)";
		xor_size=3; # size of "xor rcx, rcx" instr bytes
		printDigitCode="${printDigitCode}${JGE_V1}$(printEndianValue $(( 0 - $( echo -e "$printDigitCode" | wc -c ) - xor_size - 11 )) $SIZE_8BITS_1BYTE)"; # TODO why do i need to substract 11?
		local jmpv1_size=2; # it is not in code_dec_part yet because it depends on this block size
		printDigitCode="${printDigitCode}${JMP_V1}$(printEndianValue $(( $(echo -en "${code_dec_part}"| wc -c) + jmpv1_size)) $SIZE_8BITS_1BYTE)";
		# continue; # jump back to "xor %rcx, %rcx"
	jmpsize=$(( $(echo -e "$printDigitCode" | wc -c) ));
	loopcode="${loopcode}${JNG_V1}$(printEndianValue ${jmpsize} $SIZE_8BITS_1BYTE)";
	loopcode="${loopcode}${printDigitCode}";
	# jg loopcode
	codepart2="${codepart2}${loopcode}";
	# fix the stack
	# sub power10(rax), rax
	codepart2="${codepart2}${code_dec_part}";
	# jmp back
	code="${code}${codepart2}";
	code="${code}${JMP_V1}$(printEndianValue $(( - $(echo -en "${codepart2}" | wc -c) +1 )) $SIZE_8BITS_1BYTE )"; # TODO: why +1 ?
	code="${code}$(pop rax | b64_to_hex_dump)";
	code="${code}$(pop rax | b64_to_hex_dump)";
	code="${code}$(pop rax | b64_to_hex_dump)";
	# TODO code="${code}${MOV_v0_ADDR4_rdi}$(printEndianValue $str_addr $SIZE_32BITS_4BYTES)"; # append the 00 to close the string
	code="${code}$(mov $str_addr rdi | b64_to_hex_dump)";
	code="${code}$(bytecode_ret | b64_to_hex_dump)";
	echo -en "$code" | base64 -w0;
}

