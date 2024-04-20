#!/bin/bash
#
# Here should be all x86_64 specific code.
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
# which are named from R0 to R15. The first 8 registers, 
# R0 to R7, can be accessed using their traditional names (AX, BX, CX, DX, BP, SI, DI, and SP), 
# which have been used since the early days of x86 processors. 
# However, the additional registers introduced in the x86-64 architecture 
# (R8 to R15) have new names that reflect their expanded capabilities 
# and wider use in modern software development. 
# These new names are intended to make it easier for programmers 
# to distinguish between the older and newer registers and to avoid naming conflicts.
#
# 16 general purpose registers
#  The prefix E stands for 32bit and R for 64bit
#  RAX: Accumulator: Used In Arithmetic operations
#  RCX: Counter: Used in loops and shift/rotate instructions
#  RDX: Data: Used in arithmetic operations and I/O operations
#  RBX: Base: Used as a pointer to data
#  RSP: Stack Pointer: Points to top of stack
#  RBP: Stack Base Pointer: Points to base of stack
#  RSI: Points to source in stream operations
#  RDI: Points to destination in streams operations
#  r8-r15: general purpose
# 6 segment registers: points to memory segment addresses (but uses paging instead segmentation)
# 1 flag register: used to support arithmetic functions and debugging.
#  EFLAG(32)
#  RFLAG(64)
#
#Here is a table of all the registers in x86_64 with their sizes:
#	regval	64bit	32bit	16bit	8bit
#	000	rax	eax	ax	al
#	001	rcx	ecx	cx	cl
#	010	rdx	edx	dx	dl
#	011	rbx	ebx	bx	bl
#	100	rsp	esp	sp	spl	processor controlled pointing to stack pointer
#	101	rbp	ebp	bp	bpl
#	110	rsi	esi	si	sil
#	111	rdi	edi	di	dil
#	000	r8	r8d	r8w	r8b
#	001	r9	r9d	r9w	r9b
#	010	r10	r10d	r10w	r10b
#	011	r11	r11d	r11w	r11b
#	100	r12	r12d	r12w	r12b
#	101	r13	r13d	r13w	r13b
#	110	r14	r14d	r14w	r14b
#	111	r15	r15d	r15w	r15b
#		rip	eip			instruction pointer: address of the next instruction to execute.
#
# Note that the smallers registers uses the same space as the bigger ones. changing the small will affect the bigger
# These sub-registers are commonly used in instruction encoding and can be useful for optimizing code size.
#
# Extended registers:
#  Register Name	Size (bits)	Description
#  XMM0 - XMM15	128	Extended Multimedia Register (Streaming SIMD Extensions)
#  YMM0 - YMM15	256	Extended Multimedia Register (AVX Advanced Vector Extensions)
#  ZMM0 - ZMM31	512	Extended Multimedia Register (AVX-512 Advanced Vector Extensions 2)
#
# Note that YMM0-YMM15 are essentially the same as XMM0-XMM15,
# but with support for AVX (Advanced Vector Extensions) 
# instructions which operate on 256-bit operands. 
# ZMM0-ZMM31 are registers introduced in AVX-512 which support 512-bit operands.
#
. arch/system_call_linux_x86.sh

# THE REX PREFFIX:
#  REX prefix is optional, without it the code will be 32bit.
#  REX prefix determines the addressing size and extensions.
#
#  REX Bits:
#  |7|6|5|4|3|2|1|0|
#  |0|1|0|0|W|R|X|B|
#  W bit = Operand size 1==64-bits, 0 == legacy, depends on opcode.
#  R bit = Extends the ModR/M reg field to 4 bits. 0 selects RAX-RSI, 1 selects R8-R15
#  X bit = extends SIB 'index' field, same as R but for the SIB byte (memory operand)
#  B bit = extends the ModR/M r/m or 'base' field or the SIB field
#
rex(){
	local src=$1;
	local tgt=$2;
	local W=1;
	local R=0;	# 1 if source is a register from r8 to r15
	local X=0;
	local B=0;	# 1 if target(base) is a register from r8 to r15
	if is_r8_to_r15 "$src"; then
		R=1;
	fi;
	if is_r8_to_r15 "$tgt"; then
		B=1;
	fi;
	local v=$(printf "%02x" $(( (2#0100 << 4) + (W<<3) + (R<<2) + (X<<1) + B )) );
	code=$(echo -ne $v | xxd --ps -r | base64 -w0);
	echo -ne "$code";
}
	#    $(( (2#0100 << 4) + (1 << 3) +  ( target_is_r8_to_r15 << 2 ) + ( 0 << 1) + ( source_is_r8_to_r15 ) ))
# SIB byte
#  SIB stands for: Scale Index Base
#  The x64 the ModR/M can not handle all register/memory combinations
#  for example when you try to move the RSP to an memory address,
#  the RSP(100) is set to require an additional field the SIB is this additional field
#Register	Low 3 bits
RAX=0; # 000
RCX=1; # 001
RDX=2; # 010
RBX=3; # 011
RSP=4; # 100
RBP=5; # 101
RSI=6; # 110
RDI=7; # 111
R8=0; # 000
R9=1; # 001
R10=2; # 010
R11=3; # 011
R12=4; # 100
R13=5; # 101
R14=6; # 110
R15=7; # 111

#In the opcode "48 89 C6", the byte C6 is actually the ModR/M byte, which is divided into three fields:
#
#  The ModR/M's mod field indicates the addressing mode.
#    The first 2 bits (11) indicate the addressing mode.  In this case, 11 represents the register addressing mode. It means the instruction operates on registers directly, rather than accessing memory.
#       Check the constants MODRM_MOD_DISPLACEMENT_* below to see the domain
#    The next 3 bits (110) specify the destination register (which in this case is RSI).
#    The last 3 bits (000) specify the source register (which in this case is RAX).
#
# So, in summary, the ModR/M byte in the opcode "48 89 C6" indicates that we are using a register-to-register move instruction, with RSI as the destination register and RAX as the source register.
# MOV_RSP_RSI="$(rex | b64_to_hex_dump)${MOV_R}\x$( printf %x $(( MOVR + (RSI << 3) + RSP )) )"; # move the RSP to RSI #11000110
# MOV__RSP__RSI="$(rex | b64_to_hex_dump)\x8b\x34\x24"; # mov (%rsp), %rsp; # move value resolving pointer
# show_bytecode "MOV %RSI, (%RSP)"
#48893424
# show_bytecode "MOV %RSI, %RSP"
#4889f4

function push(){
	local reg="$1";
	local b2=$(( 16#50 + reg ));
	if is_r8_to_r15 "$reg"; then
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

MODRM_OPCODE_ADD=$(( 0 << 3 )) # 000
MODRM_OPCODE_OR=$((  1 << 3 )) # 001
MODRM_OPCODE_ADC=$(( 2 << 3 )) # 010
MODRM_OPCODE_SBB=$(( 3 << 3 )) # 011
MODRM_OPCODE_AND=$(( 4 << 3 )) # 100
MODRM_OPCODE_SUB=$(( 5 << 3 )) # 101
MODRM_OPCODE_XOR=$(( 6 << 3 )) # 110
MODRM_OPCODE_CMP=$(( 7 << 3 )) # 111

MODRM_REG_RAX=$(( RAX << 3 )); # 000 0
MODRM_REG_RCX=$(( RCX << 3 )); # 001 1
MODRM_REG_RDX=$(( RDX << 3 )); # 010 2
MODRM_REG_RBX=$(( RBX << 3 )); # 011 3
MODRM_REG_RSP=$(( RSP << 3 )); # 100 4
MODRM_REG_RBP=$(( RBP << 3 )); # 101 5
MODRM_REG_RSI=$(( RSI << 3 )); # 110 6
MODRM_REG_RDI=$(( RDI << 3 )); # 111 7
MODRM_REG_R8=$((  R8  << 3 )); # 000 0
MODRM_REG_R9=$((  R9  << 3 )); # 001 1
MODRM_REG_R10=$(( R10 << 3 )); # 010 2
MODRM_REG_R11=$(( R11 << 3 )); # 011 3
MODRM_REG_R12=$(( R12 << 3 )); # 100 4
MODRM_REG_R13=$(( R13 << 3 )); # 101 5
MODRM_REG_R14=$(( R14 << 3 )); # 110 6
MODRM_REG_R15=$(( R15 << 3 )); # 111 7
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
SUB_RSP_SHORT="$(rex v1 rsp| b64_to_hex_dump)\x83\xec"; # Subtract 1 byte(two complement) value from RSP
TEST="\x85"; # 10000101

# Here's a table with the 3-bit ModR/M values and their corresponding descriptions, including the value 101 for MOV RAX, imm:
# 3-bit	Description
# 000	Register (Direct)
# 001	Register (Indirect w/Disp8)
# 010	Register (Indirect w/Disp32)
# 011	Memory (SIB w/Disp32)
# 100	Register (Direct)
# 101	Immediate to register
# 110	Memory (Direct w/Disp32)
# 111	Register (Direct)
IMM="$(( 2#00111000 ))";
MOV_EDI_EDI="\x67\x8b\x3f";
# LEA - Load Effective Address (page 1146)
#LEAQ_RIP_RBX="$(rex | b64_to_hex_dump)\x8d\x1d\x00\x00\x00\x00";
LEA_RAX_RAX_4="\x8d\x04\x80";
LEA_V4_RDX="$(rex | b64_to_hex_dump)\x8d\x14\x25";
LEA_V4_RAX="$(rex | b64_to_hex_dump)\x8d\x04\x25";
LEA_V4_RCX="$(rex | b64_to_hex_dump)\x8d\x0c\x25";
MOV_ADDR4_RDX="$(rex | b64_to_hex_dump)\x8b\x14\x25"; # followed by 4 bytes le;
MOV_ADDR4_RAX="$(rex | b64_to_hex_dump)\x8b\x04\x25";
MOV_ADDR4_RSI="$(rex | b64_to_hex_dump)\x8b\x34\x25";
MOV_ADDR4_RDI="$(rex | b64_to_hex_dump)\x8b\x3c\x25";
MOV_V4_RAX="$(rex | b64_to_hex_dump)\xc7\xc0";
MOV_V4_RCX="$(rex | b64_to_hex_dump)\xc7\xc1";
MOV_V4_RDX="$(rex | b64_to_hex_dump)\xc7\xc2"; # MOV value and resolve address, so the content of memory address is set at the register
MOV_V4_RSI="$(rex | b64_to_hex_dump)\xc7\xc6";
MOV_V4_RDI="$(rex | b64_to_hex_dump)\xc7\xc7";
MOV_V8_RAX="$(rex | b64_to_hex_dump)$( printEndianValue $(( MOV + IMM + RAX )) ${SIZE_8BITS_1BYTE} )"; # 48 b8
MOV_V8_RDX="$(rex | b64_to_hex_dump)$( printEndianValue $(( MOV + IMM + RDX )) ${SIZE_8BITS_1BYTE} )"; # 48 ba
MOV_V8_RSI="$(rex | b64_to_hex_dump)$( printEndianValue $(( MOV + IMM + RSI )) ${SIZE_8BITS_1BYTE} )"; # 48 be
#debug MOV_RSI=$MOV_RSI
MOV_V8_RDI="$(rex | b64_to_hex_dump)$( printEndianValue $(( MOV + IMM + RDI )) ${SIZE_8BITS_1BYTE} )"; # 48 bf; #if not prepended with rex(x48) expect 32 bit register (edi: 4 bytes)
MOV_RAX_ADDR4="$(rex | b64_to_hex_dump)\x01\x04\x25";
MOV_RDX_ADDR4="$(rex | b64_to_hex_dump)\x89\x14\x25"; # followed by 4 bytes le;
MOV_R="\x89";
MOVSB="\xa4"; # move 64bits(8 bytes) from %rsi addr to %rdi addr
MOVSQ="$(rex | b64_to_hex_dump)\xa5"; # move 64bits(8 bytes) from %rsi addr to %rdi addr
CMP_RAX_RCX="$(rex | b64_to_hex_dump)\x39\xc1";
REP="\xf3"; # repeat until rcx

# show_bytecode "mov %rsp, %rsi"
# 4889e6
MOV_RAX_RSI="$(rex | b64_to_hex_dump)${MOV_R}$(printEndianValue $(( MOVR + MODRM_REG_RAX + RSI )) ${SIZE_8BITS_1BYTE})"; # xC6 move the rax to rsi #11000110
MOV_RAX_RDX="$(rex | b64_to_hex_dump)\x89\xc2";
MOV_RAX_RDI="$(rex | b64_to_hex_dump)${MOV_R}$(printEndianValue $(( MOVR + MOVRM_REG_RAX + RDI )) ${SIZE_8BITS_1BYTE} )";
MOV_RDX_RCX="$(rex | b64_to_hex_dump)\x89\xd1";
#MOV_RSP_RSI="$(rex | b64_to_hex_dump)${MOV_R}\xe6"; # Copy the RSP(pointer address) to the RSP(as a pointer address).
MOV_RSP_RAX="$(rex | b64_to_hex_dump)\x89\xe0";
MOV_RSP_RSI="$(rex | b64_to_hex_dump)${MOV_R}$( printEndianValue $(( MOVR + MODRM_REG_RSP + RSI )) ${SIZE_8BITS_1BYTE} )"; # move the RSP to RSI #11000110
MOV_RSP_RDX="$(rex | b64_to_hex_dump)${MOV_R}$( printEndianValue $(( MOVR + MODRM_REG_RSP + RDX )) ${SIZE_8BITS_1BYTE} )"; # move the RSP to RDX #11000010
MOV_RSP_RDI="$(rex | b64_to_hex_dump)\x89\xe7";
MOV_RSI_RAX="$(rex | b64_to_hex_dump)${MOV_R}$( printEndianValue $(( MOVR + MODRM_REG_RSI + RAX )) ${SIZE_8BITS_1BYTE} )"; # move the RSI to RDX #11110010
get_mov_rsp_addr()
{
	# MOV %RSP ADDR: 48892425 78100000 ? not tested
	# 48: rex_64bit
	# 89: MOV instruction
	# 24: 00100100 MOD/R
	# 25: 00100101 SBI
	# 78100000: little endian 32bit addr
	rex="$(rex | b64_to_hex_dump)";
	INSTR_MOV="\x89";
	MOD_RM="$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_RSP + RSP )) ${SIZE_8BITS_1BYTE} )";
	SBI=$(printEndianValue $(( 2#00100101 )) ${SIZE_8BITS_1BYTE});
	echo -n "${rex}${INSTR_MOV}${MOD_RM}${SBI}";
}
get_mov_rsi_addr()
{
	# MOV %RSP ADDR: 48892425 78100000 ? not tested
	# 48: rex_64bit
	# 89: MOV instruction
	# 24: 00100100 MOD/R
	# 25: 00100101 SBI
	# 78100000: little endian 32bit addr
	rex="$(rex | b64_to_hex_dump)";
	INSTR_MOV="\x89";
	MOD_RM="$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_RSI + RSI )) ${SIZE_8BITS_1BYTE} )";
	SBI=$(printEndianValue $(( 2#00110101 )) ${SIZE_8BITS_1BYTE});
	#echo -n "${rex}${INSTR_MOV}${MOD_RM}${SBI}";
	echo -n "$(rex | b64_to_hex_dump)\x89\x34\x25";
}
MOV_RSP_ADDR4=$(get_mov_rsp_addr);
MOV_RSI_ADDR4=$(get_mov_rsi_addr);
MOV_RSI_RDX="$(rex | b64_to_hex_dump)${MOV_R}$( printEndianValue $(( MOVR + MODRM_REG_RSI + RDX )) ${SIZE_8BITS_1BYTE} )"; # move the RSI to RDX #11110010
SUB_V1_RAX="$(rex | b64_to_hex_dump)\x83\xe8";

is_register(){
	local v="$1";
	if [ "$(eval echo '${'${v^^}'}')" == "" ]; then
		return 1
	fi;
	return 0;
}

is_r8_to_r15(){
	local reg="$1";
	if [[ "${reg,,}" =~ r([8-9]|1[0-5]) ]]; then
		return 0;
	fi;
	return 1;
}

# add: given a value or a register on r1, add it to r2
# r1: can be a register id, a integer value or a address value
# 	input: register or "[address]" or integer value
# 	output: not changed
# r2: register result of add r1 and r2
# 	input: register
# 	output: added r1 and r2
ADD_FULL="\x81"; # ADD 32 or 64 bit operand (depend on ModR/M
ADD_M64="$(rex | b64_to_hex_dump)${ADD_FULL}";
ADD_M64_RDI="${ADD_M64}";
ADD_EAX_EAX="\x01\xc0";
ADD_RSI_RDX="$(rex | b64_to_hex_dump)\x01\xF2";
ADD_V4_RDX="$(rex | b64_to_hex_dump)\x81\xC2";
ADD_V4_RDI="$(rex | b64_to_hex_dump)\x81\xC7";
ADD_R15_R14="$(rex r15 r14 | b64_to_hex_dump)\x01\xfe";
ADD_R15_RAX="$(rex r15 rax | b64_to_hex_dump)\x01\xF8";
ADD_R15_RSI="$(rex r15 rsi | b64_to_hex_dump)\x01\xFE";
ADD_RCX_R8="$(rex rcx r8 | b64_to_hex_dump)\x01\xc8";
ADD_RDX_R8="$(rex rdx r8 | b64_to_hex_dump)\x01\xd0";
ADD_R8_RDI="$(rex r8 rdi | b64_to_hex_dump)\x01\xc7";
add(){
	local ADD_SHORT="\x83"; # ADD 8 or 16 bit operand (depend on ModR/M opcode first bit(most significant (bit 7)) been zero) and the ModR/M opcode
	local r1="$1";
	local r2="$2";
	local code="";
	local p=$(rex "$r1" "$r2" | b64_to_hex_dump);
	if [ "$r2" = "AL" ]; then
		ADD_AL="\x04";
		code="${code}${ADD_AL}$(printEndianValue "$r1" ${SIZE_8BITS_1BYTE})";
		echo -en "${code}" | base64 -w0;
		return
	fi;
	if is_register "$r1"; then
	{
		if is_register "$r2"; then
			code="ADD";
			echo -en "${code}" | base64 -w0;
			return;
		fi;
	}
	elif is_valid_number "$r1"; then
	{
		if is_register "$r2"; then
			if [ $r1 -lt 128 ]; then
				r=$(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_ADD + ${r2^^} ))
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

INC_RDX="$(rex | b64_to_hex_dump)\xff\xc2";
DEC_RDI="$(rex | b64_to_hex_dump)\xff\xcf";
MOV_V4_R14="$(rex v4 r14 | b64_to_hex_dump)\xC7\xC6";
XOR_R15_R15="\x4D\x31\xFF";
MOV_RSP_R14="$(rex rsp r14 | b64_to_hex_dump)\x89\xe6";
MOV_R14_ADDR4="$(rex r14 addr4| b64_to_hex_dump)\x89\x34\x25";
MOV_RESOLVE_ADDRESS="\x8b"; # Replace the address pointer with the value pointed from that address
# MOV_RESOLVE_ADDRESS needs the ModR/M mod (first 2 bits) to be 00.
MODRM="$(printEndianValue "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_RDI + RAX))" $SIZE_8BITS_1BYTE)";
#MOV_RAX_RAX="$(rex | b64_to_hex_dump)${MOV_RESOLVE_ADDRESS}${MODRM}";
MOV_RAX_RAX="$(rex | b64_to_hex_dump)\x8b\x00";
MOV_RCX_RCX="$(rex | b64_to_hex_dump)\x8b\x09";
MODRM="$(printEndianValue "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_RSI + RSI))" $SIZE_8BITS_1BYTE)";
MOV_RSI_RSI="$(rex | b64_to_hex_dump)${MOV_RESOLVE_ADDRESS}${MODRM}"; # mov (%rsi), %rsi
MODRM="$(printEndianValue "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_RDX + RDX))" $SIZE_8BITS_1BYTE)";
MOV_RDX_RDX="$(rex | b64_to_hex_dump)${MOV_RESOLVE_ADDRESS}${MODRM}";
MODRM="$(printEndianValue "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_RDI + RDI))" $SIZE_8BITS_1BYTE)";
MOV_RDI_RDI="$(rex | b64_to_hex_dump)${MOV_RESOLVE_ADDRESS}${MODRM}";
MOV_RDI_ADDR4="$(rex | b64_to_hex_dump)\x89\x3C\x25";

# show_bytecode "movq (%rsp), %rsi"
# 488b3424
# MOV_VALUE_RSI_RSP="$(rex | b64_to_hex_dump)\x8b\x34\x24"; # Copy the RSP(pointer value, not address) to the RSI(as a integer value).

# while $(rex | b64_to_hex_dump) is used for first 8 register, the last 8 register use \x49
MOV_RAX_R8="$(rex rax r8| b64_to_hex_dump)${MOV_R}$(printEndianValue $(( MOVR + MODRM_REG_RAX + R8 )) ${SIZE_8BITS_1BYTE})";
MOV_RAX_R9="$(rex rax r9| b64_to_hex_dump)\x89\xc1"; # move the size read to r9
MOV_R8_RDI="$(rex r8 rdi | b64_to_hex_dump)\x89\xc7";
MOV_R8_RDX="$(rex r8 rdx | b64_to_hex_dump)\x89$(printEndianValue $(( MOVR + MODRM_REG_R8 + RDX )) ${SIZE_8BITS_1BYTE})";
MOV_R9_RDI="$(rex r9 rdi | b64_to_hex_dump)\x89$(printEndianValue $(( MOVR + MODRM_REG_R9 + RDI )) ${SIZE_8BITS_1BYTE})";
MOV_R9_RDX="$(rex r9 rdx | b64_to_hex_dump)\x89$(printEndianValue $(( MOVR + MODRM_REG_R9 + RDX )) ${SIZE_8BITS_1BYTE})";
MOV_V8_R8="$(rex v8 r8 | b64_to_hex_dump)\xB8";
MOV_V8_R9="$(rex v8 r9 | b64_to_hex_dump)\xB9";
MOV_V8_R10="$(rex v8 r10 | b64_to_hex_dump)\xBA";

# XOR is useful to set zero at registers using less bytes in the instruction
# Here's an table with the bytecodes for XORing each 64-bit register with zero:
# Register	Assembly	Bytecode
# RAX	xor rax, rax	48 31 C0
# RBX	xor rbx, rbx	48 31 DB
# RCX	xor rcx, rcx	48 31 C9
# RDX	xor rdx, rdx	48 31 D2
# RSI	xor rsi, rsi	48 31 F6
# RDI	xor rdi, rdi	48 31 FF
# RBP	xor rbp, rbp	48 31 E5
# RSP	xor rsp, rsp	48 31 EC
# R8	xor r8, r8	4D 31 C0
# R9	xor r9, r9	4D 31 C9
# R10	xor r10, r10	4D 31 D2
# R11	xor r11, r11	4D 31 DB
# R12	xor r12, r12	4D 31 E4
# R13	xor r13, r13	4D 31 ED
# R14	xor r14, r14	4D 31 F6
# R15	xor r15, r15	4D 31 FF
XOR_RAX_RAX="$(rex | b64_to_hex_dump)\x31\xc0";
XOR_RDX_RDX="$(rex | b64_to_hex_dump)\x31\xd2";
XOR_RSI_RSI="$(rex | b64_to_hex_dump)\x31\xf6";
XOR_RDI_RDI="$(rex | b64_to_hex_dump)\x31\xff";
XOR_R8_R8="$(rex r8 r8 | b64_to_hex_dump)\x31\xc0";
XOR_R10_R10="$(rex r10 r10 | b64_to_hex_dump)\x31\xd2";

# CMP
CMP="$(rex | b64_to_hex_dump)\x83"; # only if most significant bit(bit 7) of the next byte is 1 and depending on opcode(bits 6-3) And ModR/M opcode
CMP_RAX_V1="${CMP}$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_CMP + RAX )) $SIZE_8BITS_1BYTE)";
CMP_RSI_V1="${CMP}$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_CMP + RSI )) $SIZE_8BITS_1BYTE)";

# JMP
# We have some types of jump
# Relative jumps (short and near):
JMP_V1="\xeb"; # followed by a 8-bit signed char (-128 to 127) to move relative to BIP.
JMP_V4="\xe9"; # followed by a 32-bit signed integer(-2147483648 to 2147483647).
# Jump to the full virtual address
JMP_RAX="\xff";
JMP_RDI="\xe0";
JNE="\x0f\x85"; # The second byte "85" is the opcode for the JNE(Jump if Not Equal) same of JNZ(Jump if Not Zero) instruction. The following four bytes "06 00 00 00" represent the signed 32-bit offset from the current instruction to the target label.
JZ="\x0f\x84";
JG="\x0F\x8F"; # Jump if Greater than zero



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
	CODE="${CODE}${MOV_V4_RAX}$(printEndianValue $SYS_CLOSE ${SIZE_32BITS_4BYTES})";
	CODE="${CODE}${SYSCALL}";
	echo -en "${CODE}" | base64 -w0;
}

# stat get information of a file
sys_stat()
{
	local CODE="";
	local FD="$1";
	if [ "$FD" != "" ]; then
		CODE="${CODE}${MOV_V4_RAX}$(printEndianValue $FD ${SIZE_32BITS_4BYTES})";
	else
		# ; we will default to use rax as input. (normally used after a open, so)
		# mov rdi, rax        ; File descriptor returned by the open syscall
		CODE="${CODE}${MOV_RAX_RDI}"
	fi
	# mov rax, 0x9c       ; System call number for fstat
	CODE="${CODE}${MOV_V4_RAX}$(printEndianValue $((16#9c)) ${SIZE_32BITS_4BYTES})"
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
	# RDI: File descriptor number
	if [ "${fd}" != "" ]; then
		CODE="${CODE}${MOV_V8_RDI}$(printEndianValue $fd ${SIZE_64BITS_8BYTES})";
	else
		# if no fd providen use rax by default
		CODE="${CODE}${MOV_RAX_RDI}";
		# TODO not sure this is a good idea but we will lost rax so for 
		# now we will save it at r8 too
		CODE="${CODE}${MOV_RAX_R8}";
	fi;
 	# RSI: Pointer to a struct stat (will be filled with file information)
 	CODE="${CODE}${MOV_V8_RSI}$(printEndianValue ${stat_addr} $SIZE_64BITS_8BYTES)";
	# RAX: fstat
	CODE="${CODE}${MOV_V4_RAX}$(printEndianValue $SYS_FSTAT ${SIZE_32BITS_4BYTES})";
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
	code="${code}${MOV_V8_RSI}$(printEndianValue $(( STAT_ADDR + st_size )) ${SIZE_64BITS_8BYTES})";
	code="${code}${MOV_RSI_RSI}"; # resolve pointer to address
	local default_value_code="${MOV_V8_RSI}$(printEndianValue "$PAGESIZE" $SIZE_64BITS_8BYTES)"
	code="${code}${CMP_RSI_V1}\x00"; # 64bit cmp rsi, 00
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
	CODE="${CODE}${MOV_V4_RAX}$(printEndianValue $((16#3f)) $SIZE_32BITS_4BYTES)"; # syscall
	CODE="${CODE}${MOV_RDI_ADDR4}$(printEndianValue $((16#18)) $SIZE_32BITS_4BYTES)"; # _SC_PAGESIZE
	CODE="${CODE}${XOR_RSI_RSI}"; # zeroes unused RSI
	CODE="${CODE}${SYSCALL}"; # 
	return;
}

PAGESIZE=$(( 4 * 1024 )); # 4KiB
# map a memory region
#|RAX|syscall___________________|RDI______________|RSI________________|RDX________________|R10________________|R8_______________|R9________|
#| 9 |sys_mmap                  |unsigned long    |unsigned long len  |int prot           |int flags          |int fd           |long off  |
# Returns:
#  RAX Memory Address
#  R8 FD
#  R9 Size
function sys_mmap()
{
	local size="$1";
	local fd="$2";
	local CODE="";
	# ; Map the memory region
	# mov rdi, 0     ; addr (let kernel choose)
	CODE="${CODE}${XOR_RDI_RDI}";
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
	debug "sys_mmap size=$size"
	local mmap_size_code="$(echo "$size" | b64_to_hex_dump)";
	# CODE="${CODE}${MOV_RSI}$(printEndianValue ${mmap_size} ${SIZE_64BITS_8BYTES})";
	#if pagesize > size {
	#	pagesize
	#} else {
	#	(1+(requested size / pagesize)) * pagesize
	#}
	#CODE="${CODE}${MOV_RSI}$(printEndianValue ${PAGESIZE} ${SIZE_64BITS_8BYTES})";
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
	CODE="${CODE}${MOV_V4_RDX}$(printEndianValue $(( PROT_READ + PROT_WRITE )) ${SIZE_32BITS_4BYTES})";
	# man mmap for valid flags
	#    mov r10, 2    ; flags
	MAP_SHARED=1;
	MAP_PRIVATE=2;
	MAP_SHARED_VALIDATE=3;
	MAP_ANONYMOUS=$((2#00100000));
	CODE="${CODE}${MOV_V8_R10}$(printEndianValue $(( MAP_PRIVATE )) ${SIZE_64BITS_8BYTES})";
	
	# The file descriptor is expected to be at R8,
	# but for virtual files it will fail with a -19 at rax.
	# 
	if [ "$fd" == "rax" ]; then
		CODE="${CODE}${MOV_RAX_R8}";
	elif [ "$fd" != "" ]; then
		CODE="${CODE}${MOV_V8_R8}$(printEndianValue $fd ${SIZE_64BITS_8BYTES})";
	fi;
	#CODE="${CODE}${XOR_R8_R8}";
	#    mov r9, 0     ; offset
	CODE="${CODE}${MOV_V8_R9}$(printEndianValue 0 ${SIZE_64BITS_8BYTES})";
	#    mov rax, 9    ; mmap system call number
	CODE="${CODE}${MOV_V8_RAX}$(printEndianValue $SYS_MMAP ${SIZE_64BITS_8BYTES})";
	CODE="${CODE}${SYSCALL}";
	# test rax to detect failure
	CODE="${CODE}${CMP_RAX_V1}\x00"; # 64bit cmp rax, 00
	# if it fails do mmap with  MAP_ANONYMOUS
	local ANON_MMAP_CODE="${MOV_V8_R10}$(printEndianValue $(( MAP_PRIVATE + MAP_ANONYMOUS )) ${SIZE_64BITS_8BYTES})";
	ANON_MMAP_CODE="${ANON_MMAP_CODE}${MOV_V8_RAX}$(printEndianValue $SYS_MMAP ${SIZE_64BITS_8BYTES})";
	ANON_MMAP_CODE="${ANON_MMAP_CODE}${SYSCALL}";
	# then we need to read the data to that location
	ANON_MMAP_CODE="${ANON_MMAP_CODE}${MOV_R8_RDI}";
	ANON_MMAP_CODE="${ANON_MMAP_CODE}$(system_call_read "" "rsi" | b64_to_hex_dump)"; # TODO not sure the best choice here. We should do it better
	# if rax > 0 jump over this code block
	# rax will be less than zero on failure
	ANON_MMAP_CODE="${ANON_MMAP_CODE}${MOV_RAX_R9}";
	# By default the sys_read will move the memory address from rax to rsi.
	ANON_MMAP_CODE="${ANON_MMAP_CODE}${MOV_RSI_RAX}"; # restore rax to return the memory address
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
	local TARGET_ADDR="$1";
	local CURRENT_ADDR="$2";
	local RELATIVE=$(( TARGET_ADDR - CURRENT_ADDR ));
	local code="";
	if [ ! "$(( (RELATIVE >= -128) && (RELATIVE <= 127) ))" -eq 1 ]; then
		debug "displacement too big to jump short.";
		return;
	fi;
	# debug jump short relative $RELATIVE
	local RADDR_V="$(printEndianValue "$RELATIVE" $SIZE_8BITS_1BYTE )";
	# debug jump short to RADDR_V=[$( echo -n "$RADDR_V" | xxd)]
	code="${code}${JMP_V1}${RADDR_V}";
	echo -ne "$(echo -en "${code}" | base64 -w0)";
	return
}

# jump should receive the target address and the current BIP.
#   It will select the correct approach for each context based on the JMP alternatives
function jump()
{
	local TARGET_ADDR="$1";
	local CURRENT_ADDR="$2";
	# debug "jump: TARGET_ADDR:[$(printf %x $TARGET_ADDR)], CURRENT_ADDR:[$( printf %x ${TARGET_ADDR})]"
	local OPCODE_SIZE=1;
	local DISPLACEMENT_BITS=32; # 4 bytes
	local JUMP_NEAR_SIZE=$(( OPCODE_SIZE + DISPLACEMENT_BITS / 8 )); # 5 bytes

	local short_jump_response=$(bytecode_jump_short "$TARGET_ADDR" "${CURRENT_ADDR}")
	if [ "$(echo -n "${short_jump_response}" | base64 -d | wc -c)" -gt 0 ];then
		# debug short jump succeed;
		echo -n "${short_jump_response}";
		return;
	fi;
	# debug jump, unable to short, trying near: $short_jump_response
	#bytecode_jump_near
	local RELATIVE=$(( TARGET_ADDR - CURRENT_ADDR ))
	if [ "$(( (RELATIVE >= - ( 1 << 31 )) && (RELATIVE <= ( 1 << 31 ) -1) ))" -eq 1 ]; then
		# jump near
		local RADDR_V;
		RADDR_V="$(printEndianValue "${RELATIVE}" $SIZE_32BITS_4BYTES)";
		# debug "jump near relative ( $RELATIVE, $RADDR_V )";
		CODE="${CODE}${JMP_V4}${RADDR_V}";
		echo -ne "$(echo -en "${CODE}" | base64 -w0)";
		return;
	fi;

	error "JMP not implemented for that relative or absolute value: $RELATIVE"
	# TODO, another way to move to a location is set the RIP directly
	# something like
	# mov eax, $address
	# mov [rsp], eax
	# mov eip, [rsp]
	echo -ne ",0"
	return;
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
		local array_code="$XOR_R15_R15";
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
			code="${code}${MOV_RDI_ADDR4}$(printEndianValue $retval_addr $SIZE_32BITS_4BYTES)";
		fi;
		echo -en "$code" | base64 -w0;
		return;
	fi;
	error "call not implemented for this address size: CURRENT: $CURRENT, TARGET: $TARGET, RELATIVE: $RELATIVE";

	FAR_CALL="\x9a";
	MODRM="$(printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_SUB + RSP )) $SIZE_8BITS_1BYTE)";
	SUB_RSP="$(rex | b64_to_hex_dump)${SUB_IMMSE8}${MODRM}\x28" # sub rsp, x28
	addr="$(( 16#000100b8 ))"
	BYTES="\xe8${CALL_ADDR}";
	code="${code}${BYTES}";
	if [ "$retval_addr" != "" ]; then
		code="${code}${MOV_RDI_ADDR4}$(printEndianValue $retval_addr $SIZE_32BITS_4BYTES)";
	fi;
	echo -en "$code" | base64 -w0;
}

function push_v_stack()
{
	local value="$1";
	local code="";
	code="${code}${MOV_V4_RAX}$(printEndianValue "${value}" "${SIZE_32BITS_4BYTES}")";
	code="${code}$(push RAX | b64_to_hex_dump)";
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
		code="${code}${MOV_V4_RDI}$(printEndianValue ${symbol_value:=0} $SIZE_32BITS_4BYTES)"
		if [ "$symbol_type" != $SYMBOL_TYPE_HARD_CODED ]; then
			code="${code}${MOV_RDI_RDI}";
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
	CODE="${CODE}${MOV_V8_RAX}$(printEndianValue ${SYS_OPEN} "${SIZE_64BITS_8BYTES}")";
	# mov rdi, filename ; File name
	local FILENAME_ADDR="$(printEndianValue "${filename}" "${SIZE_64BITS_8BYTES}" )";
	CODE="${CODE}${MOV_V8_RDI}${FILENAME_ADDR}";
	# TODO best to use xor when setting rsi to 0
	# mov rsi, 'r' ; Open mode
	CODE="${CODE}${MOV_V8_RSI}$(printEndianValue $(( 16#0 )) "${SIZE_64BITS_8BYTES}")"; # mode=r (x72)
	# xor rdx, rdx ; File permissions (ignored when opening)
	#CODE="${CODE}${XOR}${RDX}${RDX}"
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
		# now we create a buffer with mmap using this fd in RAX.
		CODE="${CODE}$(sys_mmap "${DATA_LEN}" | b64_to_hex_dump)";
		CODE="${CODE}${MOV_RAX_ADDR4}$(printEndianValue "$targetMemory" $SIZE_32BITS_4BYTES)";
		# TODO test sys_mmap return at rax, and if fails(<0) then mmap without the fd
		# TODO once mmap set, if the source file is read only we can just close it.
		# then the fd should be at eax and r8
		#
		# TODO:
		# collect $RAX (memory location returned from mmap)
		# use it as argument to write out.
		echo -en "${CODE}" | base64 -w0;
		return;
	elif [ "${TYPE}" == ${SYMBOL_TYPE_DYNAMIC} ]; then
		if [ "$(echo -n "${DATA_ADDR_V}" | base64 -d | cut -d, -f1 | base64 -w0)" == "$( echo -n ${ARCH_CONST_ARGUMENT_ADDRESS} | base64 -w0)" ]; then
			# now we create a buffer with mmap using this fd in RAX.
			CODE="${CODE}$(sys_mmap | b64_to_hex_dump)";
			# collect $RAX (memory location returned from mmap)
			# use it as argument to write out.
			CODE="${MOV_RAX_ADDR4}$(printEndianValue "$targetMemory" $SIZE_32BITS_4BYTES)";
			CODE="${CODE}${MOV_RAX_RSI}";
			CODE="${CODE}${MOV_V8_RAX}$(printEndianValue $SYS_WRITE $SIZE_64BITS_8BYTES)";
			STDOUT=1;
			CODE="${CODE}${MOV_V8_RDI}$(printEndianValue $STDOUT $SIZE_64BITS_8BYTES)";
			CODE="${CODE}${MOV_V8_RDX}$(printEndianValue "${DATA_LEN}" $SIZE_64BITS_8BYTES)";
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
		CODE="${CODE}${MOV_V8_RDI}$(printEndianValue $FD $SIZE_64BITS_8BYTES)";
	fi
	if [ "$len" == "rsi" ]; then
		CODE="${CODE}${MOV_RSI_RDX}";
	else
		CODE="${CODE}${MOV_V8_RDX}$(printEndianValue ${len} $SIZE_64BITS_8BYTES)";
	fi;
	if [ "$DATA_ADDR" == "" ]; then
		#use rax
		CODE="${CODE}${MOV_RAX_RSI}";
	else
		CODE="${CODE}${MOV_V8_RSI}$(printEndianValue "$DATA_ADDR" "$SIZE_64BITS_8BYTES" )";
	fi;
	CODE="${CODE}${MOV_V8_RAX}$(printEndianValue $SYS_READ $SIZE_64BITS_8BYTES)";
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
	CODE="${CODE}${MOV_V8_RAX}$(printEndianValue $SYS_WRITE $SIZE_64BITS_8BYTES)";
	CODE="${CODE}${MOV_V8_RDI}$(printEndianValue $OUT $SIZE_64BITS_8BYTES)";
	CODE="${CODE}${MOV_V8_RSI}${DATA_ADDR}";
	CODE="${CODE}${MOV_V8_RDX}$(printEndianValue "${DATA_LEN}" $SIZE_64BITS_8BYTES)";
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
	# to find the arg size, use rdx as RSI
	CODE="${CODE}${MOV_RSI_RDX}";
	# increment RDX by 8
	ARGUMENT_DISPLACEMENT=8
	CODE="${CODE}$(add $ARGUMENT_DISPLACEMENT rdx | b64_to_hex_dump)";
	# mov to the real address (not pointer to address)
	ModRM=$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_REG_RSI + RDX )) ${SIZE_8BITS_1BYTE} )
	SUB_RDX_RSI="$(rex | b64_to_hex_dump)${SUB_R}${ModRM}";
	CODE="${CODE}${MOV_RSI_RSI}"; # resolve pointer to address
	CODE="${CODE}${MOV_RDX_RDX}"; # resolve pointer to address
	# and subtract RDX - RSI (resulting in the result(str len) at RDX)
	CODE="${CODE}${SUB_RDX_RSI}";
	echo -n "${CODE}";
}

# how dinamically discover the size?
# one way is to increment the pointer, then subtract the previous pointer, this is fast but this is only garanteed to work in arrays of data, where the address are in same memory block. see detect_argsize
# another way is to count the bytes until find \x00. but this will block the possibility of write out the \x00 byte. this is what bash does. despite slower and the side effect of not allowing \x00, it is safer.
function detect_string_length()
{
	local code="";
	#code="${code}${XOR_RDX_RDX}"; # ensure rdx = 0
	code="${code}${MOV_RSI_RDX}"; # let's use rdx as rsi incrementing it each loop interaction
	# save rip
	# leaq (%rip), %rbx # 
	#code=${code}${LEAQ_RIP_RBX};
	# get the data byte at addr+rdx into rax
	MOV__RDX__RAX="$(rex | b64_to_hex_dump)\x0f\xb6\x02"; # movzbq (%rdx), %rax
	code="${code}${MOV__RDX__RAX}"; # resolve current rdx pointer to rax
	#MOV_DATA_RAX="$(rex | b64_to_hex_dump)\x0f\xb6\x06"; # movzbq (%rsi), %rax
	#code="${code}${MOV_DATA_RAX}";
	TEST_RAX_RAX="$(rex | b64_to_hex_dump)\x85\xc0";
	# inc rdx
	code="${code}${INC_RDX}";
	# test data byte
	TEST_AL="\x84\xc0";
	# loop back if not null
	code="${code}${TEST_AL}";
	# jz
	# "ebfe" # jump back 0 bytes
	JUMP_BACK_BYTES="\x7f\xf5"; # jg .-9; Jump back 9 bytes only if AL > 0
	code="${code}${JUMP_BACK_BYTES}";
	DEC_RDX="$(rex | b64_to_hex_dump)\xff\xca";
	code="${code}${DEC_RDX}";
	# sub %rsi, %rdx
	SUB_RSI_RDX="$(rex | b64_to_hex_dump)\x29\xf2";
	code="${code}${SUB_RSI_RDX}";
	#JMP_RBX="\xff\x23";
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
	if [ "$DATA_ADDR_V" == "RAX" ]; then
		code="${code}${MOV_RAX_RSI}";
	else
		code="${code}${MOV_ADDR4_RSI}$(printEndianValue ${DATA_ADDR_V} ${SIZE_32BITS_4BYTES})";
	fi
	if [ "${DATA_LEN}" == "0" ]; then
		code="${code}$(detect_string_length)";
	else
		local MOV_V_RDX="${MOV_V8_RDX}$(printEndianValue "${DATA_LEN}" ${SIZE_64BITS_8BYTES})";
		code="${code}${MOV_V_RDX}";
	fi;
	code="${code}${MOV_V8_RDI}$(printEndianValue $OUT $SIZE_64BITS_8BYTES)";
	code="${code}${MOV_V8_RAX}$(printEndianValue $SYS_WRITE $SIZE_64BITS_8BYTES)";
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
		code="${code}${MOV_V4_RAX}$(printEndianValue $SYS_WRITE $SIZE_32BITS_4BYTES)";
		code="${code}${MOV_V4_RDI}$(printEndianValue $OUT $SIZE_32BITS_4BYTES)";
		code="${code}${MOV_RSP_RSI}";
		code="${code}${MOV_V4_RDX}$(printEndianValue "8" $SIZE_32BITS_4BYTES)";
		code="${code}${SYSCALL}";
		code="${code}$(pop RAX | b64_to_hex_dump)";
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
		code="${code}${MOV_V8_RAX}$(printEndianValue $SYS_WRITE $SIZE_64BITS_8BYTES)";
		code="${code}${MOV_R9_RDX}"
		code="${code}${MOV_V8_RDI}$(printEndianValue $OUT $SIZE_64BITS_8BYTES)";
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
	code="${code}${MOV_V4_RAX}$(printEndianValue $SYS_EXIT $SIZE_32BITS_4BYTES)";
	code="${code}${MOV_V4_RDI}$(printEndianValue ${exit_code:=0} $SIZE_32BITS_4BYTES)"
	if [ "$symbol_type" != $SYMBOL_TYPE_HARD_CODED ]; then
		code="${code}${MOV_RDI_RDI}";
	fi;
	code="${code}${SYSCALL}"
	echo -en "${code}" | base64 -w0;
}

function system_call_fork()
{
	local SYS_FORK=57
	local CODE="";
	CODE="${CODE}${MOV_V4_RAX}$(printEndianValue ${SYS_FORK} ${SIZE_32BITS_4BYTES})";
	CODE="${CODE}${SYSCALL}";
	echo -en "${CODE}" | base64 -w0;
	echo -en ",$(echo -en "${CODE}" | wc -c )";
}

function system_call_pipe()
{
	local pipe_addr="$1";
	local sys_pipe=22;
	local code="";
	code="${code}${MOV_V4_RAX}$(printEndianValue "${sys_pipe}" "$SIZE_32BITS_4BYTES")";
	code="${code}${MOV_V4_RDI}$(printEndianValue "${pipe_addr}" "$SIZE_32BITS_4BYTES")";
	code="${code}${SYSCALL}";
	echo -en "${code}" | base64 -w0;
}

function system_call_wait4()
{
	local sys_wait4=61;
	local code="";
	code="${code}${MOV_V4_RAX}$(printEndianValue ${sys_wait4} ${SIZE_32BITS_4BYTES})"
	# printEndianValue seems buggy with negative values
	#wait_code="${wait_code}${MOV_V4_RDI}$(printEndianValue -1 ${SIZE_32BITS_4BYTES}) ";# pid_t pid
	# so lets change to decrement rdi
	code="${code}${XOR_RDI_RDI}${DEC_RDI}";
	code="${code}${XOR_RSI_RSI}";# int __user *stat_addr
	code="${code}${XOR_RDX_RDX}";# int options
	code="${code}${XOR_R10_R10}";# struct rusage
	code="${code}${SYSCALL}";
	echo -en "${code}" | base64 -w0;
}

function system_call_dup2()
{
	local old_fd_addr="$1"; # where in memory we have the int value of the fd
	local new_fd="$2";
	local sys_dup2=33;
	local code="";
	code="${code}${MOV_V4_RAX}$(printEndianValue "${sys_dup2}" "${SIZE_32BITS_4BYTES}")";
	code="${code}${MOV_V4_RDI}$(printEndianValue "${old_fd_addr}" "${SIZE_32BITS_4BYTES}")";
	code="${code}${MOV_RDI_RDI}";
	code="${code}${MOV_V4_RSI}$(printEndianValue "${new_fd}" "${SIZE_32BITS_4BYTES}")";
	code="${code}${SYSCALL}";
	echo -en "${code}" | base64 -w0;
}

function system_call_exec()
{
	#TODO we need to map some memory, or use a mapped memory space to store the arrays bytes;
	local PTR_ARGS="$1";
	local args=()
	eval "args=( $2 )"
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
		read_pipe="${read_pipe}${MOV_V4_RAX}$(printEndianValue "${SYS_READ}" "${SIZE_32BITS_4BYTES}")";
		read_pipe="${read_pipe}${MOV_V4_RDI}$(printEndianValue "${pipe_in}" "${SIZE_32BITS_4BYTES}")${MOV_EDI_EDI}"; # fd
		read_pipe="${read_pipe}${MOV_V4_RSI}$(printEndianValue "${pipe_buffer_addr}" "${SIZE_32BITS_4BYTES}")"; # buff
		read_pipe="${read_pipe}${MOV_RSI_ADDR4}$(printEndianValue "$((pipe_buffer_addr - 8))" "${SIZE_32BITS_4BYTES}")"; # set the pointer to the buffer allowing concat to work
		read_pipe="${read_pipe}${MOV_V4_RDX}$(printEndianValue "${pipe_buffer_size}" "${SIZE_32BITS_4BYTES}")"; # count
		read_pipe="${read_pipe}${SYSCALL}";
	fi;

	local exec_code="";
	# set the args array in memory
	local argc=${#args[@]}
	debug "exec args=$argc = [${args[@]}] == [$2]"
	debug "exec staticmap=${#static_map[@]} = [${static_map[@]}] == [$3]"
	for (( i=0; i<${argc}; i++ ));
	do {
		exec_code="${exec_code}${MOV_V8_RAX}$(printEndianValue "${args[$i]}" "${SIZE_64BITS_8BYTES}")";
		if [ "${static_map[$i]}" == 0 ]; then # it's a dynamic command, resolve it
			exec_code="${exec_code}${MOV_RAX_RAX}";
		fi;
		exec_code="${exec_code}${MOV_RAX_ADDR4}$(printEndianValue "$(( PTR_ARGS + i*8 ))" "${SIZE_32BITS_4BYTES}")";
	}; done
	exec_code="${exec_code}${XOR_RAX_RAX}";
	exec_code="${exec_code}${MOV_RAX_ADDR4}$(printEndianValue $(( PTR_ARGS + ${#args[@]} * 8 )) ${SIZE_32BITS_4BYTES})";
	exec_code="${exec_code}${MOV_V8_RDI}$(printEndianValue ${args[0]} ${SIZE_64BITS_8BYTES})";
	if [ "${static_map[0]}" == 0 ]; then # it's a dynamic command, resolve it
		exec_code="${exec_code}${MOV_RDI_RDI}";
	fi;

	exec_code="${exec_code}${MOV_V8_RSI}$(printEndianValue ${PTR_ARGS:=0} ${SIZE_64BITS_8BYTES})"

	exec_code="${exec_code}${MOV_V8_RDX}$(printEndianValue ${PTR_ENV:=0} ${SIZE_64BITS_8BYTES})" # const char *const envp[]

	exec_code="${exec_code}${MOV_V8_RAX}$(printEndianValue ${SYS_EXECVE} ${SIZE_64BITS_8BYTES})" # sys_execve (3b)

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
	fork_code="${fork_code}${CMP_RAX_V1}\x00"; # 64bit cmp rax, 00
	# rax will be zero on child, on parent will be the pid of the forked child
	# so if non zero (on parent) we will jump over the sys_execve code to not run it twice,
	# and because it will exit after run
	CODE_TO_JUMP="$(printEndianValue "$(echo -en "${dup2_child}${exec_code}" | wc -c)" ${SIZE_32BITS_4BYTES})" # 45 is the number of byte instructions of the syscall sys_execve (including the MOV (%rdi), %rdi.
	fork_code="${fork_code}${JNE}${CODE_TO_JUMP}"; # The second byte "85" is the opcode for the JNE instruction. The following four bytes "06 00 00 00" represent the signed 32-bit offset from the current instruction to the target label.
	# end fork code
	local wait_code="$(system_call_wait4 | b64_to_hex_dump)";

	code="${pipe_code}${fork_code}${dup2_child}${exec_code}${wait_code}${read_pipe}";
	echo -en "${code}" | base64 -w0;
}

# The base pointer integer value is by convention the argc(argument count)
# In x86_64 is the RSP with integer size.
# It can be recovered in gdb by using 
# (gdb) print *((int*)($rsp))
# 
# But given it is a runtime only value, we don't have that value at build time, 
# so we need to create a dynamic ref that can be evaluatet at runtime.
# 
# My strategy is to set the constant _ARG_CNT_ then I can figure out latter that is means "RSP Integer"
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
	# 	This function should copy the pointer value currently set at RSP and copy it to the address
	local addr="$1"; # memory where to put the argc count
	local code="";
	code="${code}${MOV_RSP_R14}";
	code="${code}${ADD_R15_R14}";
	code="${code}${MOV_R14_ADDR4}$(printEndianValue $addr $SIZE_32BITS_4BYTES)";
	echo -en "${code}" | base64 -w0;
}

function get_arg()
{
	local ADDR="$1";
	local ARGN="$2";
	local CODE="";
	# MOV %RSP %RSI
	CODE="${CODE}${MOV_RSP_RSI}";
	# ADD RSI 8
	CODE="${CODE}$(add $(( 8 * (1 + ARGN) )) rsi | b64_to_hex_dump)";
	CODE="${CODE}${ADD_R15_RSI}";
	# RESOLVE RSI (Copy pointer address content to RSI)
	CODE="${CODE}${MOV_RSI_RSI}";
	# MOV RSI ADDR
	CODE="${CODE}${MOV_RSI_ADDR4}$(printEndianValue "$ADDR" $SIZE_32BITS_4BYTES)";

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
	local mmap_size_code="$( echo -en "${MOV_V4_RSI}$(printEndianValue $(( 4 * 1024 )) ${SIZE_32BITS_4BYTES})" | base64 -w0)";
	local mmap_code="$(sys_mmap "${mmap_size_code}" | b64_to_hex_dump)"
	# unable to move addr to addr;
	# so let's mov addr to a reg,
	# then reg to addr;
	if [ "$idx" == 1 ]; then # on first item zero r8 to accum the size
		code="${code}${XOR_R8_R8}";
		code="${code}$(push R8 | b64_to_hex_dump)"; # create zeroed target space at stack;
		code="${code}${MOV_RSP_ADDR4}$(printEndianValue "${dyn_addr}" ${SIZE_32BITS_4BYTES})";
	fi;
	if [ "$size" -eq -1 ]; then
		code="${code}${MOV_ADDR4_RSI}$(printEndianValue "${addr}" "${SIZE_32BITS_4BYTES}")"; # source addr
		code="${code}$(detect_string_length)"; # the return is set at rdx
		code="${code}${MOV_RDX_RCX}"; # but we need it on rcx because REP decrements it
	elif [ "$size" -eq -2 ]; then # procedure pointer
		code="${code}${MOV_ADDR4_RSI}$(printEndianValue "${addr}" "${SIZE_32BITS_4BYTES}")"; # source addr
		# TODO: how to manage to con
		#code="${code}${}"; # the return is set at rdx
		code="${code}${MOV_RDX_RCX}"; # but we need it on rcx because REP decrements it
		echo -en "${code}" | base64 -w0
		return;
	else
		code="${code}${MOV_V4_RSI}$(printEndianValue "$addr" "${SIZE_32BITS_4BYTES}")"; # source addr
		code="${code}${MOV_V4_RCX}$(printEndianValue "$size" ${SIZE_32BITS_4BYTES})"
	fi;
	code="${code}${MOV_RSP_RDI}"; # target addr
	#code="${code}${MOV_RAX_RDI}";
	code="${code}${ADD_R8_RDI}";
	code="${code}${ADD_RCX_R8}";

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
		code="${code}${MOV_V4_RAX}$(printEndianValue "$a" "${SIZE_32BITS_4BYTES}")";
	fi;
	if [ "${type_b}" == "$SYMBOL_TYPE_HARD_CODED" ]; then
		code="${code}${MOV_V4_RCX}$(printEndianValue "$b" "${SIZE_32BITS_4BYTES}")";
	fi;
	if [ "${type_a}" == "$SYMBOL_TYPE_STATIC" ]; then
		code="${code}${MOV_V4_RAX}$(printEndianValue "$a" "${SIZE_32BITS_4BYTES}")";
	fi;
	if [ "${type_b}" == "$SYMBOL_TYPE_STATIC" ]; then
		code="${code}${MOV_V4_RCX}$(printEndianValue "$b" "${SIZE_32BITS_4BYTES}")";
	fi;
	if [ "${type_a}" == "$SYMBOL_TYPE_DYNAMIC" ]; then
		code="${code}${LEA_V4_RAX}$(printEndianValue "$a" "${SIZE_32BITS_4BYTES}")";
		code="${code}${MOV_RAX_RAX}";
	fi;
	if [ "${type_b}" == "$SYMBOL_TYPE_DYNAMIC" ]; then
		code="${code}${LEA_V4_RCX}$(printEndianValue "$b" "${SIZE_32BITS_4BYTES}")";
		code="${code}${MOV_RCX_RCX}";
	fi;
	code="${code}${CMP_RAX_RCX}";
	echo -en "${code}" | base64 -w0;
}

set_increment()
{
	local addr=$1;
	local value=$2;
	local value_type=$3;
	local code="";
	code="${code}${MOV_V4_RDX}$(printEndianValue "${addr}" "${SIZE_32BITS_4BYTES}")";
	code="${code}${MOV_RDX_RDX}";
	if [ "$value" == 1 ]; then
		code="${code}${INC_RDX}";
	elif [ "$value" -gt -128 -a "$value" -lt 128 ]; then
		code="${code}$(add "${value}" rdx | b64_to_hex_dump)";
	elif [ "$value_type" == $SYMBOL_TYPE_HARD_CODED ]; then
		code="${code}${ADD_V4_RDX}$(printEndianValue "${value}" "${SIZE_32BITS_4BYTES}")";
	else
		code="${code}${XOR_RSI_RSI}";
		code="${code}${MOV_V4_RSI}$(printEndianValue "${value}" "${SIZE_32BITS_4BYTES}")";
		code="${code}${MOV_RSI_RSI}";
		code="${code}${ADD_RSI_RDX}";
	fi;
	code="${code}${MOV_RDX_ADDR4}$(printEndianValue "${addr}" "${SIZE_32BITS_4BYTES}")"
	echo -en "${code}" | base64 -w0
}

jump_if_equal(){
	local code="";
	local target_offset="$1";
	local current_offset="$2";
	local jump_instr_size=6; # 2 bytes for jz and 4 bytes for addr
	CODE_TO_JUMP="$(printEndianValue "$(( target_offset - current_offset - jump_instr_size ))" ${SIZE_32BITS_4BYTES})";
	code="${code}${JZ}${CODE_TO_JUMP}"; # The second byte is the opcode for the JE instruction. The following four bytes represent the signed 32-bit offset from the current instruction to the target label.
	echo -en "${code}" | base64 -w0
}

function bind()
{
	# I have found this shell code only and it seems to be a BIND exploit
	# I believe it can be useful to learn how to listen a port:
	local code="";
	code="${code}${XOR_RAX_RAX}";
	code="${code}${MOV_RAX_RDX}";
	code="${code}${MOV_RAX_RSI}";
	code="${code}$(rex | b64_to_hex_dump)\x8d\x3d\x04\x00\x00\x00";# lea rdi,[rel 0xb]
	code="${code}$(add ${SYS_EXECVE} AL | b64_to_hex_dump)";
	code="${code}${SYSCALL}";
	code="${code}\x2f\x62\x69\x6e\x2f\x73\x68\x00\xcc\x90\x90\x90";
#  https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.
#
# https://www.exploit-db.com/exploits/41128
#  "$(rex | b64_to_hex_dump)\x31\xc0"
#  "$(rex | b64_to_hex_dump)\x31\xd2"
#  "$(rex | b64_to_hex_dump)\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f"
#  "\x0f\x05"
#  "$(rex | b64_to_hex_dump)\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a"
#  "\x0f\x05"
#  "\x5e\x6a\x32\x58"
#  "\x0f\x05"
#  "\x6a\x2b\x58"
#  "\x0f\x05"
#  "$(rex | b64_to_hex_dump)\x97\x6a\x03\x5e\xff\xce\xb0\x21"
#  "\x0f\x05"
#  "\x75\xf8\xf7\xe6\x52$(rex | b64_to_hex_dump)\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53$(rex | b64_to_hex_dump)\x8d\x3c\x24\xb0\x3b"
#  "\x0f\x05";
  :
}
init_bloc(){
	local code="";
	MOV_RSP_RBP="$(rex | b64_to_hex_dump)\x89\xe5";
	MOV_V1_R15="$(rex v1 r15 | b64_to_hex_dump)\xc7\xc7";
	#code="${code}${MOV_V1_R15}$(printEndianValue 8 $SIZE_8BITS_1BYTE)";
	#code="${code}${MOV_RSP_RBP}";
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
		code="${code}${MOV_V4_RAX}$(printEndianValue "${item_addr}" $SIZE_32BITS_4BYTES)";
		code="${code}$(push RAX | b64_to_hex_dump)";
	fi;
	echo -ne "${code}" | base64 -w0;
}
array_end(){
	local array_addr="$1";
	local array_size="$2";
	local code="";
	# save the array addr outside the stack(in the main memory)
	code="${code}${MOV_RSP_RAX}";
	code="${code}$(add $(( array_size * 8 -8)) rax | b64_to_hex_dump)";
	code="${code}${MOV_RAX_ADDR4}$(printEndianValue "$array_addr" $SIZE_32BITS_4BYTES)";
	# put the array size in the stack
	code="${code}$(push_v_stack $array_size | b64_to_hex_dump)";
	echo -ne "${code}" | base64 -w0;
}
sys_geteuid(){
	local addr="$1";
	local code="";
	local SYS_GETEUID=107;
	code="${code}${MOV_V4_RAX}$(printEndianValue "$SYS_GETEUID" $SIZE_32BITS_4BYTES)"
	code="${code}${SYSCALL}";
	code="${code}${MOV_RAX_ADDR4}$(printEndianValue "${addr}" $SIZE_32BITS_4BYTES)";
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
	IMUL_RDX_RAX="$(rex | b64_to_hex_dump)\x0f\xaf\xc2";
	code="${code}${IMUL_RDX_RAX}";
	echo -ne "$code" | base64 -w0;
}

mod10(){
	local code="";
	code="${code}$(div10 | b64_to_hex_dump)";
	# shr    $0x23,%rax
	SHR_V1_RAX="$(rex | b64_to_hex_dump)\xc1\xe8";
	code="${code}${SHR_V1_RAX}\x23";
	# lea    (%rax,%rax,4),%eax
	code="${code}${LEA_RAX_RAX_4}";
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
	local rc=$(( ( 2#11 << 6 ) + ( 2#${r2^^} << 3 ) + ( 2#${r1^^} ) ));
	BSR="$(rex | b64_to_hex_dump)\x0F\xBD${rc}";
	echo -ne "$code" | base64 -w0;
}

# ilog10 do a log operation over a base on rax and put the result in the register passed as arg $2
# the result is integer truncated with cvttsd2si
# registers need: 2
# r1: value
# 	input: value to process;
# 	behavior: used to count bits with bsr instruction
# 	output: no change;
# r2: bit count
# 	input: unused;
# 	behavior: is a work register where the bsr will set the bit count
# 	output: will return the count bits of the value
# r3: max_bit_val_ilog10 address / integer log base 10
# 	input: address value pointer to to max_bit_val_ilog10
# 	behavior: will be incremented by the number of bits to point at the log10 integer value;
# 		echo "[$(for (( i=0; i<63; i++)); do [ $i -gt 0 ] && echo -n ,; v=$(( 2 ** i )); l=$(echo "scale=1;l($v)/l(10)" | bc -l); l=${l/.*/}; echo -n ${l:=0}; done )]";
#		[0,0,0,0,1,1,1,2,2,2,3,3,3,3,4,4,4,5,5,5,6,6,6,6,7,7,7,8,8,8,9,9,9,9,10,10,10,11,11,11,12,12,12,12,13,13,13,14,14,14,15,15,15,15,16,16,16,17,17,17,18,18,18]
# 	output: log10 integer value at base 10
ilog10(){
	local r1=$1;
	local r2=$2;
	local r3=$3;
	local code="";
	# bsr rbx, esi		# count bits into rbx
	code="${code}$(bsr $r2 $r1 | b64_to_hex_dump)";
	# movzx   eax, BYTE PTR max_bit_val_ilog10[1+rax] # movzx (zero extend, set the byte and fill with zeroes the remaining bits)
	code="${code}$(add $r2 $r3 | b64_to_hex_dump)";
	echo -en "$code" | base64 -w0;
}

# i2s integer to string
i2s(){
	local int_symbol_value="$1";
	local int_symbol_type="$2";
	local str_addr="$2";
	local code="";
	if [ "$int_symbol_type" == $SYMBOL_TYPE_DYNAMIC ]; then
		code="${code}${MOV_ADD4_RAX}$(printEndianValue "${int_symbol_value}" $SIZE_32BITS_4BYTES)";
	elif [ "$int_symbol_type" == $SYMBOL_TYPE_HARD_CODED ]; then
		code="${code}${MOV_V4_RAX}$(printEndianValue "${int_symbol_value}" $SIZE_32BITS_4BYTES)";
	else
		error not implemented;
		code="${code}${MOV_ADD4_RAX}$(printEndianValue "${int_symbol_value}" $SIZE_32BITS_4BYTES)";
	fi;
	# mov log10(rax) + 1, %rsi;	# 4;
	code="${code}$(ilog10 rax rdx rsi | b64_to_hex_dump)";
	code="${code}${INC_RSI}";
	# do:	# for 3123 will run 4 times:	# [ 1,		2,	3,	4	];
	# 	mov %rax mod 10, %rcx;		# [ 3,		2,	1,	3	];
	code="${code}$(module10 rcx | b64_to_hex_dump)";
	# 	sub rax, rcx;			# [ 3120,	310,	30,	0	];
	code="${code}$(sub rax rcx | b64_to_hex_dump)";
	# 	mov %rcx + 0x30, %rdx;		# [ "3",	"2",	"1",	"3"	];
	# 	mov %rdx, memory + %rsi
	# 	dec %rsi
	# 	div %rax, 10
	code="${code}$(div10 | b64_to_hex_dump)";
	# 	cmp %rax, 0
	code="${code}${CMP_RAX}"
	#code="${code}${CMP_RAX}0";
	# 	jg do
	echo -en "$code" | base64 -w0;
}

