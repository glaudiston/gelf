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
#  RAX(32): Accumulator: Used In Arithmetic operations
#  RAX(64): Accumulator: Used In Arithmetic operations
#  ECX(32): Counter: Used in loops and shift/rotate instructions
#  RCX(64): Counter: Used in loops and shift/rotate instructions
#  EDX(32): Data: Used in arithmetic operations and I/O operations
#  RDX(64): Data: Used in arithmetic operations and I/O operations
#  EBX(32): Base: Used as a pointer to data
#  RBX(64): Base: Used as a pointer to data
#  ESP(32): Stack Pointer: Points to top of stack
#  RSP(64): Stack Pointer: Points to top of stack
#  EBP(32): Stack Base Pointer: Points to base of stack
#  RBP(64): Stack Base Pointer: Points to base of stack
#  ESI(32): Points to source in stream operations
#  RSI(64): Points to source in stream operations
#  EDI(32): Points to destination in streams operations
#  RDI(64): Points to destination in streams operations
# 6 segment registers: points to memory segment addresses (but uses paging instead segmentation)
# 1 flag register: used to support arithmetic functions and debugging.
#  EFLAG(32)
#  RFLAG(64)
# Instruction Pointer: Address of the next instruction to execute.
#  EIP(32)
#  RIP(64)
#
#Here is a table of all the registers in x86_64 with their sizes:
#Register	Size (bits)
#RAX	64
#RBX	64
#RCX	64
#RDX	64
#RSI	64
#RDI	64
#RBP	64
#RSP	64
#R8	64
#R9	64
#R10	64
#R11	64
#R12	64
#R13	64
#R14	64
#R15	64
#EAX	32
#EBX	32
#ECX	32
#EDX	32
#ESI	32
#EDI	32
#EBP	32
#ESP	32
#R8D	32
#R9D	32
#R10D	32
#R11D	32
#R12D	32
#R13D	32
#R14D	32
#R15D	32
#AX	16
#BX	16
#CX	16
#DX	16
#SI	16
#DI	16
#BP	16
#SP	16
#R8W	16
#R9W	16
#R10W	16
#R11W	16
#R12W	16
#R13W	16
#R14W	16
#R15W	16
#AL	8
#BL	8
#CL	8
#DL	8
#SIL	8
#DIL	8
#BPL	8
#SPL	8
#R8B	8
#R9B	8
#R10B	8
#R11B	8
#R12B	8
#R13B	8
#R14B	8
#R15B	8
#
# Note that some of the registers have smaller sub-registers 
# that can be accessed, such as the lower 32 bits of a 64-bit register, 
# or the lower 16 or 8 bits of a 32-bit or 64-bit register. 
# These sub-registers are commonly used in instruction encoding 
# and can be useful for optimizing code.
#
# Register Name	Size (bits)	Description
# XMM0 - XMM15	128	Extended Multimedia Register (Streaming SIMD Extensions)
# YMM0 - YMM15	256	Extended Multimedia Register (AVX Advanced Vector Extensions)
# ZMM0 - ZMM31	512	Extended Multimedia Register (AVX-512 Advanced Vector Extensions 2)
#
# Note that YMM0-YMM15 are essentially the same as XMM0-XMM15,
# but with support for AVX (Advanced Vector Extensions) 
# instructions which operate on 256-bit operands. 
# ZMM0-ZMM31 are registers introduced in AVX-512 which support 512-bit operands.
#
. arch/system_call_linux_x86.sh

# THE REX PREFFIX:
#  REX prefix determines the addressing size without it the default is 32bit
#  REX Bits
#  |7|6|5|4|3|2|1|0|
#  |0|1|0|0|W|R|X|B|
#  W bit = Operand size 1==64-bits, 0 == legacy, depends on opcode.
#  R bit = Extends the ModR/M reg field to 4 bits. 0 selects RAX-RSI, 1 selects R8-R15
#  X bit = extends SIB 'index' field, same as R but for the SIB byte (memory operand)
#  B bit = extends the ModR/M r/m or 'base' field or the SIB field
#
REX(){
	local W=0;
	local R=0;
	local X=0;
	local B=0;
	echo $(( (2#0100 << 4) + (W<<3) (R<<2) + (X<<1) + B ));
}
M64="\x48"; # 01001000; set REX use addresses and registers(operand) with 64 bits (8 bytes)
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
# MOV_RSP_RSI="${M64}${MOV_R}\x$( printf %x $(( MOVR + (RSI << 3) + RSP )) )"; # move the RSP to RSI #11000110
# MOV__RSP__RSI="\x48\x8b\x34\x24"; # mov (%rsp), %rsp; # move value resolving pointer
# show_bytecode "MOV %RSI, (%RSP)"
#48893424
# show_bytecode "MOV %RSI, %RSP"
#4889f4

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
MODRM_REG_R8=$(( R8 << 3 )); # 000 0
MODRM_REG_R9=$(( R9 << 3 )); # 001 1
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
SUB_RSP_SHORT="$M64\x83\xec"; # Subtract 1 byte(two complement) value from RSP
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
MOV_V8_RAX="${M64}$( printEndianValue $(( MOV + IMM + RAX )) ${SIZE_8BITS_1BYTE} )"; # 48 b8
MOV_V4_RCX="\x48\xc7\xc1";
MOV_RDX="${M64}$( printEndianValue $(( MOV + IMM + RDX )) ${SIZE_8BITS_1BYTE} )"; # 48 ba
MOV_ADDR_RDX="\x48\x8b\x14\x25"; # followed by 4 bytes le;
MOV_ADDR_RSI="\x48\x8b\x34\x25";
MOV_ADDR_RDI="\x48\x8b\x3c\x25";
MOV_RAX_ADDR="\x48\x01\x04\x25";
MOV_RDX_ADDR="\x48\x89\x14\x25"; # followed by 4 bytes le;
REP="\xf3"; # repeat until rcx
MOVSB="\xa4"; # move 64bits(8 bytes) from %rsi addr to %rdi addr
MOVSQ="\x48\xa5"; # move 64bits(8 bytes) from %rsi addr to %rdi addr
MOV_RSI="${M64}$( printEndianValue $(( MOV + IMM + RSI )) ${SIZE_8BITS_1BYTE} )"; # 48 be
MOV_V4_RSI="\x48\xc7\xc6";
#debug MOV_RSI=$MOV_RSI
MOV_V8_RDI="${M64}$( printEndianValue $(( MOV + IMM + RDI )) ${SIZE_8BITS_1BYTE} )"; # 48 bf; #if not prepended with M64(x48) expect 32 bit register (edi: 4 bytes)
MOV_R="\x89";

# show_bytecode "mov %rsp, %rsi"
# 4889e6
MOV_RAX_RSI="${M64}${MOV_R}$(printEndianValue $(( MOVR + MODRM_REG_RAX + RSI )) ${SIZE_8BITS_1BYTE})"; # xC6 move the rax to rsi #11000110
MOV_RAX_RDI="${M64}${MOV_R}$(printEndianValue $(( MOVR + MOVRM_REG_RAX + RDI )) ${SIZE_8BITS_1BYTE} )";
MOV_RDX_RCX="\x48\x89\xd1";
#MOV_RSP_RSI="${M64}${MOV_R}\xe6"; # Copy the RSP(pointer address) to the RSP(as a pointer address).
MOV_RSP_RSI="${M64}${MOV_R}$( printEndianValue $(( MOVR + MODRM_REG_RSP + RSI )) ${SIZE_8BITS_1BYTE} )"; # move the RSP to RSI #11000110
MOV_RSP_RDX="${M64}${MOV_R}$( printEndianValue $(( MOVR + MODRM_REG_RSP + RDX )) ${SIZE_8BITS_1BYTE} )"; # move the RSP to RDX #11000010
MOV_RSI_RAX="${M64}${MOV_R}$( printEndianValue $(( MOVR + MODRM_REG_RSI + RAX )) ${SIZE_8BITS_1BYTE} )"; # move the RSI to RDX #11110010
get_mov_rsp_addr()
{
	# MOV %RSP ADDR: 48892425 78100000 ? not tested
	# 48: REX_64bit
	# 89: MOV instruction
	# 24: 00100100 MOD/R
	# 25: 00100101 SBI
	# 78100000: little endian 32bit addr
	REX="\x48";
	INSTR_MOV="\x89";
	MOD_RM="$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_RSP + RSP )) ${SIZE_8BITS_1BYTE} )";
	SBI=$(printEndianValue $(( 2#00100101 )) ${SIZE_8BITS_1BYTE});
	echo -n "${REX}${INSTR_MOV}${MOD_RM}${SBI}";
}
get_mov_rsi_addr()
{
	# MOV %RSP ADDR: 48892425 78100000 ? not tested
	# 48: REX_64bit
	# 89: MOV instruction
	# 24: 00100100 MOD/R
	# 25: 00100101 SBI
	# 78100000: little endian 32bit addr
	REX="\x48";
	INSTR_MOV="\x89";
	MOD_RM="$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_RSI + RSI )) ${SIZE_8BITS_1BYTE} )";
	SBI=$(printEndianValue $(( 2#00110101 )) ${SIZE_8BITS_1BYTE});
	#echo -n "${REX}${INSTR_MOV}${MOD_RM}${SBI}";
	echo -n "\x48\x89\x34\x25";
}
MOV_RSP_ADDR=$(get_mov_rsp_addr);
MOV_RSI_ADDR=$(get_mov_rsi_addr);
MOV_RSI_RDX="${M64}${MOV_R}$( printEndianValue $(( MOVR + MODRM_REG_RSI + RDX )) ${SIZE_8BITS_1BYTE} )"; # move the RSI to RDX #11110010
ADD_SHORT="\x83"; # ADD 8 or 16 bit operand (depend on ModR/M opcode first bit(most significant (bit 7)) been zero) and the ModR/M opcode
ADD_MODRM_RSI="$(printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + RSI )) $SIZE_8BITS_1BYTE)";
ADD_MODRM_RSP="$(printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + RSP )) $SIZE_8BITS_1BYTE)";
ADD_RSI="${M64}${ADD_SHORT}${ADD_MODRM_RSI}";
ADD_RSP="${M64}${ADD_SHORT}${ADD_MODRM_RSP}";
ADD_RDX_MODRM="$(printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + RDX )) $SIZE_8BITS_1BYTE)";
ADD_RDX="${M64}${ADD_SHORT}${ADD_RDX_MODRM}";
MOV_RESOLVE_ADDRESS="\x8b"; # Replace the address pointer with the value pointed from that address
# MOV_RESOLVE_ADDRESS needs the ModR/M mod (first 2 bits) to be 00.
MODRM="$(printEndianValue "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_RSI + RSI))" $SIZE_8BITS_1BYTE)";
MOV_RSI_RSI="${M64}${MOV_RESOLVE_ADDRESS}${MODRM}"; # mov (%rsi), %rsi
MODRM="$(printEndianValue "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_RDX + RDX))" $SIZE_8BITS_1BYTE)";
MOV_RDX_RDX="${M64}${MOV_RESOLVE_ADDRESS}${MODRM}";
MODRM="$(printEndianValue "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + MODRM_REG_RDI + RDI))" $SIZE_8BITS_1BYTE)";
MOV_RDI_RDI="${M64}${MOV_RESOLVE_ADDRESS}${MODRM}";

# show_bytecode "movq (%rsp), %rsi"
# 488b3424
# MOV_VALUE_RSI_RSP="\x48\x8b\x34\x24"; # Copy the RSP(pointer value, not address) to the RSI(as a integer value).

# while \x48 is used for first 8 register, the last 8 register use \x49
MOV_RAX_R8="\x49${MOV_R}$(printEndianValue $(( MOVR + MODRM_REG_RAX + R8 )) ${SIZE_8BITS_1BYTE})";
MOV_RAX_R9="\x49\x89\xc1"; # move the size read to r9
MOV_R8_RDI="\x4c\x89\xc7";
MOV_R8_RDX="\x4c\x89$(printEndianValue $(( MOVR + MODRM_REG_R8 + RDX )) ${SIZE_8BITS_1BYTE})";
MOV_R9_RDI="\x4c\x89$(printEndianValue $(( MOVR + MODRM_REG_R9 + RDI )) ${SIZE_8BITS_1BYTE})";
MOV_R9_RDX="\x4c\x89$(printEndianValue $(( MOVR + MODRM_REG_R9 + RDX )) ${SIZE_8BITS_1BYTE})";
MOV_R8="\x49\xB8";
MOV_R9="\x49\xB9";
MOV_R10="\x49\xBA";

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
XOR_RDX_RDX="\x48\x31\xD2";
XOR_R8_R8="\x4d\x31\xc0";

# JMP
# We have some types of jump
# Relative jumps (short and near):
JMP_SHORT="\xeb"; # followed by a 8-bit signed char (-128 to 127) to move relative to BIP.
JMP_NEAR="\xe9"; # followed by a 32-bit signed integer(-2147483648 to 2147483647).
# Jump to the full virtual address
JMP_RAX="\xff";
JMP_RDI="\xe0";
CMP="${M64}\x83"; # only if most significant bit(bit 7) of the next byte is 1 and depending on opcode(bits 6-3) And ModR/M opcode
JNE="\x0f\x85"; # The second byte "85" is the opcode for the JNE(Jump if Not Equal) same of JNZ(Jump if Not Zero) instruction. The following four bytes "06 00 00 00" represent the signed 32-bit offset from the current instruction to the target label.
JZ="\x0f\x84";
JG="\x0F\x8F"; # Jump if Greater than zero

#48 81 C7 01 02 03 04     add    rdi, 0x04030201
ADD_FULL="\x81"; # ADD 32 or 64 bit operand (depend on ModR/M
ADD_M64="${M64}${ADD_FULL}";
ADD_M64_RDI="${ADD_M64}";


# LEA - Load Effective Address (page 1146)
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
	CODE="${CODE}${MOV_V8_RAX}$(printEndianValue $SYS_CLOSE ${SIZE_64BITS_8BYTES})";
	CODE="${CODE}${SYSCALL}";
	echo -en "${CODE}" | base64 -w0;
}

# stat get information of a file
sys_stat()
{
	local CODE="";
	local FD="$1";
	if [ "$FD" != "" ]; then
		CODE="${CODE}${MOV_V8_RAX}$(printEndianValue $FD)";
	else
		# ; we will default to use rax as input. (normally used after a open, so)
		# mov rdi, rax        ; File descriptor returned by the open syscall
		CODE="${CODE}${MOV_RAX_RDI}"
	fi
	# mov rax, 0x9c       ; System call number for fstat
	CODE="${CODE}${MOV_V8_RAX}$(printEndianValue $((16#9c)) ${SIZE_64BITS_8BYTES})"
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
 	CODE="${CODE}${MOV_RSI}$(printEndianValue ${stat_addr})";
	# RAX: fstat
	CODE="${CODE}${MOV_V8_RAX}$(printEndianValue $SYS_FSTAT ${SIZE_64BITS_8BYTES})";
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
	code="${code}${MOV_RSI}$(printEndianValue $(( STAT_ADDR + st_size )) ${SIZE_64BITS_8BYTES})";
	code="${code}${MOV_RSI_RSI}"; # resolve pointer to address
	local default_value_code="${MOV_RSI}$(printEndianValue $PAGESIZE)"
	local ModRMCmpRSI="$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_CMP + RSI )) $SIZE_8BITS_1BYTE)";
	code="${code}${CMP}${ModRMCmpRSI}\x00"; # 64bit cmp rsi, 00
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
	CODE="${CODE}${MOV_V8_RAX}$(printEndianValue $((16#3f)) $SIZE_64BITS_8BYTES)"; # syscall
	CODE="${CODE}${MOV_RDI_64b}$(printEndianValue $((16#18)) $SIZE_64BITS_8BYTES)"; # _SC_PAGESIZE
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
	CODE="${CODE}${MOV_V8_RDI}$(printEndianValue 0 ${SIZE_64BITS_8BYTES})";
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
	local mmap_size_code="$(echo "$size" | base64 -d | toHexDump)";
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
	CODE="${CODE}${MOV_RDX}$(printEndianValue $(( PROT_READ + PROT_WRITE )) ${SIZE_64BITS_8BYTES})";
	# man mmap for valid flags
	#    mov r10, 2    ; flags
	MAP_SHARED=1;
	MAP_PRIVATE=2;
	MAP_SHARED_VALIDATE=3;
	MAP_ANONYMOUS=$((2#00100000))
	CODE="${CODE}${MOV_R10}$(printEndianValue $(( MAP_PRIVATE )) ${SIZE_64BITS_8BYTES})"
	
	# The file descriptor is expected to be at R8,
	# but for virtual files it will fail with a -19 at rax.
	# 
	if [ "$fd" == "rax" ]; then
		CODE="${CODE}${MOV_RAX_R8}"
	elif [ "$fd" != "" ]; then
		CODE="${CODE}${MOV_R8}$(printEndianValue $fd ${SIZE_64BITS_8BYTES})";
	fi;
	#CODE="${CODE}${XOR_R8_R8}";
	#    mov r9, 0     ; offset
	CODE="${CODE}${MOV_R9}$(printEndianValue 0 ${SIZE_64BITS_8BYTES})"
	#    mov rax, 9    ; mmap system call number
	CODE="${CODE}${MOV_V8_RAX}$(printEndianValue $SYS_MMAP ${SIZE_64BITS_8BYTES})"
	CODE="${CODE}${SYSCALL}";
	# test rax to detect failure
	local ModRM="$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_CMP + RAX )) $SIZE_8BITS_1BYTE)";
	CODE="${CODE}${CMP}${ModRM}\x00"; # 64bit cmp rax, 00
	# if it fails do mmap with  MAP_ANONYMOUS
	local ANON_MMAP_CODE="${MOV_R10}$(printEndianValue $(( MAP_PRIVATE + MAP_ANONYMOUS )) ${SIZE_64BITS_8BYTES})"
	ANON_MMAP_CODE="${ANON_MMAP_CODE}${MOV_V8_RAX}$(printEndianValue $SYS_MMAP ${SIZE_64BITS_8BYTES})"
	ANON_MMAP_CODE="${ANON_MMAP_CODE}${SYSCALL}"
	# then we need to read the data to that location
	ANON_MMAP_CODE="${ANON_MMAP_CODE}${MOV_R8_RDI}";
	ANON_MMAP_CODE="${ANON_MMAP_CODE}$(system_call_read "" "rsi" | base64 -d | toHexDump)"; # TODO not sure the best choice here. We should do it better
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
	local JUMP_SHORT_SIZE=2;
	local RELATIVE=$(( TARGET_ADDR - CURRENT_ADDR - JUMP_SHORT_SIZE ))
	local CODE="";
	if [ ! "$(( (RELATIVE >= -128) && (RELATIVE <= 127) ))" -eq 1 ]; then
		error tried to jump to an invalid range: $RELATIVE
		echo -en ",-1";
		return;
	fi;
	# debug jump short relative $RELATIVE
	local RADDR_V="$(printEndianValue "$RELATIVE" $SIZE_8BITS_1BYTE )";
	# debug jump short to RADDR_V=[$( echo -n "$RADDR_V" | xxd)]
	CODE="${CODE}${JMP_SHORT}${RADDR_V}";
	echo -ne "$(echo -en "${CODE}" | base64 -w0),${JUMP_SHORT_SIZE}";
	return
}

# system_call_jump should receive the target address and the current BIP.
#   It will select the correct approach for each context based on the JMP alternatives
function system_call_jump()
{
	local TARGET_ADDR="$1";
	local CURRENT_ADDR="$2";
	# debug "jump: TARGET_ADDR:[$(printf %x $TARGET_ADDR)], CURRENT_ADDR:[$( printf %x ${TARGET_ADDR})]"
	local OPCODE_SIZE=1;
	local DISPLACEMENT_BITS=32; # 4 bytes
	local JUMP_NEAR_SIZE=$(( OPCODE_SIZE + DISPLACEMENT_BITS / 8 )); # 5 bytes

	local short_jump_response=$(bytecode_jump_short "$TARGET_ADDR" "${CURRENT_ADDR}")
	if [ "$(echo -n "${short_jump_response}" | cut -d, -f2)" -gt -1 ];then
		# debug short jump succeed;
		echo -n "${short_jump_response}";
		return;
	fi;
	# debug jump, unable to short, trying near: $short_jump_response

	#bytecode_jump_near
	local JUMP_NEAR_SIZE=5;
	local RELATIVE=$(( TARGET_ADDR - CURRENT_ADDR - JUMP_NEAR_SIZE ))
	if [ "$(( (RELATIVE >= - ( 1 << 31 )) && (RELATIVE <= ( 1 << 31 ) -1) ))" -eq 1 ]; then
		# jump near
		local RADDR_V;
		RADDR_V="$(printEndianValue "${RELATIVE}" $SIZE_32BITS_4BYTES)";
		# debug "jump near relative ( $RELATIVE, $RADDR_V )";
		CODE="${CODE}${JMP_NEAR}${RADDR_V}";
		echo -ne "$(echo -en "${CODE}" | base64 -w0),${JUMP_NEAR_SIZE}";
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
function system_call_procedure()
{
	local TARGET="$1";
	local CURRENT="$2";
	# call procedure (in same segment)
	# we don't have a short call in x64.
	# direct has a 32bit displacement to receive the near relative address

	# debug "calling: TARGET:[$TARGET], CURRENT:[${CURRENT}]"
	local OPCODE_SIZE=1;
	local DISPLACEMENT_BITS=32; # 4 bytes
	local CALL_NEAR_SIZE=$(( OPCODE_SIZE + DISPLACEMENT_BITS / 8 )); # 5 bytes
	local RELATIVE=$(( TARGET - CURRENT - CALL_NEAR_SIZE ))
	if [ "$(( (RELATIVE >= - ( 1 << ( DISPLACEMENT_BITS -1 ) )) && (RELATIVE <= ( 1 << ( DISPLACEMENT_BITS -1) ) -1) ))" -eq 1 ]; then
		local OPCODE_CALL_NEAR="\xe8"; #direct call with 32bit displacement
		local NEAR_ADDR_V="$(printEndianValue $RELATIVE $SIZE_32BITS_4BYTES)" # call addr
		local BYTES="${OPCODE_CALL_NEAR}${NEAR_ADDR_V}"
		echo -en "$BYTES" | base64 -w0;
		return
	fi;
	error "call not implemented for this address size: CURRENT: $CURRENT, TARGET: $TARGET, RELATIVE: $RELATIVE";

	FAR_CALL="\x9a";
	MODRM="$(printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_SUB + RSP )) $SIZE_8BITS_1BYTE)"
	SUB_RSP="${M64}${SUB_IMMSE8}${MODRM}\x28" # sub rsp, x28
	addr="$(( 16#000100b8 ))"
	BYTES="\xe8${CALL_ADDR}";
	echo -en "$BYTES" | base64 -w0;
}

function system_call_push_stack()
{
	# PUSHA/PUSHAD – Push All General Registers 0110 0000
	
	local PUSH="\x68";
	local ADDR_V="$(printEndianValue )"
	echo -n "${PUSH}${ADDR_V}"
}

function bytecode_ret()
{
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
	# run RET
	local bytecode_ret_len=1;
	echo -en $(echo -en "${NEAR_RET}" | base64 -w0 ),${bytecode_ret_len}
}

function system_call_pop_stack()
{
	# POPA/POPAD – Pop All General Registers 0110 0001
	:
}


function system_call_open()
{
	local filename="$1"
	local CODE="";
	# mov rax, 2 ; System call for open()
	CODE="${CODE}${MOV_V8_RAX}$(printEndianValue ${SYS_OPEN} "${SIZE_64BITS_8BYTES}")"
	# mov rdi, filename ; File name
	local FILENAME_ADDR="$(printEndianValue "${filename}" "${SIZE_64BITS_8BYTES}" )";
	CODE="${CODE}${MOV_V8_RDI}${FILENAME_ADDR}";
	# TODO best to use xor when setting rsi to 0
	# mov rsi, 'r' ; Open mode
	CODE="${CODE}${MOV_RSI}$(printEndianValue $(( 16#0 )) "${SIZE_64BITS_8BYTES}")"; # mode=r (x72)
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
	if [ "${TYPE}" == "${SYMBOL_TYPE_STATIC}" ]; then
		# do we have a buffer to read into? should we use it in a mmap?
		# now we create a buffer with mmap using this fd in RAX.
		CODE="${CODE}$(sys_mmap "${DATA_LEN}" | base64 -d | toHexDump)"
		# TODO test sys_mmap return at rax, and if fails(<0) then mmap without the fd
		# TODO once mmap set, if the source file is read only we can just close it.
		# then the fd should be at eax and r8
		#
		# TODO:
		# collect $RAX (memory location returned from mmap)
		# use it as argument to write out.
		echo -en "${CODE}" | base64 -w0;
		return
	elif [ "${TYPE}" == ${SYMBOL_TYPE_DYNAMIC} ]; then
		#debug dynamic
		if [ "$(echo -n "${DATA_ADDR_V}" | base64 -d | cut -d, -f1 | base64 -w0)" == "$( echo -n ${ARCH_CONST_ARGUMENT_ADDRESS} | base64 -w0)" ]; then
			# now we create a buffer with mmap using this fd in RAX.
			CODE="${CODE}$(sys_mmap | base64 -d | toHexDump)"
			# then the fd should be at eax
			#
			# TODO:
			# collect $RAX (memory location returned from mmap)
			# use it as argument to write out.
			# DEBUG CODE:
			CODE="${CODE}${MOV_RAX_RSI}"
			CODE="${CODE}${MOV_V8_RAX}$(printEndianValue $SYS_WRITE $SIZE_64BITS_8BYTES)";
			STDOUT=1;
			CODE="${CODE}${MOV_V8_RDI}$(printEndianValue $STDOUT $SIZE_64BITS_8BYTES)";
			CODE="${CODE}${MOV_RDX}$(printEndianValue "${DATA_LEN}" $SIZE_64BITS_8BYTES)";
			CODE="${CODE}${SYSCALL}";
			echo -en "${CODE}" | base64 -w0;
		else
			# otherwise we expect all instruction already be in the data_addr_v as base64
			# so just throw it back
			echo -n "$DATA_ADDR_V"
		fi;
		return
	fi
	error "b Not Implemented path type[$TYPE], DATA_ADDR_V=[$DATA_ADDR_V]"
	return
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
		CODE="${CODE}${MOV_RDX}$(printEndianValue ${len} $SIZE_64BITS_8BYTES)";
	fi;
	if [ "$DATA_ADDR" == "" ]; then
		#use rax
		CODE="${CODE}${MOV_RAX_RSI}";
	else
		CODE="${CODE}${MOV_RSI}$(printEndianValue "$DATA_ADDR" "$SIZE_64BITS_8BYTES" )";
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
	CODE="${CODE}${MOV_RSI}${DATA_ADDR}";
	CODE="${CODE}${MOV_RDX}$(printEndianValue "${DATA_LEN}" $SIZE_64BITS_8BYTES)";
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
	ARGUMENT_DISPLACEMENT=$(printEndianValue 8 ${SIZE_8BITS_1BYTE})
	#ADD_RDX="${M64}${ADD_SHORT}\xC2"
	CODE="${CODE}${ADD_RDX}${ARGUMENT_DISPLACEMENT}";
	# mov to the real address (not pointer to address)
	ModRM=$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_REG_RSI + RDX )) ${SIZE_8BITS_1BYTE} )
	SUB_RDX_RSI="${M64}${SUB_R}${ModRM}";
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
	#LEAQ_RIP_RBX="\x48\x8d\x1d\x00\x00\x00\x00";
	#code=${code}${LEAQ_RIP_RBX};
	# get the data byte at addr+rdx into rax
	MOV__RDX__RAX="\x48\x0f\xb6\x02"; # movzbq (%rdx), %rax
	code="${code}${MOV__RDX__RAX}"; # resolve current rdx pointer to rax
	#MOV_DATA_RAX="\x48\x0f\xb6\x06"; # movzbq (%rsi), %rax
	#code="${code}${MOV_DATA_RAX}";
	TEST_RAX_RAX="\x48\x85\xc0";
	# inc rdx
	INC_RDX="\x48\xff\xc2";
	code="${code}${INC_RDX}";
	# test data byte
	TEST_AL="\x84\xc0";
	# loop back if not null
	code="${code}${TEST_AL}";
	# jz
	# "ebfe" # jump back 0 bytes
	JUMP_BACK_BYTES="\x7f\xf5"; # jg .-9; Jump back 9 bytes only if AL > 0
	code="${code}${JUMP_BACK_BYTES}";
	DEC_RDX="\x48\xff\xca";
	code="${code}${DEC_RDX}";
	# sub %rsi, %rdx
	SUB_RSI_RDX="\x48\x29\xf2";
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
	debug "write a dynamic address[$(printf 0x%x $DATA_ADDR_V )] to $OUT";
	if [ "$(echo -n "${DATA_ADDR_V}" | cut -d, -f1 | base64 -w0)" == "$( echo -n ${ARCH_CONST_ARGUMENT_ADDRESS} | base64 -w0)" ]; then
	{
		local CODE="";
		CODE="${CODE}${MOV_V8_RAX}$(printEndianValue $SYS_WRITE $SIZE_64BITS_8BYTES)";
		CODE="${CODE}${MOV_V8_RDI}$(printEndianValue $OUT $SIZE_64BITS_8BYTES)";

		CODE="${CODE}$(detect_argsize)";

		local LAST_ARG_CODE="";
		LAST_ARG_CODE="${LAST_ARG_CODE}${MOV_RSP_RDX}";
		ARGUMENT_DISPLACEMENT=$(printEndianValue $(( 8 * argument_number + 16 )) ${SIZE_8BITS_1BYTE})
		LAST_ARG_CODE="${LAST_ARG_CODE}${ADD_RDX}${ARGUMENT_DISPLACEMENT}";
		LAST_ARG_CODE="${LAST_ARG_CODE}${MOV_RDX_RDX}";
		LAST_ARG_CODE="${LAST_ARG_CODE}${SUB_RDX_RSI}";

		local ModRM="$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_CMP + RDX )) $SIZE_8BITS_1BYTE)";
		CODE="${CODE}${CMP}${ModRM}\x00"; # 64bit cmp rdx, 00
		BYTES_TO_JUMP="$(printEndianValue $(echo -en "${LAST_ARG_CODE}" | wc -c) $SIZE_32BITS_4BYTES)";
		# If is not the last argument, we are good, jump over
		CODE="${CODE}${JG}${BYTES_TO_JUMP}";
		CODE="${CODE}${LAST_ARG_CODE}";
		# so here we want to look at first env address to subtract it and find out the last argument size
		MODRM=$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_SUB + RDX)) $SIZE_8BITS_1BYTE );
		SUB_RDX_1="${SUB_IMMSE8}${MODRM}\x01";
		CODE="${CODE}${SUB_RDX_1}";
		CODE="${CODE}${SYSCALL}";
		echo -en "${CODE}" | base64 -w0;
	}
	else
	{
		# otherwise we expect all instruction already be in the data_addr_v as base64
		debug "**** b **** [$DATA_ADDR_V]"
		local code="";
		if [ "$DATA_ADDR_V" == "RAX" ]; then
			code="${code}${MOV_RAX_RSI}";
		else
			code="${code}${MOV_ADDR_RSI}$(printEndianValue ${DATA_ADDR_V} ${SIZE_32BITS_4BYTES})";
		fi
		if [ "${DATA_LEN}" == "0" ]; then
			code="${code}$(detect_string_length)";
		else
			local MOV_V_RDX="${MOV_RDX}$(printEndianValue "${DATA_LEN}" ${SIZE_64BITS_8BYTES})";
			code="${code}${MOV_V_RDX}";
		fi;
		code="${code}${MOV_V8_RDI}$(printEndianValue $OUT $SIZE_64BITS_8BYTES)";
		code="${code}${MOV_V8_RAX}$(printEndianValue $SYS_WRITE $SIZE_64BITS_8BYTES)";
		code="${code}${SYSCALL}";
		echo -ne "${code}" | base64 -w0;
		return;
	}
	fi;
}

function system_call_write()
{
	local TYPE="$1";
	local OUT="$2";
	local DATA_ADDR_V="$3";
	local DATA_LEN="$4";
	local CURRENT_RIP="$5";
	if [ "${TYPE}" == "${SYMBOL_TYPE_STATIC}" ]; then
		echo -n "$(system_call_write_addr "${OUT}" "${DATA_ADDR_V}" "${DATA_LEN}")";
	elif [ "${TYPE}" == "${SYMBOL_TYPE_DYNAMIC}" ]; then
	{
		echo -n "$(system_call_write_dyn_addr "${OUT}" "${DATA_ADDR_V}" "${DATA_LEN}")";
	}
	elif [ "$TYPE" == "${SYMBOL_TYPE_PROCEDURE}" ]; then
	{
		local code="";
		code="${CODE}$(system_call_procedure ${DATA_ADDR_V} ${CURRENT_RIP} | base64 -d | toHexDump)";
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

system_call_exit_len=22
function system_call_exit()
{
	local exit_code="$1"
	local BIN_CODE="";
	local EXIT="$(printEndianValue $SYS_EXIT $SIZE_64BITS_8BYTES)";
	BIN_CODE="${BIN_CODE}${MOV_V8_RAX}${EXIT}"
	BIN_CODE="${BIN_CODE}${MOV_V8_RDI}$(printEndianValue ${exit_code:=0} $SIZE_64BITS_8BYTES)"
	BIN_CODE="${BIN_CODE}${SYSCALL}"
	echo -en "${BIN_CODE}" | base64 -w0;
}

function system_call_fork()
{
	local SYS_FORK=57
	local FORK=$(printEndianValue ${SYS_FORK} ${SIZE_64BITS_8BYTES})
	local CODE="";
	CODE="${CODE}${MOV_V8_RAX}${FORK}"
	CODE="${CODE}${SYSCALL}"
	echo -en "${CODE}" | base64 -w0;
	echo -en ",$(echo -en "${CODE}" | wc -c )";
}

function toHexDump()
{
	xxd --ps | sed "s/\(..\)/\\\\x\1/g" | tr -d '\n'
}

function system_call_sys_execve()
{
	:
}

function system_call_exec()
{
	local PTR_FILE="$1"
	local PTR_FILE_ADDR_TYPE="$2";
	local PTR_ARGS="$3"
	local PTR_ENV="$4"
	local CODE="";
	CODE="${CODE}$(system_call_fork | cut -d, -f1 | base64 -d | toHexDump)";
	# TODO: CMP ? then (0x3d) rAx, lz
	local TWOBYTE_INSTRUCTION_PREFIX="\0f"; # The first byte "0F" is the opcode for the two-byte instruction prefix that indicates the following instruction is a conditional jump.
	local ModRM="$( printEndianValue $(( MODRM_MOD_DISPLACEMENT_REG + MODRM_OPCODE_CMP + RAX )) $SIZE_8BITS_1BYTE)";
	CODE="${CODE}${CMP}${ModRM}\x00"; # 64bit cmp rax, 00
	# rax will be zero on child, on parent will be the pid of the forked child
	# so if non zero (on parent) we will jump over the sys_execve code to not run it twice,
	# and because it will exit after run
	if [ "$PTR_FILE_ADDR_TYPE" == 1 ]; then
		CODE_TO_JUMP="$(printEndianValue 45 ${SIZE_32BITS_4BYTES})" # 45 is the number of byte instructions of the syscall sys_execve (including the MOV (%rdi), %rdi.
	else
		CODE_TO_JUMP="$(printEndianValue 42 ${SIZE_32BITS_4BYTES})" # 42 is the number of byte instructions of the syscall sys_execve.
	fi;
	CODE="${CODE}${JNE}${CODE_TO_JUMP}"; # The second byte "85" is the opcode for the JNE instruction. The following four bytes "06 00 00 00" represent the signed 32-bit offset from the current instruction to the target label.
	# TODO: JNE ?
	#CODE=${CODE}${cmp}$(printEndianValue 0 ${SIZE_32BITS_4BYTES})$(printEndianValue $rax ${})) ; rax receives 0 for the child and the child pid on the parent
	# je child_process_only # only on the child, jump over next line to execute the execve code
	# jmp end # if reach this (is parent) then jump over all sys_execve instructions to the end and do nothing
	# child_process_only:
	#								mem       elf     str
	# 401000:       48 bf 00 20 40 00 00    movabs $0x402000,%rdi #        == 2000 == /bin/sh
	# 401007:       00 00 00
	#CODE="${CODE}${MOV_V8_RDI}$(printEndianValue ${PTR_FILE:=0} ${SIZE_64BITS_8BYTES})"
	#       :       48 bf c0 00 01 00 00 00 00 00"
	CODE="${CODE}${MOV_V8_RDI}$(printEndianValue ${PTR_FILE:=0} ${SIZE_64BITS_8BYTES})";
	if [ "$PTR_FILE_ADDR_TYPE" == $SYMBOL_TYPE_DYNAMIC ]; then
		CODE="${CODE}${MOV_RDI_RDI}";
	fi;

	# LEA_RSP_RSI="\x48\x8d\x74\x24\x08";
	# 40100a:       48 8d 74 24 08          lea    0x8(%rsp),%rsi
	# CODE="${CODE}${LEA_RSP_RSI}"
	CODE="${CODE}${MOV_RSI}$(printEndianValue ${PTR_ARGS:=0} ${SIZE_64BITS_8BYTES})"

	# 40100f:       ba 00 00 00 00          mov    $0x0,%edx
	CODE="${CODE}${MOV_RDX}$(printEndianValue ${PTR_ENV:=0} ${SIZE_64BITS_8BYTES})" # const char *const envp[]

	# 401014:       b8 3b 00 00 00          mov    $0x3b,%eax
	CODE="${CODE}${MOV_V8_RAX}$(printEndianValue ${SYS_EXECVE} ${SIZE_64BITS_8BYTES})" # sys_execve (3b)

	# 401019:       0f 05                   syscall
	CODE="${CODE}${SYSCALL}"
	# end:
	echo -en "${CODE}" | base64 -w0;
	echo -en ",$(echo -en "${CODE}" | wc -c )";
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
	local ADDR="$1"; # memory where to put the argc count
	local CODE="";
	CODE="${CODE}${MOV_RSP_ADDR}$(printEndianValue $ADDR $SIZE_32BITS_4BYTES)";
	echo -en "${CODE}" | base64 -w0;
}

function get_arg()
{
	local ADDR="$1";
	local ARGN="$2";
	local CODE="";
	# MOV %RSP %RSI
	CODE="${CODE}${MOV_RSP_RSI}";
	# ADD RSI 8
	CODE="${CODE}${ADD_RSI}$(printEndianValue $(( 8 * (1 + ARGN) )) ${SIZE_8BITS_1BYTE})";
	# RESOLVE RSI (Copy pointer address content to RSI)
	CODE="${CODE}${MOV_RSI_RSI}";
	# MOV RSI ADDR
	CODE="${CODE}${MOV_RSI_ADDR}$(printEndianValue "$ADDR" $SIZE_32BITS_4BYTES)";

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
	# unable to move addr to addr;
	# so let's mov addr to a reg,
	# then reg to addr;
	if [ "$idx" == 1 ]; then # on first item zero r8 to accum the size
		code="${code}${XOR_R8_R8}";
		# We need a memory position to store the concatenated value;
		#TODO I will do something ugly and wrong here. fix it later
		# I will get the next address(+8 bytes) as target address,
		# so I don't have to manage the memory now.
		code="${code}${MOV_V8_RAX}$(printEndianValue "$(( dyn_addr + 8 ))" ${SIZE_64BITS_8BYTES})";
		code="${code}${MOV_RAX_ADDR}$(printEndianValue "$dyn_addr" ${SIZE_32BITS_4BYTES})";
	fi;
	if [ "$size" -eq -1 ]; then
		code="${code}${MOV_ADDR_RSI}$(printEndianValue "$addr" "${SIZE_32BITS_4BYTES}")"; # source addr
		code="${code}$(detect_string_length)"; # the return is set at rdx
		code="${code}${MOV_RDX_RCX}"; # but we need it on rcx because REP decrements it
	else
		code="${code}${MOV_V4_RSI}$(printEndianValue "$addr" "${SIZE_32BITS_4BYTES}")"; # source addr
		code="${code}${MOV_V4_RCX}$(printEndianValue "$size" ${SIZE_32BITS_4BYTES})"
	fi;
	#ADD_RDX_R8="\x49\x01\xd0";
	ADD_RCX_R8="\x49\x01\xc8";
	code="${code}${MOV_V8_RDI}$(printEndianValue "$(( dyn_addr + 8 ))" "${SIZE_64BITS_8BYTES}")"; # target addr
	ADD_R8_RDI="\x4c\x01\xc7";
	code="${code}${ADD_R8_RDI}";
	code="${code}${ADD_RCX_R8}";

	# if addr is 0 allocate some address to it.
	# cmp rdi
	# jg .(alloc mem instr len)
	# alloc mem
	code="${code}${REP}${MOVSB}";
	echo -en "${code}" | base64 -w0;
}
