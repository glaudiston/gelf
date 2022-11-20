#!/bin/bash
# https://github.com/xcellerator/libgolf/tree/main/examples/03_aarch64
# https://tmpout.sh/2/14.html
# System Interrupt call table for 64bit aarch64 linux:
# https://syscalls.w3challs.com/?arch=arm_strong
#
# aarch64 Instruction set
# https://en.wikipedia.org/wiki/X86_instruction_listings#Original_8086.2F8088_instructions
#
# Intel i64 and IA-32 Architectures
# https://software.intel.com/sites/default/files/managed/39/c5/325462-sdm-vol-1-2abcd-3abcd.pdf
# Linux syscall:
# https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
# See Table A-2. One-byte Opcode Map on Intel i64 documentation (page 2626)
# See Table B-13.  General Purpose Instruction Formats and Encodings for Non-64-Bit Modes (Contd.) (page 2658)
MOV="d280"
MOV_BIN=$(printLittleEndian $(( 16#$MOV )) 2)
MOV_RAX="\xb8"
MOV_RDX="\xba"
MOV_RSI="\xbe"
MOV_RDI="\xbf" #32 bit register (4 bytes)

# LEA - Load Effective Address
SYSCALL="\x01\x00\x00\xd4"

function system_call_read()
{
	local string="$1";
	local len="${2}";
	local CODE="";
	SYS_READ=0;
	STDIN=0;
	CODE="${CODE}${MOV_RAX}$(printEndianValue $SYS_READ $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${MOV_RDI}$(printEndianValue $STDIN $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${MOV_RSI}${string}";
	CODE="${CODE}${MOV_RDX}$(printEndianValue ${len} $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${SYSCALL}";
	echo -en "${CODE}" | base64 -w0;
}

system_call_write_len=22
# given a data address as argument, write it to stdout
function system_call_write()
{
	local DATA_ADDR_V="$1";
	local DATA_LEN="$2";
	local CODE="";
	local DATA_ADDR="$(printEndianValue $DATA_ADDR_V $SIZE_32BITS_4BYTES)";
	SYS_WRITE=1;
	STDOUT=1;
	CODE="${CODE}${MOV_RAX}$(printEndianValue $SYS_WRITE $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${MOV_RDI}$(printEndianValue $STDOUT $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${MOV_RSI}${DATA_ADDR}";
	CODE="${CODE}${MOV_RDX}$(printEndianValue ${DATA_LEN} $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${SYSCALL}";
	echo -en "${CODE}" | base64 -w0;
}

system_call_exit_len=12
function system_call_exit()
{
	# mov x0, #0      @ Return value is 0
	# mov x8, #0x5d   @ 0x5d is sys_exit
	# svc #0          @ Interrupt to svc mode (syscall)
	local SYS_EXIT=$(( 16#0ba8 ))
	local exit_code="$1"
	local BIN_CODE="";
	local EXIT="$(printEndianValue $SYS_EXIT $SIZE_16BITS_2BYTES)";

	# 000 00000001 00000
	#  |  ---+---- -----> 5 bits defines the register x0
	#  |     +-> 8 bits define the value
	#  +-> No Idea
	v=$(( ( exit_code << 5 ) + 0 ))
	VALUE_AND_TARGET_REGISTER=$(printEndianValue $v $SIZE_16BITS_2BYTES)

	# join and apply little endian
	BIN_CODE="${VALUE_AND_TARGET_REGISTER}$MOV_BIN${EXIT}$MOV_BIN"
	BIN_CODE="${BIN_CODE}${SYSCALL}"
	echo -en "${BIN_CODE}" | base64 -w0;
}

function system_call_exec()
{
	local PTR_FILE="$1"
	local CODE=""
	local SYS_EXECVE=$(( 16#3b ))
	#								mem       elf     str
	# 401000:       48 bf 00 20 40 00 00    movabs $0x402000,%rdi #        == 2000 == /bin/sh
	# 401007:       00 00 00
	#CODE="${CODE}${MOV_RDI}$(printEndianValue ${PTR_FILE:=0} $SIZE_32BITS_4BYTES)"
	CODE="${CODE}\x48\xbf\xc0\x00\x01\x00\x00\x00\x00\x00"

	# LEA_RSP_RSI="\x48\x8d\x74\x24\x08";
	# 40100a:       48 8d 74 24 08          lea    0x8(%rsp),%rsi
	# CODE="${CODE}${LEA_RSP_RSI}"
	CODE="${CODE}${MOV_RSI}$(printEndianValue ${PTR_ARGS:=0} $SIZE_32BITS_4BYTES)"

	# 40100f:       ba 00 00 00 00          mov    $0x0,%edx
	CODE="${CODE}${MOV_RDX}$(printEndianValue ${PTR_ENV:=0} $SIZE_32BITS_4BYTES)" # const char *const envp[]

	# 401014:       b8 3b 00 00 00          mov    $0x3b,%eax
	CODE="${CODE}${MOV_RAX}$(printEndianValue ${SYS_EXECVE} $SIZE_32BITS_4BYTES)" # sys_execve (3b)

	# 401019:       0f 05                   syscall
	CODE="${CODE}${SYSCALL}"
	echo -en "${CODE}" | base64 -w0;
}
