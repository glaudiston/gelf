#!/bin/bash
# System Interrupt call table for 64bit linux:
# http://www.cpu2.net/linuxabi.html
#
# x86 Instruction set
# https://en.wikipedia.org/wiki/X86_instruction_listings#Original_8086.2F8088_instructions
#
# Intel i64 and IA-32 Architectures
# https://software.intel.com/sites/default/files/managed/39/c5/325462-sdm-vol-1-2abcd-3abcd.pdf
# Linux syscall:
# https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
# See Table A-2. One-byte Opcode Map on Intel i64 documentation (page 2626)
# See Table B-13.  General Purpose Instruction Formats and Encodings for Non-64-Bit Modes (Contd.) (page 2658)
MOV_RAX="\xb8"
MOV_RDX="\xba"
MOV_RSI="\xbe"
MOV_RDI="\xbf" #32 bit register (4 bytes)

# JMP
# We have some types of jump
# Relative jumps (short and near):
JMP_SHORT="\xeb"; # followed by a 8-bit signed char (-128 to 127) to move relative to BIP.
JMP_NEAR="\xe9"; # followed by a 32-bit signed integer(-2147483648 to 2147483647).
# Jump to the full virtual address
JMP_RAX="\xff";
JMP_RDI="\xe0";


# LEA - Load Effective Address (page 1146)
SYSCALL="$( printEndianValue $(( 16#050f )) $SIZE_16BITS_2BYTES)"


# system_call_jump should receive the target address and the current BIP.
#   It will select the correct approach for each context based on the JMP alternatives
function system_call_jump()
{
	local TARGET="$1";
	local CURRENT="$2";
	local RELATIVE=$(( TARGET - CURRENT - 4))
	local CODE="";
	if [ "$(( (RELATIVE >= -128) && (RELATIVE <= 127) ))" -eq 1 ]; then
		# jump short
		debug jump short relative $RELATIVE
		local RADDR_V="$( echo -en "\x$(printf %x "${RELATIVE}" | sed 's/.*\(..\)$/\1/g')" )";
		debug RADDR_V=$RADDR_V
		CODE="${CODE}${JMP_SHORT}${RADDR_V}";
		echo -ne "$(echo -en "${CODE}" | base64 -w0),2";
		return;
	fi;
	if [ "$(( (RELATIVE >= - ( 1 << 31 )) && (RELATIVE <= ( 1 << 31 ) -1) ))" -eq 1 ]; then
		# jump near
		local RADDR_V;
		if [ $RELATIVE -lt 0 ]; then
			RADDR_V="$(printEndianValue "$(( RELATIVE + ( 1 << 32 ) ))" $SIZE_32BITS_4BYTES)";
		else
			RADDR_V="$(printEndianValue "${RELATIVE}" $SIZE_32BITS_4BYTE)";
		fi;
		debug "jump near relative ( $RELATIVE, $RADDR_V )";
		CODE="${CODE}${JMP_NEAR}${RADDR_V}";
		echo -ne "$(echo -en "${CODE}" | base64 -w0),5";
		return;
	fi;

	error "JMP not implemented for that relative or absolute value: $RELATIVE"
	echo -ne ",0"
	return;
}

function system_call_read()
{
	local DATA_ADDR="$(printEndianValue "${1}" "$SIZE_32BITS_4BYTES" )";
	local len="${2}";
	local CODE="";
	SYS_READ=0;
	STDIN=0;
	CODE="${CODE}${MOV_RAX}$(printEndianValue $SYS_READ $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${MOV_RDI}$(printEndianValue $STDIN $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${MOV_RSI}${DATA_ADDR}";
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
	local DATA_ADDR="$(printEndianValue "$DATA_ADDR_V" "$SIZE_32BITS_4BYTES")";
	SYS_WRITE=1;
	STDOUT=1;
	local CODE="";
	CODE="${CODE}${MOV_RAX}$(printEndianValue $SYS_WRITE $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${MOV_RDI}$(printEndianValue $STDOUT $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${MOV_RSI}${DATA_ADDR}";
	CODE="${CODE}${MOV_RDX}$(printEndianValue "${DATA_LEN}" $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${SYSCALL}";
	echo -en "${CODE}" | base64 -w0;
}

system_call_exit_len=12
function system_call_exit()
{
	local SYS_EXIT=$(( 16#3c ))
	local exit_code="$1"
	local BIN_CODE="";
	local EXIT="$(printEndianValue $SYS_EXIT $SIZE_32BITS_4BYTES)";
	BIN_CODE="${BIN_CODE}${MOV_RAX}${EXIT}"
	BIN_CODE="${BIN_CODE}${MOV_RDI}$(printEndianValue ${exit_code:=0} $SIZE_32BITS_4BYTES)"
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
