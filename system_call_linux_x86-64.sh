#!/bin/bash
# See Table A-2. One-byte Opcode Map on Intel i64 documentation (page 2626)
# See Table B-13.  General Purpose Instruction Formats and Encodings for Non-64-Bit Modes (Contd.) (page 2658)
MOV_RAX="\xb8"
MOV_RDX="\xba"
MOV_RSI="\xbe"
MOV_RDI="\xbf" #32 bit register (4 bytes)

# LEA - Load Effective Address (page 1146)
SYSCALL="\x0f\x05"

function system_call_read()
{
	local string="$1";
	local len="${2}";
	local CODE="";
	SYS_READ=0;
	STDIN=0;
	CODE="${CODE}${MOV_RAX}$(printLittleEndian $SYS_READ 4)";
	CODE="${CODE}${MOV_RDI}$(printLittleEndian $STDIN 4)";
	CODE="${CODE}${MOV_RSI}${string}";
	CODE="${CODE}${MOV_RDX}$(printLittleEndian ${len} 4)";
	CODE="${CODE}${SYSCALL}";
	echo "${CODE}";
}

# given a data address as argument, write it to stdout
function system_call_write()
{
	local DATA_ADDR="$1";
	local DATA_LEN="$2";
	local CODE="";
	SYS_WRITE=1;
	STDOUT=1;
	CODE="${CODE}${MOV_RAX}$(printLittleEndian $SYS_WRITE $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${MOV_RDI}$(printLittleEndian $STDOUT $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${MOV_RSI}${DATA_ADDR}";
	CODE="${CODE}${MOV_RDX}$(printLittleEndian ${DATA_LEN} $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${SYSCALL}";
	echo "${CODE}";
}

function system_call_exit()
{
	local SYS_EXIT=$(( 16#3c ))
	local exit_code="$1"
	local BIN_CODE="";
	local EXIT="$(printLittleEndian $SYS_EXIT $SIZE_32BITS_4BYTES)";
	BIN_CODE="${BIN_CODE}${MOV_RDI}$(printLittleEndian ${exit_code:=0} $SIZE_32BITS_4BYTES)"
	BIN_CODE="${BIN_CODE}${MOV_RAX}${EXIT}"
	BIN_CODE="${BIN_CODE}${SYSCALL}"
	echo -n "${BIN_CODE}"
}

function system_call_exec()
{
	local PTR_FILE="$1"
	local CODE=""
	local SYS_EXECVE=$(( 16#3b ))
	#								mem       elf     str
	# 401000:       48 bf 00 20 40 00 00    movabs $0x402000,%rdi #        == 2000 == /bin/sh
	# 401007:       00 00 00
	#CODE="${CODE}${MOV_RDI}$(printLittleEndian ${PTR_FILE:=0} $SIZE_32BITS_4BYTES)"
	CODE="${CODE}\x48\xbf\xc0\x00\x01\x00\x00\x00\x00\x00"

	# LEA_RSP_RSI="\x48\x8d\x74\x24\x08";
	# 40100a:       48 8d 74 24 08          lea    0x8(%rsp),%rsi
	# CODE="${CODE}${LEA_RSP_RSI}"
	CODE="${CODE}${MOV_RSI}$(printLittleEndian ${PTR_ARGS:=0} $SIZE_32BITS_4BYTES)"

	# 40100f:       ba 00 00 00 00          mov    $0x0,%edx
	CODE="${CODE}${MOV_RDX}$(printLittleEndian ${PTR_ENV:=0} $SIZE_32BITS_4BYTES)" # const char *const envp[]

	# 401014:       b8 3b 00 00 00          mov    $0x3b,%eax
	CODE="${CODE}${MOV_RAX}$(printLittleEndian ${SYS_EXECVE} $SIZE_32BITS_4BYTES)" # sys_execve (3b)

	# 401019:       0f 05                   syscall
	CODE="${CODE}${SYSCALL}"
	echo "${CODE}"
}
