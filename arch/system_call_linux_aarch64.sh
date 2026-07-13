#!/bin/bash
#
# Author: Glaudiston Gomes da Silva
#
# refs:
# https://docs.rs/syscall-numbers/latest/syscall_numbers/aarch64/index.html
# https://github.com/xcellerator/libgolf/tree/main/examples/03_aarch64
# System Interrupt call table for 64bit aarch64 linux:
# Linux syscall:
# https://syscalls.w3challs.com/?arch=arm_strong
# https://github.com/torvalds/linux/blob/v4.17/include/uapi/asm-generic/unistd.h
#
# Special thanks to: Nate Eldredge
#   https://stackoverflow.com/questions/74532163/elf-aarch64-golfed-with-sys-write/74534626#74534626
#
MOV="d280"
MOVK="f2a0"
LDR="5800"
MOV_BIN=$(printLittleEndian $(( 16#${MOV} )) $SIZE_16BITS_2BYTES)
LDR_BIN=$(printLittleEndian $(( 16#${LDR} )) $SIZE_16BITS_2BYTES)
# register vars just for readability
r0=0
r1=1
r2=2
r3=3
r4=4
r5=5
r6=6
r7=7
r8=8


# LEA - Load Effective Address
SYSCALL="\x01\x00\x00\xd4"

function system_call_read()
{
	local string="$1";
	local len="${2}";
	local CODE="";
	SYS_READ=3f;
	STDIN=0;
	CODE="${CODE}${MOV_RAX}$(printEndianValue $SYS_READ $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${MOV_RDI}$(printEndianValue $STDIN $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${MOV_RSI}${string}";
	CODE="${CODE}${MOV_RDX}$(printEndianValue ${len} $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${SYSCALL}";
	echo -en "${CODE}" | base64 -w0;
}

system_call_write_len=24
# given a data address as argument, write it to stdout
function system_call_write()
{
	local symbol_type="$1";
	local data_output="$2";
	local DATA_ADDR_V="$3";
	local DATA_LEN="$4";
	local instr_offset="$5";
	local CODE="";
	local DATA_ADDR="$(printEndianValue $DATA_ADDR_V $SIZE_32BITS_4BYTES)";
	STDOUT=1;

	local sys_write='40';
	local sys_write_bin="$(aarch64_instr_value r8 "$(( 16#${sys_write} ))")";

	local output_fd_bin="$(aarch64_instr_value r0 "${STDOUT}")";
	debug data addr=$DATA_ADDR_V 
	local data_addr_bin="$(aarch64_instr_value r1 "$(( ${DATA_ADDR_V} - (1<<16) )) ")"
	local data_size_bin="$(aarch64_instr_value r2 "${DATA_LEN}")";

	local BIN_CODE="";
	BIN_CODE="${BIN_CODE}$(aarch64_mov "${output_fd_bin}")";
	BIN_CODE="${BIN_CODE}$(aarch64_mov "${data_addr_bin}")";
	BIN_CODE="${BIN_CODE}$(aarch64_movk "0021")";
	BIN_CODE="${BIN_CODE}$(aarch64_mov "${data_size_bin}")";
	BIN_CODE="${BIN_CODE}$(aarch64_mov "${sys_write_bin}")";
	BIN_CODE="${BIN_CODE}${SYSCALL}";
	echo -en "${BIN_CODE}" | base64 -w0;
}

function aarch64_instr_value()
{
	# 000 00000001 00000
	#  |  ---+---- -----> 5 bits defines the register x0
	#  |     +-> 8 bits define the value 1
	#  +-> No Idea
	register="$1"
	value="$2"
	v=$(( ( value << 5 ) + ${register} ))
	# join and apply little endian
	printEndianValue "$v" "$SIZE_16BITS_2BYTES"
}

system_call_exit_len=12

function aarch64_ldr(){
	local VALUE="$1"
	echo -n "${VALUE}${LDR_BIN}"
}

function aarch64_mov(){
	local VALUE="$1"
	echo -n "${VALUE}${MOV_BIN}"
}

function aarch64_movk() {
	echo -n "$(printEndianValue $(( 16#${MOVK}${1} )) $SIZE_32BITS_4BYTES)"
}

function system_call_exit()
{
	# mov x0, #0      @ Return value is 0
	# mov x8, #0x5d   @ 0x5d is sys_exit
	# svc #0          @ Interrupt to svc mode (syscall)
	#local SYS_EXIT=$(( ( 16#5d << 5) + r8 ))
	#local EXIT_BIN="$(printEndianValue $SYS_EXIT $SIZE_16BITS_2BYTES)";
	local SYS_EXIT=5d
	local exit_bin=$( aarch64_instr_value r8 "$(( 16#${SYS_EXIT} ))" )
	local exit_code="$1"
	local value_bin="$(aarch64_instr_value r0 $exit_code)"

	local BIN_CODE="";
	BIN_CODE="${BIN_CODE}$(aarch64_mov "${value_bin}")"
	BIN_CODE="${BIN_CODE}$(aarch64_mov "${exit_bin}")"
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
	echo -n ",27";
}
