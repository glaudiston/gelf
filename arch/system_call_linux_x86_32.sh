#!/bin/bash
#
# This should have all 32bit specific code
# The ones shared to x64_64 should be at system_call_x64.sh
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
# x86 has:
# 8 general purpose registers
#  EAX(32): Accumulator: Used In Arithmetic operations
#  ECX(32): Counter: Used in loops and shift/rotate instructions
#  EDX(32): Data: Used in arithmetic operations and I/O operations
#  EBX(32): Base: Used as a pointer to data
#  ESP(32): Stack Pointer: Points to top of stack
#  EBP(32): Stack Base Pointer: Points to base of stack
#  ESI(32): Points to source in stream operations
#  EDI(32): Points to destination in streams operations
# 6 segment registers: points to memory segment addresses ( but uses pagin instead segmentation)
# 1 flag register: used to support arithmetic functions and debugging.
#  EFLAG(32)
# Instruction Pointer: Address of the next instruction to execute.
#  EIP(32)
#
. arch/system_call_linux_x86.sh

MOV_EAX="\xb8";
MOV_EDX="\xba";
MOV_ESI="\xbe";
MOV_EDI="\xbf";

# JMP
# We have some types of jump
# Relative jumps (short and near):
JMP_SHORT="\xeb"; # followed by a 8-bit signed char (-128 to 127) to move relative to BIP.
JMP_NEAR="\xe9"; # followed by a 32-bit signed integer(-2147483648 to 2147483647).
# Jump to the full virtual address
JMP_EAX="\xff";
JMP_EDI="\xe0";

#81 C7 01 02 03 04     add    rdi, 0x04030201
ADD_EDI="\x81";

# LEA - Load Effective Address (page 1146)
SYSCALL="$( printEndianValue $(( 16#80 )) $SIZE_16BITS_2BYTES)"

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
	OPCODE_SIZE=1;
	DISPLACEMENT_BITS=32; # 4 bytes
	local JUMP_NEAR_SIZE=$(( OPCODE_SIZE + DISPLACEMENT_BITS / 8 )); # 5 bytes

	local short_jump_response=$(bytecode_jump_short "$TARGET_ADDR" "${CURRENT_ADDR}")
	if [ "$(echo "${short_jump_response}" | cut -d, -f2)" -gt -1 ];then
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
	# mov [esp], eax
	# mov eip, [esp]
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
	OPCODE_SIZE=1;
	DISPLACEMENT_BITS=32; # 4 bytes
	local CALL_NEAR_SIZE=$(( OPCODE_SIZE + DISPLACEMENT_BITS / 8 )); # 5 bytes
	local RELATIVE=$(( TARGET - CURRENT - CALL_NEAR_SIZE ))
	if [ "$(( (RELATIVE >= - ( 1 << ( DISPLACEMENT_BITS -1 ) )) && (RELATIVE <= ( 1 << ( DISPLACEMENT_BITS -1) ) -1) ))" -eq 1 ]; then
		local OPCODE_CALL_NEAR="\xe8"; #direct call with 32bit displacement
		local NEAR_ADDR_V="$(printEndianValue $RELATIVE $SIZE_32BITS_4BYTES)" # call addr
		local BYTES="${OPCODE_CALL_NEAR}${NEAR_ADDR_V}"
		echo $(echo -en "$BYTES" | base64 -w0),5;
		return
	fi;
	error call not implemented for this address size: CURRENT: $CURRENT, TARGET: $TARGET, RELATIVE: $RELATIVE;


	FAR_CALL="\x9a";
	SUB_ESP="${M64}\x83\xEC\x28" # sub esp, 28
	addr="$(( 16#000100b8 ))"
	BYTES="\xe8${CALL_ADDR}";
	echo -en "$BYTES" | base64 -w0;
}

function system_call_push_stack()
{
	# PUSHA/PUSHAD – Push All General Registers 0110 0000
	
	local PUSH="\x68";
	local ADDR_V="$(printEndianValue )"
	echo "${PUSH}${ADDR_V}"
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


function system_call_read()
{
	local DATA_ADDR="$(printEndianValue "${1}" "$SIZE_32BITS_4BYTES" )";
	local len="${2}";
	local CODE="";
	SYS_READ=0;
	STDIN=0;
	CODE="${CODE}${MOV_EAX}$(printEndianValue $SYS_READ $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${MOV_EDI}$(printEndianValue $STDIN $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${MOV_ESI}${DATA_ADDR}";
	CODE="${CODE}${MOV_EDX}$(printEndianValue ${len} $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${SYSCALL}";
	echo -en "${CODE}" | base64 -w0;
}

system_call_write_len=22
# given a data address as argument, write it to stdout
function system_call_write()
{
	local STDOUT="$1";
	local DATA_ADDR_V="$2";
	local DATA_LEN="$3";
	local DATA_ADDR="$(printEndianValue "$DATA_ADDR_V" "$SIZE_32BITS_4BYTES")";
	SYS_WRITE=1;
	local CODE="";
	CODE="${CODE}${MOV_EAX}$(printEndianValue $SYS_WRITE $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${MOV_EDI}$(printEndianValue $STDOUT $SIZE_32BITS_4BYTES)";
	CODE="${CODE}${MOV_ESI}${DATA_ADDR}";
	CODE="${CODE}${MOV_EDX}$(printEndianValue "${DATA_LEN}" $SIZE_32BITS_4BYTES)";
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

function system_call_fork()
{
	local SYS_FORK=57
	local FORK=$(printEndianValue ${SYS_FORK} ${SIZE_32BITS_4BYTES})
	local CODE="";
	CODE="${CODE}${MOV_EAX}${FORK}"
	CODE="${CODE}${SYSCALL}"
	echo -en "${CODE}" | base64 -w0;
	echo -en ",$(echo -en "${CODE}" | wc -c )";
}

function system_call_exec()
{
	local PTR_FILE="$1"
	#debug "PTR_FILE=$( printf %x "${PTR_FILE}")"
	#local PTR_ARGS="$1"
	#local PTR_ENV="$1"
	local CODE="";
	CODE="${CODE}$(system_call_fork | cut -d, -f1 | base64 -d | xxd --ps | sed "s/\(..\)/\\\\x\1/g")";
	# TODO: CMP ? then (0x3d) rAx, lz
	local TWOBYTE_INSTRUCTION_PREFIX="\0f"; # The first byte "0F" is the opcode for the two-byte instruction prefix that indicates the following instruction is a conditional jump.
	CODE="${CODE}\x83\xf8\x00"; # 32bit cmp eax, 00
	#CODE="${CODE}\x85\x06\x00\x00\x00"; # The second byte "85" is the opcode for the JNE instruction. The following four bytes "06 00 00 00" represent the signed 32-bit offset from the current instruction to the target label.
	# TODO: JNE ?
	#CODE=${CODE}${cmp}$(printEndianValue 0 ${SIZE_32BITS_4BYTES})$(printEndianValue $rax ${})) ; rax receives 0 for the child and the child pid on the parent
	# je child_process_only # only on the child, jump over next line to execute the execve code
	# jmp end # if reach this (is parent) then jump over all sys_execve instructions to the end and do nothing
	# child_process_only:
	local SYS_EXECVE=$(( 16#3b ));
	#								mem       elf     str
	# 401000:       bf 00 20 40 00 00    movabs $0x402000,%rdi #        == 2000 == /bin/sh
	# 401007:       00 00 00
	#CODE="${CODE}${MOV_EDI}$(printEndianValue ${PTR_FILE:=0} ${SIZE_32BITS_4BYTES})"
	#CODE="${CODE}\xbf\xc0\x00\x01\x00\x00\x00\x00\x00"
	CODE="${CODE}${MOV_M64_RDI}$(printEndianValue ${PTR_FILE:=0} ${SIZE_64BITS_8BYTES})"

	# LEA_ESP_ESI="\x8d\x74\x24\x08";
	# 40100a:       8d 74 24 08          lea    0x8(%esp),%esi
	# CODE="${CODE}${LEA_ESP_ESI}"
	CODE="${CODE}${MOV_ESI}$(printEndianValue ${PTR_ARGS:=0} ${SIZE_32BITS_4BYTES})"

	# 40100f:       ba 00 00 00 00          mov    $0x0,%edx
	CODE="${CODE}${MOV_EDX}$(printEndianValue ${PTR_ENV:=0} ${SIZE_32BITS_4BYTES})" # const char *const envp[]

	# 401014:       b8 3b 00 00 00          mov    $0x3b,%eax
	CODE="${CODE}${MOV_EAX}$(printEndianValue ${SYS_EXECVE} ${SIZE_32BITS_4BYTES})" # sys_execve (3b)

	# 401019:       0f 05                   syscall
	CODE="${CODE}${SYSCALL}"
	# end:
	echo -en "${CODE}" | base64 -w0;
	echo -en ",$(echo -en "${CODE}" | wc -c )";
}
