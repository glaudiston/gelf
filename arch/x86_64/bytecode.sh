#!/bin/bash
. arch/system_call_linux_x86.sh
. arch/x86_64/add.sh
. arch/x86_64/mul.sh
. arch/x86_64/array.sh
. arch/x86_64/bind.sh
. arch/x86_64/bsr.sh
. arch/x86_64/cmp.sh
. arch/x86_64/compare.sh
. arch/x86_64/concat_symbols.sh
. arch/x86_64/detect_string_length.sh
. arch/x86_64/div10.sh
. arch/x86_64/get_arg.sh
. arch/x86_64/i2s.sh
. arch/x86_64/ilog10.sh
. arch/x86_64/jump.sh
. arch/x86_64/log.sh
. arch/x86_64/memory.sh
. arch/x86_64/mod10.sh
. arch/x86_64/mod_rm.sh
. arch/x86_64/mov.sh
. arch/x86_64/prefix.sh
. arch/x86_64/read_file.sh
. arch/x86_64/registers.sh
. arch/x86_64/s2i.sh
. arch/x86_64/stack.sh
. arch/x86_64/sub.sh
. arch/x86_64/sys_exec.sh
. arch/x86_64/sys_fstat.sh
. arch/x86_64/sys_geteuid.sh
. arch/x86_64/sys_open.sh
. arch/x86_64/sys_read.sh
. arch/x86_64/sys_write.sh
. arch/x86_64/syscall.sh

#
# The x86 instructions have this design in 64bit mode:
# +------------+--------+--------+------------+--------------+-------------+
# |  Prefixes  | OpCode | ModR/M |    SIB     | displacement |  Immediate  |
# | (optional) |        |        | (optional) | (optional)   |  (optional) |
# |            | 1-3 b  | 1 byte |  0-1 byte  |   0-4 bytes  |  0-8 bytes  |
# +------------+--------+--------+------------+--------------+-------------+
#
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

# SEGMENTS
# When the processor starts it is in 16bit real mode, it means it has access to real physical memory address;
# Then BIOS deliver the control to the OS, and the OS sets the memory to virtual mode;
# When a process is started by the OS, it selects some physical memory space according with the "Program Hearders"(that should be called segment headers); And when the process runs it is in a user mode that only see the virtual memory; So each process has his own 0x010078;
#
# In program segments we can set if a virtual memory block is Read, Writable, Executable and the memory block size;
segments=( es cs ss ds fs gs segr6 segr7 )
#The 16-Bit Segment Registers are:
#CS	Code Segment
#DS	Data Segment
#SS	Stack Segment
#ES	Data Segment
#FS	Data Segment
#GS	Data Segment

# We can use mov instruction to mov segment values to registers:
# for ((i=0;i<256;i++));do { xdr | ndisasm -b64 - | head -1; } <<<"488C$(px $i 1)34010203040506070809"; done | less
# and from register to segments:
# for ((i=0;i<256;i++));do { xdr | ndisasm -b64 - | head -1; } <<<"488E$(px $i 1)34010203040506070809"; done | less
#
# Memory is
#
# THE CS (Code Segment)
# CS is the memory segment address(in address space) set for the code.
# Code and stack are in separated segments;
# the DS register is a special register for defining memory segments?

# SIB byte
#  SIB stands for: Scale Index Base
#  The x64 the ModR/M can not handle all register/memory combinations
#  for example when you try to move the rsp to an memory address,
#  the rsp(100) is set to require an additional field the SIB is this additional field
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

# About the "Effective Address":
#
# The offset part of a memory address can be specified directly as a static value (called a displacement) or through an address computation made up of one or more of the following components:
#
# Displacement — An 8-, 16-, or 32-bit value.
# Base — The value in a general-purpose register.
# Index — The value in a general-purpose register.
# Scale factor — A value of 2, 4, or 8 that is multiplied by the index value.
#
# The offset which results from adding these components is called an effective address. Each of these components can have either a positive or negative (2s complement) value, with the exception of the scaling factor.
#
# EffectiveAddress calculates an effective address using:
#
# Base + (Index*Scale) + Displacement
#
# +------------------------+----------------------------+-----------------------------+
# | Mode                   | Intel                      | AT&T                        |
# +------------------------+----------------------------+-----------------------------+
# | Absolute               | MOV EAX, [0100]            | movl           0x0100, %eax |
# | Register               | MOV EAX, [ESI]             | movl           (%esi), %eax |
# | Reg + Off              | MOV EAX, [EBP-8]           | movl         -8(%ebp), %eax |
# | Reg*Scale + Off        | MOV EAX, [EBX*4 + 0100]    | movl   0x100(,%ebx,4), %eax |
# | Base + Reg*Scale + Off | MOV EAX, [EDX + EBX*4 + 8] | movl 0x8(%edx,%ebx,4), %eax |
# +------------------------+----------------------------+-----------------------------+
#
# https://stackoverflow.com/questions/34058101/referencing-the-contents-of-a-memory-location-x86-addressing-modes/34058400#34058400
#
MOV="$(( MODRM_MOD_DISPLACEMENT_32 ))";	# \x80 Move using memory as source (32-bit)
MOVR="$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS ))";	# \xc0 move between registers


TEST="\x85"; # 10000101
IMM="$(( 2#00111000 ))";
MOV_8BIT="\x88";
#MOV="\x89";
MOV_RESOLVE_ADDRESS="\x8b"; # Replace the address pointer with the value pointed from that address
# perform a bitwise AND using register
test(){
	local v1="$1";
	local v2="$2";
	v2="${v2:=$v1}";
	local prefix="$(prefix "$v1" "$v2")";
	local opcode="85";
	if is_8bit_legacy_register "$v1" && is_8bit_legacy_register "$v2"; then
		opcode=84;
	fi;
	local modrm="$(modrm "$v1" "$v2")";
	local sib="";
	local displacement="";
	local immediate="";
	local instr="${prefix}${opcode}${modrm}${sib}${displacement}${immediate}";
	debug "asm: test $v1, $v2; $instr";
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
	local reg=$1;
	local nbits=$2;
	local p=$(prefix "$nbits" "$reg");
	if is_valid_number "$nbits"; then
		local opcode1="c1";
		local opcode2="$( px $(( 16#e8 + reg )) $SIZE_8BITS_1BYTE)";
		local code="";
		code="${code}${p}${opcode1}${opcode2}$(px $((nbits)) $SIZE_8BITS_1BYTE)";
		echo -n "${code}";
		debug "asm: shrq $@; # $code"
		return;
	fi;
	if [ "$nbits" == "cl" ]; then
		local opcode1="d3";
		local opcode2="$( px $(( 16#e8 + reg )) $SIZE_8BITS_1BYTE)";
		local code="";
		code="${code}${p}${opcode1}${opcode2}";
		local rv=$(echo -n "${code}");
		debug "asm: shrq $@; # $rv"
		echo -n $rv;
		return;
	fi;
	error not implemented/supported
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
SHR_V1_rax="$(prefix v1 rax | xd2esc)\xc1\xe8";

SYSCALL="$( printEndianValue $(( 16#050f )) $SIZE_16BITS_2BYTES)"
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


# get_read_size receives a stat address and return the bytecode instructions to recover the length to a target register.
# if no target register is provided it puts the value on the rsi
# this is used when opening a file
function get_read_size()
{
	debug get_read_size
	local stat_addr="$1";
	local target_register="$2";
	local st_size=$((16#30)); # in the stuct stat the offset 0x30 is where we have the file size;
	mov rsi $(( stat_addr + st_size ));
	mov rsi '(rsi)';
	cmp rsi 0; # 64bit cmp rsi, 00
	local default_value_code="$(mov rsi "$PAGESIZE")";
	jg $(xcnt<<<$default_value_code);
	printf "${default_value_code}";
	# TODO
	#if rsi == 0
	#	rsi = pagesize
	#fi
	#
	#if rsi > 0 align it with the next page size multple
}

function getpagesize()
{

	mov rax $((16#3f));	# sys_uname syscall
	# mov rax, 0x3f        ; sysconf syscall number
	mov rdi $((16#18));	# _SC_PAGESIZE parameter
	xor rsi, rsi;		# unused third parameter
	# syscall
	#
	# ; Store the result in the pagesizebuf buffer
	# mov qword [pagesizebuf], rax

	mov rdi $((16#18)); # _SC_PAGESIZE
	syscall;
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
		local array_code="$(mov r15 8 | xd2esc)"; # r15+rsp to ignore the return addr when parsing args
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
				mov $retval_addr rdi;
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
		code="${code}$(mov $retval_addr rdi | xd2esc)";
	fi;
	echo -en "$code" | base64 -w0;
	debug "call_procedure $@:: $code"
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
		mov rdi ${symbol_value:=0};
		if [ "$symbol_type" != $SYMBOL_TYPE_HARD_CODED ]; then
			mov rdi "(rdi)";
		fi;
	fi;
	# run RET
	printf "${NEAR_RET}";
}

function system_call_exit()
{
	local exit_code="$1"
	local symbol_type="$2";
	local code="";
	code="${code}$(mov rax $SYS_EXIT)";
	code="${code}$(mov rdi ${exit_code:=0})";
	if [ "$symbol_type" != $SYMBOL_TYPE_HARD_CODED ]; then
		code="${code}$(mov rdi "(rdi)")";
	fi;
	code="${code}$(syscall)"
	echo -n "${code}" | xdr | base64 -w0;
}

function system_call_fork()
{
	mov rax $SYS_FORK;
	syscall;
}

function system_call_pipe()
{
	local pipe_addr="$1";
	mov rax "${SYS_PIPE}";
	mov rdi "${pipe_addr}";
	syscall;
}

function system_call_wait4()
{
	mov rax ${SYS_WAIT4};
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
	mov rax "${SYS_DUP2}";
	mov rdi "${old_fd_addr}";
	mov rdi "(rdi)";
	mov rsi "${new_fd}";
	syscall;
}

set_increment()
{
	local addr=$1;
	local value=$2;
	local value_type=$3;
	mov rdx "$addr";
	mov rdx "(rdx)";
	if [ "$value" == 1 ]; then
		inc rdx;
	elif [ is_valid_number "$value" -a "$value_type" == $SYMBOL_TYPE_HARD_CODED ]; then
		add rdx "${value}";
	else
		xor rsi rsi;
		mov rsi "${value}";
		mov rsi "(rsi)";
		mov rsi "(rsi)";
		add rdx rsi;
	fi;
	mov "$addr" rdx;
	echo -en "${code}";
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
