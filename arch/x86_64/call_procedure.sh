#!/bin/bash

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
	stack_mng=$({
		push rbp; # save previous base stack pointer;
		mov rbp rsp; # set new base stack pointer
	});
	printf $stack_mng;
	stack_mng_size=$(xcnt<<<$stack_mng)
	CURRENT=$(( CURRENT + stack_mng_size ));
	if [ "$ARGS_TYPE" == $SYMBOL_TYPE_ARRAY ]; then
		array_code="$(mov r15 16)"; # r15+rsp to ignore the return addr and the rbp when parsing args
		code="${code}${array_code}";
		array_code_size="$(xcnt<<<"$array_code")";
		CURRENT=$((CURRENT + array_code_size)); # append current bytecode size
		printf $code;
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
		local OPCODE_CALL_NEAR="e8"; #direct call with 32bit displacement
		local NEAR_ADDR_V="$(px $RELATIVE $SIZE_32BITS_4BYTES)"; # call addr
		printf "${OPCODE_CALL_NEAR}${NEAR_ADDR_V}";
		if [ "$retval_addr" != "" ]; then
			#mov "(rdi)" rdi;
			mov $retval_addr rdi;
		fi;
		pop rbp;
		return;
	fi;
	error "call not implemented for this address size: CURRENT: $CURRENT, TARGET: $TARGET, RELATIVE: $RELATIVE";

	FAR_CALL="9a";
	MODRM="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + MODRM_OPCODE_SUB + rsp )) $SIZE_8BITS_1BYTE)";
	addr="$(( 16#000100b8 ))"
	BYTES="e8${CALL_ADDR}";
	printf "${BYTES}";
	if [ "$retval_addr" != "" ]; then
		#mov "(rdi)" rdi;
		mov $retval_addr rdi;
	fi;
}

