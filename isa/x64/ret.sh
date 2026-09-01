#!/bin/bash

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
			mov rdi [rdi];
		fi;
	fi;
	# run RET
	printf "${NEAR_RET}";
}

