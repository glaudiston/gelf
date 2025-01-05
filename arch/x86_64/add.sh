#!/bin/bash
. $(dirname $(realpath $BASH_SOURCE))/prefix.sh
# add: given a value or a register on r1, add it to r2
# r1: can be a register id, a integer value or a address value
# 	input: register or "[address]" or integer value
# 	output: not changed
# r2: register result of add r1 and r2
# 	input: register
# 	output: added r1 and r2
ADD_FULL="\x81"; # ADD 32 or 64 bit operand (depend on ModR/M
ADD_M64="$(prefix rax | xd2esc)${ADD_FULL}";
ADD_M64_rdi="${ADD_M64}";
ADD_EAX_EAX="\x01\xc0";
ADD_rsi_rdx="$(prefix rsi rdx | xd2esc)\x01\xF2";
ADD_V4_rdx="$(prefix v4 rdx | xd2esc)\x81\xC2";
ADD_V4_rdi="$(prefix v4 rdi | xd2esc)\x81\xC7";
ADD_r15_r14="$(prefix r15 r14 | xd2esc)\x01\xfe";
ADD_r15_rax="$(prefix r15 rax | xd2esc)\x01\xF8";
ADD_r15_rsi="$(prefix r15 rsi | xd2esc)\x01\xFE";
ADD_rdx_r8="$(prefix rdx r8 | xd2esc)\x01\xd0";
add(){
	local ADD_SHORT="83"; # ADD 8 or 16 bit operand (depend on ModR/M opcode first bit(most significant (bit 7)) been zero) and the ModR/M opcode
	local r1="$1";
	local r2="$2";
	local code="";
	local p=$(prefix "$r1" "$r2");
	if [ "$r2" = "AL" ]; then
		ADD_AL="04";
		code="${code}${ADD_AL}$(px "$r1" ${SIZE_8BITS_1BYTE})";
		echo -n "${code}";
		debug "asm: add $@; # $(echo -n "$code")"
		return
	fi;
	if is_8bit_register "$r1" && is_8bit_register "$r2"; then
		b1="00";
		b2="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + (r1 << 3) + r2 )) $SIZE_8BITS_1BYTE)";
		code="$p$b1$b2";
		echo -n $code;
		debug "add $@; # $code";
		return;
	fi;
	if is_register "$r1"; then
	{
		if is_register "$r2"; then
		{
			local opadd="${p}01";
			local rv=$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + MODRM_OPCODE_ADD + (${r1,,} << 3) + ${r2,,} ));
			r=$(px $rv $SIZE_8BITS_1BYTE);
			code="${code}${opadd}${r}";
			echo -n "${code}";
			debug "asm: add $@; # $(echo -n "$code")"
			return;
		}
		fi;
	}
	elif is_valid_number "$r1"; then
	{
		if is_register "$r2"; then
			if [ $r1 -lt 128 ]; then
			{
				r=$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + MODRM_OPCODE_ADD + ${r2,,} ))
				code="${code}${p}${ADD_SHORT}$(px $r $SIZE_8BITS_1BYTE)";
				code="${code}$(px $r1 $SIZE_8BITS_1BYTE)";
				debug "asm: add $@; # $(echo -n "$code")"
				echo -n "${code}";
				return;
			}
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

