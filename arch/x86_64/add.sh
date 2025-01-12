#!/bin/bash
if ! declare -F add >/dev/null; then
. $(dirname $(realpath $BASH_SOURCE))/prefix.sh
. $(dirname $(realpath $BASH_SOURCE))/mod_rm.sh
. $(dirname $(realpath $BASH_SOURCE))/../../logger.sh
. $(dirname $(realpath $BASH_SOURCE))/../../utils.sh
. $(dirname $(realpath $BASH_SOURCE))/multiple_one_byte_operations.sh
# add: given a value or a register on addend, add it to augend
# addend: can be a register id, a integer value or a address value
# 	input: register or "[address]" or integer value
# 	output: not changed
# augend: register result of add addend and augend
# 	input: register
# 	output: added addend and augend
ADD_FULL="\x81"; # ADD 32 or 64 bit operand (depend on ModR/M
ADD_M64="$(prefix rax | xd2esc)${ADD_FULL}";
ADD_M64_rdi="${ADD_M64}";
ADD_EAX_EAX="\x01\xc0";
ADD_rsi_rdx="$(prefix rsi rdx | xd2esc)\x01\xF2";
ADD_V4_rdx="$(prefix v4 rdx | xd2esc)\x81\xC2";
ADD_V4_rdi="$(prefix v4 rdi | xd2esc)\x81\xC7";
ADD_addend5_addend4="$(prefix addend5 addend4 | xd2esc)\x01\xfe";
ADD_addend5_rax="$(prefix addend5 rax | xd2esc)\x01\xF8";
ADD_addend5_rsi="$(prefix addend5 rsi | xd2esc)\x01\xFE";
ADD_rdx_r8="$(prefix rdx r8 | xd2esc)\x01\xd0";
add(){
	debug "begin: add $@"
	local augend="$1";
	local addend="$2";
	if is_register "$addend" && is_8bit_sint "$augend"; then
		multiple_one_byte_operation add "$addend" "$augend";
		return;
	fi
	local ADD_SHORT="83"; # ADD 8 or 16 bit operand (depend on ModR/M opcode first bit(most significant (bit 7)) been zero) and the ModR/M opcode
	local code="";
	local p=$(prefix "$augend" "$addend");
	if [ "$augend" = "AL" ]; then
		ADD_AL="04";
		code="${code}${ADD_AL}$(px "$addend" ${SIZE_8BITS_1BYTE})";
		echo -n "${code}";
		debug "asm: add $@; # $(echo -n "$code")"
		return
	fi;
	if is_8bit_register "$addend" && is_8bit_register "$augend"; then
		b1="00";
		b2="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + (addend << 3) + augend )) $SIZE_8BITS_1BYTE)";
		code="$p$b1$b2";
		echo -n $code;
		debug "add $@; # $code";
		return;
	fi;
	if is_register "$addend"; then
	{
		if is_register "$augend"; then
		{
			local opadd="${p}01";
			local rv=$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + MODRM_OPCODE_ADD + (${addend,,} << 3) + ${augend,,} ));
			r=$(px $rv $SIZE_8BITS_1BYTE);
			code="${code}${opadd}${r}";
			echo -n "${code}";
			debug "asm: add $@; # $(echo -n "$code")"
			return;
		}
		fi;
	}
	elif is_valid_number "$addend"; then
	{
		if is_register "$augend"; then
			if [ $addend -lt 128 ]; then
			{
				r=$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + MODRM_OPCODE_ADD + ${augend,,} ))
				code="${code}${p}${ADD_SHORT}$(px $r $SIZE_8BITS_1BYTE)";
				code="${code}$(px $addend $SIZE_8BITS_1BYTE)";
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
fi;
