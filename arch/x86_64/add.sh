#!/bin/bash
. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash <<-EOF
	./prefix.sh
	./mod_rm.sh
	../../logger/bash/logger.sh
	../../utils.sh
	./multiple_one_byte_operations.sh
EOF
# add: given a value or a register on addend, add it to augend
# addend: can be a register id, a integer value or a address value
# 	input: register or "[address]" or integer value
# 	output: not changed
# augend: register result of add addend and augend
# 	input: register
# 	output: added addend and augend
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
	local prefix opcode modrm imm32;
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
	elif is_register "$augend" && is_valid_number "$addend"; then
	{
		if [[ "$(number_bits "$addend")" -le 8 ]]; then
		{
				r=$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + MODRM_OPCODE_ADD + ${augend,,} ))
				code="${code}${p}${ADD_SHORT}$(px "$r" "$SIZE_8BITS_1BYTE")";
				code="${code}$(px "$addend" "$SIZE_8BITS_1BYTE")";
				debug "asm: add $*; # $(echo -n "$code")"
				echo -n "${code}";
				return;
		}
		fi;
		if [[ "$augend" == rax ]]; then
			prefix=$p
			opcode=05; # 32bit addend
			imm32="$(px "$addend" "$SIZE_32BITS_4BYTES")"
			code="${prefix}${opcode}${imm32}";
			debug "asm: add $*; # $(echo -n "$code")"
			echo -n "${code}";
			return
		fi;
		prefix=$p
		opcode=81; # 32bit addend
		modrm="$(px "$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS | augend ))" "$SIZE_8BITS_1BYTE")";
		imm32="$(px "$addend" "$SIZE_32BITS_4BYTES")"
		code="${prefix}${opcode}${modrm}${imm32}";
		debug "asm: add $*; # $(echo -n "$code")"
		echo -n "${code}";
		return;
	}
	else
	{
		error "mem ref not implemented yet: [add $@]"
	}
	fi;
	error "not implemented: add $@"
};
