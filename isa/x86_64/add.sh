#!/bin/bash
. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash <<-EOF
	./prefix.sh
	./mod_rm.sh
	../../logger/bash/logger.sh
	../../utils.sh
	./multiple_operation.sh
EOF
# add: given a value or a register on addend, add it to augend
# addend: can be a register id, a integer value or a address value
# 	input: register or "[address]" or integer value
# 	output: not changed
# augend: register result of add addend and augend
# 	input: register
# 	output: added addend and augend
add(){
	debug "begin: add $1 $2"
	local augend="$1";
	local addend="$2";
	local prefix opcode modrm imm32;
	local modrm_opcode;
	modrm_opcode="$(multiple_operation_map_idx add)"
	if is_register "$addend" && is_8bit_sint "$augend"; then
		multiple_operation add "$addend" "$augend";
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
	if is_8bit_register "$augend" && is_8bit_register "$addend"; then
		b1="00";
		b2="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + (addend << 3) + augend )) $SIZE_8BITS_1BYTE)";
		code="$p$b1$b2";
		echo -n $code;
		debug "add $@; # $code";
		return;
	fi;
	if is_register "$augend" && is_register "$addend"; then
	{
			local opadd="${p}01";
			local rv=$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + modrm_opcode + (${addend,,} << 3) + ${augend,,} ));
			r=$(px $rv $SIZE_8BITS_1BYTE);
			code="${code}${opadd}${r}";
			echo -n "${code}";
			debug "asm: add $@; # $(echo -n "$code")"
			return;
	}
	elif is_register "$augend" && is_valid_number "$addend"; then
	{
		if [[ "$(number_bits "$addend")" -le 8 ]]; then
		{
				r=$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + modrm_opcode + ${augend,,} ))
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
		error "mem ref not implemented yet: [add $1 $2]"
	}
	fi;
	error "not implemented: add $1 $2"
};
