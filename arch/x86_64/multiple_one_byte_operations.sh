#!/bin/bash
import_bash <<-EOF
	./../../types.sh
	./prefix.sh
	./mod_rm.sh
	./registers.sh
EOF
declare -xga one_byte_op_map=( "add" "or" "adc" "ssb" "and" "sub" "xor" "cmp" );
one_byte_op_map_idx(){
	for (( i=0; i<${#one_byte_op_map[@]}; i++ ));
	do
		[ "${one_byte_op_map[$i]}" == "$1" ] && echo $i && break;
	done;
}

multiple_one_byte_operation()
{
	local prefix opcode modrm imm8;
	local code;
	local op op_idx v1 v2;
	op="$1";
	v1="$2";
	v2="$3";
	prefix=$(prefix "$v1" "$v2");
	opcode=83;
	op_idx=$(one_byte_op_map_idx "$op");
	modrm="$(px "$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS | op_idx << 3 | v1 ))" "$SIZE_8BITS_1BYTE")";
	imm8="";
	if is_valid_number $v2; then
		imm8="$(px "$v2" "$SIZE_8BITS_1BYTE")";
	fi;
	code="${prefix}${opcode}${modrm}${imm8}";
	printf %s "$code"
	debug "asm: $op $v1 $v2; # $code"
}
