#!/bin/bash
import_bash <<-EOF
	./../../types.sh
	./prefix.sh
	./mod_rm.sh
EOF
declare -a one_byte_op_map=( "add" "or" "adc" "ssb" "and" "sub" "xor" "cmp" );
one_byte_op_map_idx(){
	for (( i=0; i<${#one_byte_op_map[@]}; i++ ));
	do
		[ "${one_byte_op_map[$i]}" == "$1" ] && echo $i && break;
	done;
}
multiple_one_byte_operation()
{
	local prefix;
	prefix=$(rex "$2" "$3");
	local reg=$2;
	local opcode=83;
	local op=$1;
	local op_idx;
	op_idx=$(one_byte_op_map_idx "$op");
	debug "$op $reg"
	local v=0; # this value was found by comparing with the nasm, i don't understand it yet
	[[ "$op" == or ]] && v=8; # 	2#----1--- 
	[[ "$op" == and ]] && v=32; #	2#--1-----
	local modrm=$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS | (op_idx << 3) | reg | v)) $SIZE_8BITS_1BYTE);
	local imm8=$(px $3 $SIZE_8BITS_1BYTE);
	echo -n "${prefix}${opcode}${modrm}${imm8}";
}
