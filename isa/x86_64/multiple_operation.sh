#!/bin/bash

set -euo pipefail
. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";

import_bash <<-EOF
	prefix.sh
	mod_rm.sh
	../../types.sh
	../../logger/bash/logger.sh
EOF

declare -xga multiple_operation_map=( "add" "or" "adc" "ssb" "and" "sub" "xor" "cmp" );
multiple_operation_map_idx(){
	local i l;
	l="${#multiple_operation_map[@]}";
	for (( i=0; i<l; i++ ));
	do
		[ "${multiple_operation_map[$i]}" == "$1" ] && echo $i && break;
	done;
	if [[ $i == $l ]]; then
		error "unsupported operation: $1";
	fi;
}

multiple_operation(){
	local v1 v2;
	local op op_idx;
	local prefix opcode modrm imm;
	local code;
	op="$1";
	v1="$2";
	v2="$3";
	prefix="$(prefix "$v1" "$v2")";
	if is_8bit_sint "$v2"; then
		opcode=83;
		imm="$(px "$v2" "${SIZE_8BITS_1BYTE}")"
	elif is_32bit_sint "$v2"; then
		opcode=81;
		imm="$(px "$v2" "${SIZE_32BITS_4BYTES}")"
	fi;
	op_idx="$(multiple_operation_map_idx "$op")"
	modrm="$(px "$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS | op_idx << 3 | v1 ))" "$SIZE_8BITS_1BYTE")";
	#modrm=$(modrm "$v1" "$op_idx")
	code="${prefix}${opcode}${modrm}${imm}"
	printf %s "$code"
	debug "asm: $op $v1 $v2; # $code"
}
