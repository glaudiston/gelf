#!/bin/bash

. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash <<-EOF
	./../../logger/bash/logger.sh
	./one_byte_operation.sh
	./multiple_operation.sh
EOF
and(){
	local v1="${1,,}";
	local v2="${2,,}";
	local prefix opcode modrm dispacement sib imm32
	local code;
	debug "asm: and $*"
	if is_register "$1"; then
		if is_8bit_sint "$2"; then
			multiple_operation and "$1" "$2";
			return;
		fi;
		if is_32bit_sint "$2"; then
			if [[ "$v1" == "rax" ]]; then # rax has its own opcode
			{
				prefix="$(prefix "$v1" "$v2")";
				opcode="25";
				imm32="$(px "$v2" "$SIZE_32BITS_4BYTES")"
				code="${prefix}${opcode}${imm32}"
				printf "%s" "$code";
				return;
			}
			fi;
			multiple_operation and "$1" "$2";
			return;
		fi;
	fi;
	local op=21;
	one_byte_operation "$op" "$1" "$2";
}

