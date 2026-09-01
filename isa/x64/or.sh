#!/bin/bash
. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash <<-EOF
	./prefix.sh
	./mod_rm.sh
	../../logger/bash/logger.sh
	../../utils.sh
	./one_byte_operation.sh
	./multiple_operation.sh
EOF
or(){
	debug "asm: or $@"
	if is_register "$1" && is_8bit_sint "$2"; then
		multiple_operation or "$1" "$2";
		return;
	fi
	if is_register "$1" && is_32bit_sint "$2"; then
		if [[ "$1" == "rax" ]]; then
			local code;
			prefix=$(prefix "$1" "$2")
			opcode=0d
			imm32=$(px "$2" "$SIZE_32BITS_4BYTES")
			code="${prefix}${opcode}${imm32}"
			printf %s "$code";
			return;
		fi;
		multiple_operation or "$1" "$2";
		return;
	fi
	local op=09;
	one_byte_operation "$op" "$1" "$2";
}

# accept args to the bash script, useful for debugging
[ "$#" -gt 0 ] && or "$@" || :;

