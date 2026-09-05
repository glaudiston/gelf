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
sbb(){
	debug "asm: sbb $@"
	local a b;
	a="${1:-}";
	b="${2:-}";
	if is_register "$a" && is_8bit_sint "$b"; then
		multiple_operation sbb "$a" "$b";
		return;
	fi
	if is_register "$a" && is_32bit_sint "$b"; then
		if [[ "$1" == "rax" ]]; then
			local code;
			prefix=$(prefix "$a" "$b")
			opcode=1d
			imm32=$(px "$b" "$SIZE_32BITS_4BYTES")
			code="${prefix}${opcode}${imm32}"
			printf %s "$code";
			return;
		fi;
		multiple_operation sbb "$a" "$b";
		return;
	fi
	local op=19;
	one_byte_operation "$op" "$a" "$b";
}

# accept args to the bash script, useful fsbb debugging
[ "$#" -gt 1 ] && sbb "$@" || :;


