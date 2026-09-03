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
adc(){
	debug "asm: adc $@"
	if is_register "$1" && is_8bit_sint "$2"; then
		multiple_operation adc "$1" "$2";
		return;
	fi
	if is_register "$1" && is_32bit_sint "$2"; then
		if [[ "$1" == "rax" ]]; then
			local code;
			prefix=$(prefix "$1" "$2")
			opcode="$(px 21 $SIZE_8BITS_1BYTE)"
			imm32=$(px "$2" "$SIZE_32BITS_4BYTES")
			code="${prefix}${opcode}${imm32}"
			printf %s "$code";
			return;
		fi;
		multiple_operation adc "$1" "$2";
		return;
	fi
	local idx;
	idx=$(multiple_operation_map_idx adc)
	local op=$(( 16#09 + idx));
	one_byte_operation "$op" "$1" "$2";
}

# accept args to the bash script, useful for debugging
[ "$#" -gt 0 ] && adc "$@" || :;


