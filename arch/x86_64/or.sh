#!/bin/bash
import_bash <<-EOF
	../../logger/bash/logger.sh
	./one_byte_operation.sh
	./multiple_one_byte_operations.sh
EOF
or(){
	debug "asm: or $@"
	if is_register "$1" && is_8bit_sint "$2"; then
		multiple_one_byte_operation or "$1" "$2";
		return;
	fi
	local op=09;
	one_byte_operation "$op" "$1" "$2";
}

# accept args to the bash script, useful for debugging
[ "$#" -gt 0 ] && or "$@" || :;

