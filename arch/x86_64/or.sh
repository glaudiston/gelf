#!/bin/bash
. $(dirname $(realpath $BASH_SOURCE))/../../pragma_once.sh && return 0
. $(dirname $(realpath $BASH_SOURCE))/../../logger.sh
. $(dirname $(realpath $BASH_SOURCE))/one_byte_operation.sh
. $(dirname $(realpath $BASH_SOURCE))/multiple_one_byte_operations.sh
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
[ "$#" -gt 0 ] && or "$@"
