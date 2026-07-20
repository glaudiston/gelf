#!/bin/bash

. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash <<-EOF
	./../../logger/bash/logger.sh
	./one_byte_operation.sh
	./multiple_one_byte_operations.sh
EOF
and(){
	debug "asm: and $@"
	if is_register "$1" && is_8bit_sint "$2"; then
		multiple_one_byte_operation and "$1" "$2";
		return;
	fi;
	local op=21;
	one_byte_operation "$op" "$1" "$2";
}

