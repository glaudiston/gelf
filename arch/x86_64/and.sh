. $(dirname $(realpath $BASH_SOURCE))/../../pragma_once.sh || return 0
. $(dirname $(realpath $BASH_SOURCE))/../../logger.sh
. $(dirname $(realpath $BASH_SOURCE))/one_byte_operation.sh
and(){
	debug "asm: and $@"
	local op=21;
	one_byte_operation "$op" "$1" "$2";
}

