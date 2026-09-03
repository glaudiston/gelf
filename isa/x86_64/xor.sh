xor(){
	debug "asm: xor $1 $2"
	local op=31;
	one_byte_operation "$op" "$1" "$2";
}
