array_add(){
	local array_addr="$1";
	local array_size="$2";
	local item_addr="$3";
	local item_type="$4";
	local item_value="$5";
	local code="";
	if [ "$item_addr" == "" ]; then
	    # this is the case of hard coded values SYMBOL_TYPE_HARD_CODED=0;
		# we can't put the direct value because it will fail to be parsed
		# when sent over arguments. it need to be ref. but we can't push twice
		#
		push_imm "$item_value";
	else
		push_imm "$item_addr";
	fi;
}
array_end(){
	local array_addr="$1";
	local array_size="$2";
	# save the array addr outside the stack(in the main memory)
	mov rsp rax;
	add $(( array_size * 8 -8)) rax;
	mov rax "$array_addr";
	# put the array size in the stack
	push_imm $array_size;
}
