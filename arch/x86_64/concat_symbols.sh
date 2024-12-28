# concat_symbol_instr set addr to dyn_addr or static
# in the first item(idx=1) r8 will be cleared and the appended size will be add in r8 for each call
concat_symbol_instr(){
	#TODO can be improved to use MOVSQ
	local addr="$1";
	local dyn_addr="$2";
	local size="$3";
	local idx="$4";
	local code="";
	#local mmap_size_code="$(mov $(( 1 << 12 )) rsi)";
	#local mmap_code="$(sys_mmap "${mmap_size_code}")"
	# unable to move addr to addr;
	# so let's mov addr to a reg,
	# then reg to addr;
	if [ "$idx" == 1 ]; then # on first item zero r8 to accum the size
		code="${code}$({
			xor r8 r8;
			push r8;	# create zeroed target space at stack;
			mov rsp $dyn_addr;
		})";
	fi;
	if [ "$size" -eq -1 ]; then
		code="${code}$({
			mov "(${addr})" rsi; # source is addr
			detect_string_length rsi rdx rax; # the return is set at rdx
			mov rdx rcx;
		})"; # but we need it on rcx because REP decrements it
	elif [ "$size" -eq -2 ]; then # procedure pointer
		code="${code}$({
			mov "($addr)" rsi; # source addr
			# TODO: how to manage to con
			# the return is set at rdx
			mov rdx rcx;
		})"; # but we need it on rcx because REP decrements it
		echo -en "${code}";
		return;
	else
		code="${code}$({
			mov "$addr" rsi; # source addr
			mov $size rcx;
		})";
	fi;
	code="${code}$(mov rsp rdi)"; # target addr
	#code="${code}${MOV_rax_rdi}";
	local ADD_r8_rdi="$(prefix r8 rdi)01c7";
	code="${code}${ADD_r8_rdi}";
	local ADD_rcx_r8="$(prefix rcx r8)01c8";
	code="${code}${ADD_rcx_r8}";

	# if addr is 0 allocate some address to it.
	# cmp rdi
	# jg .(alloc mem instr len)
	# alloc mem
	local REP=f3;
	local MOVSB=a4;
	code="${code}${REP}${MOVSB}";
	echo -en "${code}";
}

