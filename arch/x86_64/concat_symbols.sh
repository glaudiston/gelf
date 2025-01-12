# concat_symbol_instr set addr to dyn_addr or static
# in the first item(idx=1) r8 will be cleared and the appended size will be add in r8 for each call
concat_symbol_instr(){
	#TODO can be improved to use MOVSQ
	local addr="$1";
	local dyn_addr="$2";
	local size="$3";
	local idx="$4";
	#local mmap_size_code="$(mov $(( 1 << 12 )) rsi)";
	#local mmap_code="$(sys_mmap "${mmap_size_code}")"
	# unable to move addr to addr;
	# so let's mov addr to a reg,
	# then reg to addr;
	if [ "$idx" == 1 ]; then # on first item zero r8 to accum the size
		xor r8 r8;
		push r8;	# create zeroed target space at stack;
		mov $dyn_addr rsp;
	fi;
	if [ "$size" -eq -1 ]; then
		mov rsi "(${addr})"; # source is addr
		detect_string_length rsi rdx rax; # the return is set at rdx
		mov rcx rdx;
		# but we need it on rcx because REP decrements it
	elif [ "$size" -eq -2 ]; then # procedure pointer
		mov rsi "($addr)"; # source addr
		# the return is set at rdx
		mov rcx rdx;
		# but we need it on rcx because REP decrements it
		return;
	else
		mov rsi "$addr"; # source addr
		mov rcx $size;
	fi;
	mov rdi rsp; # target addr
	add rdi r8;
	add r8 rcx;
	# if addr is 0 allocate some address to it.
	# cmp rdi
	# jg .(alloc mem instr len)
	# alloc mem
	local REP=f3;
	local MOVSB=a4;
	printf "${REP}${MOVSB}";
}

