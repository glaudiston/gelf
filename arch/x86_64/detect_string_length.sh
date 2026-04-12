# how dinamically discover the size?
# one way is to increment the pointer, then subtract the previous pointer, this is fast but this is only garanteed to work in arrays of data, where the address are in same memory block. see detect_argsize
# another way is to count the bytes until find \x00. but this will block the possibility of write out the \x00 byte. this is what code does. despite slower and the side effect of not allowing \x00, it is safer.
function detect_string_length()
{
	local r_in="$1";
	r_in=${r_in:=rsi};
	local r_out="$2";
	r_out=${r_out:=rcx};
	local r_tmp_64="$3";
	r_tmp_64=${r_tmp_64:=rax};
	r_tmp=$(get_8bit_reg $r_tmp_64);
	# xor rcx rcx; # ensure rcx = 0
	#mov "(rsi)" rsi;
	# we expect the rsi having the address of the string
	mov "${r_out}" "${r_in}"; # let's use rcx as rsi incrementing it each loop interaction
	local loop_code=$({
		# save rip
		# leaq (%rip), %rbx #
		# LEAQ_RIP_rbx;
		# get the data byte at addr+rcx into rax
		# todo ? USE MOVSB ?
		mov $r_tmp_64 "(${r_out})"; # resolve current rcx pointer to rax (al)
		inc ${r_out};
		# test data byte
		test ${r_tmp}; # test for null byte;
	})
	printf $loop_code;
	local loop_size=$(xcnt<<<$loop_code);
	jnz_size=$(xcnt< <(jnz $(( -loop_size + 2 )) ));
	jnz $(( -loop_size - jnz_size )); # loop until find a null byte.
	dec "${r_out}";
	# sub %rsi, %rcx
	sub ${r_out} ${r_in};
	#JMP_rbx="ff23";
}
