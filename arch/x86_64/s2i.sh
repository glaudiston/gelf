#!/bin/bash
if ! declare -F s2i_loaded; then s2i_loaded(){ :; };
. $(dirname $(realpath $BASH_SOURCE))/mov.sh
. $(dirname $(realpath $BASH_SOURCE))/mul.sh
. $(dirname $(realpath $BASH_SOURCE))/add.sh
. $(dirname $(realpath $BASH_SOURCE))/cmp.sh
# s2i string to integer
# given a string address convert it to integer
s2i()
{
	local reg_str_addr="rax";
	local reg_str_8="al";
	local reg_tmp_s="rsi";
	local reg_tmp_s8="sil";
	local reg_int_addr="rdi";
	local reg_tmp_i="rcx";
	local reg_tmp_i8="cl";
	local c="";
	local init="$({
		# tmp code start
		#
		mov $reg_str_addr rsp; # rsp is ptr to rip return address
		add $reg_str_addr 40; # arg type == (rip_ret_addr+(previous rbp)+argc+s2i_ptr_type+s2i_ptr) * 8 bytes
		mov $reg_tmp_s "($reg_str_addr)"; # resolve the value type to another register;
		add $reg_str_addr 8; # add 8 to get the argment next to the type;
		mov $reg_str_addr "(${reg_str_addr})";	# resolve the stack mem ptr to the heap mem ptr
		cmp $reg_tmp_s $SYMBOL_TYPE_HARD_CODED; # is argument hard coded ?
		local resolve_arg_value=$({
			# only required when not hard coded values;
			mov $reg_str_addr "(${reg_str_addr})";	# resolve the heap mem ptr to the mmap argument ptr;
			mov $reg_str_addr "(${reg_str_addr})";	# resolve the mmap arg ptr to load the first 8 bytes at the tmp register
		})
		jz $(xcnt<<<$resolve_arg_value); # hard coded values can not resolve pointers;
		printf "$resolve_arg_value"; # only for dynamic values like process arguments;
		#
		# tmp code end
		xor $reg_tmp_i $reg_tmp_i;	# clean up target int reg
		xor $reg_tmp_s $reg_tmp_s;	# clean up target int reg
	})";
	printf "${init}";
	local loop="$({
		mov $reg_tmp_s8 ${reg_str_8};	# load the first 8 bytes at the tmp register
		cmp $reg_str_8 0;
	})";
	local r="$({
		sub $reg_tmp_s8 48;		# convert to int (- x30) (asc zero)
		imul $reg_tmp_i 10;		# multiply target by 10;
		add $reg_tmp_i $reg_tmp_s;	# add to target int
		shrq $reg_str_addr 8;		# get next byte
	})";
	r="$r$({
		local ss=$(( $(xcnt<<<$loop$r) +4 )); # TODO: why +4 ?
		jmp $(( - ss));	# jump back to loop start
	})";
	local rs=$(echo -n "$r"| xcnt);
	loop="${loop}$(jz $rs)"; 		# if found null the string is over;
	loop="${loop}${r}";
	#
	# this should work only for 8 bytes string, more than 8 needs another logic;
	#
	printf "${loop}";
	mov rdi $reg_tmp_i;	# record the value at target address
	ret;
}
fi;
