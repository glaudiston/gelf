# ilog10 returns the integer log base 10 of the value in r1 register.
# 	Step 1: Get the guess value from ilog_guess_map using the bit index(aka ilog2/bsr);
# 	Step 2: Subtract 1 from guess when the value is less than the power value recovered using the guess.
# returns:	integer truncated on rdi
# registers need: 2
# r1: value
# 	input: value to process;
# 	behavior: used to count bits with bsr instruction
# 	output: no change;
# r2: bit count
# 	input: unused;
# 	behavior: is a work register where the bsr will set the bit count
# 	output: will return the count bits of the value
# r3: ilog_guess_map address / integer log base 10
# 	input: address value pointer to to max_bit_val_ilog10
# 	behavior: will be incremented by the number of bits to point at the log10 integer value;
# 		echo "[$(for (( i=0; i<63; i++)); do [ $i -gt 0 ] && echo -n ,; v=$(( 2 ** i )); l=$(echo "scale=1;l($v)/l(10)" | bc -l); l=${l/.*/}; echo -n ${l:=0}; done )]";
#		[0,0,0,0,1,1,1,2,2,2,3,3,3,3,4,4,4,5,5,5,6,6,6,6,7,7,7,8,8,8,9,9,9,9,10,10,10,11,11,11,12,12,12,12,13,13,13,14,14,14,15,15,15,15,16,16,16,17,17,17,18,18,18]
# 	output: log10 integer value at base 10
ilog10_guess_map_size=31;
ilog10()
{
	local r1="$1"; # source value register or integer value
	local r2="$2"; # target register to put the bit count
	local guess_map_addr="$3"; # register pointing to address of array_max_bit_val_ilog10 or address value
	local ret_addr="$4";
	local retcode="";
	if [ "$r1" == "" ]; then
		# when called directly act like a function,
		# so the number will be rsp + n, move it to rax where n can be:
		# 	0 = rsp = (return addr)
		# 	8 = 2 ( argc )
		# 	16 = ilog10 type (constant 6 == TYPE_FUNCTION_PTR)
		# 	24 = ilog10 addr
		# 	32 = first arg type
		# 	40 = first arg
		# so we want n=24
		mov rax rsp;
		add rax 40; # arg type (retaddr + (previous rbp) + argc + fn_ptr + arg_type : 8 bytes each)
		mov rdx "(rax)";
		add rax 8; # next byte is the argument value
		mov rax "(rax)";
		cmp rdx $SYMBOL_TYPE_HARD_CODED; # is argument hard coded ?
		local resolve_rax=$(mov rax "(rax)";); # only need to resolve more for non hardcoded addresses ones
		jz $(xcnt<<<$resolve_rax); # hard coded values does not need to resolve pointers to other memory address;
		printf "$resolve_rax";
		# movsb rax "(rax)";
		# should be the same as: movsbl 0x18(%rsp), %eax
		# BUT it is not, because movsb copy string.
		#printf "${MOVSBL_V4rsp_EAX}$(printEndianValue 24 $SIZE_8BITS_1BYTE)";
		retcode="$(ret)";
	fi;
	r1="${r1:=rax}";
	r2="${r2:=rdx}";
	bsr "$r2" "$r1"; # count r1 bits into r2 (normally from rax to rdx)
	# movzx   eax, BYTE PTR array_max_bit_val_ilog10[1+rax] # movzx (zero extend, set the byte and fill with zeroes the remaining bits)
	#${MOV_rsi_rcx}$(add 63 rcx | b64_2esc)
	# printf "${MOVSBL_V4rsi_ECX}";
	# printf "$(add $r2 $r3 | b64_2esc)";
	# 483B04D5 	cmp 0x0(,%rdx,8),%rax
	# 1 0000 0FBE1415 	movsbl 0x010018(,%rdx,),%edx
	#movsbl guess_map_addr(rdx), %edx
	printf "${MOVSBL_V4_rdx_EDX}$(px $guess_map_addr $SIZE_32BITS_4BYTES)";
	local power_map_addr=$((guess_map_addr + ilog10_guess_map_size));
	printf "${CMP_V4_rdx_8_rax}$(px $power_map_addr $SIZE_32BITS_4BYTES)";
	printf "${SBB_0_EDX}";
	if [ "$ret_addr" != "" ]; then
		# mov "(rsi)" rsi;
		#1 0000 480FB6FA 	movzx %dl,%rdi
		printf "${MOVZX_DL_rdi}";
		# mov rsi $ret_addr;
	fi;
	printf "${retcode}";
}

