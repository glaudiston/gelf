# i2s integer to string
# registers:
# rsp: stack changed and restored
# rax: number to convert
# rcx: digit value
# rdx: decrement by power(10, digit) until less than zero
# rdi: used by ilog10; strlen position
# rsi: used by ilog10
i2s(){
	local int_symbol_value="$1";
	local int_symbol_type="$2";
	local str_addr="$3";# return address(stored pointer)
	debug "i2s to store at $(printf 0x%x $str_addr)";
	local ilog10_addr="$4";
	local power10_addr="$5";
	local CURRENT_RIP="$6";
	local init_code="$({
		if [ "$int_symbol_type" == $SYMBOL_TYPE_DYNAMIC ]; then
			mov "${int_symbol_value}" rax;
		elif [ "$int_symbol_type" == $SYMBOL_TYPE_HARD_CODED ]; then
			mov "${int_symbol_value}" rax;
		else
			:
			# expect to have the value on rax already;
		fi;
		mov rsp rax;
		add 24 rax;
		mov "(rax)" rax;
		mov "(rax)" rax;
		cmp rax 0;
		local return_if_zero="$({
			add 48 rax; # 0x30
			mov al "$str_addr";
			mov "$str_addr" rdi;
			ret;
		})";
		local displacement=$(echo -n "$return_if_zero" | xcnt);
		jg $displacement;
		printf "${return_if_zero}";
	})";
	printf "${init_code}";
	# now rax has the int value
	local ilog10_skip_stack=10; # expected to skip first part of ilog10 code, so it will not try to recover the value from stack. This will break at any change on ilog10 begin code
	local init_codesize=$(echo -n "${init_code}" | xcnt);
	local displacement=$(( CURRENT_RIP + init_codesize -ilog10_skip_stack ));
	call_procedure ${ilog10_addr} ${displacement} | b64xd;
	# at this point rdx == 3 (log 10 (n))
	# rax is the value (0x3e8==1000)
	# rdx is the remaining digit count(base 10) from ilog10
	# rdi is the digit count (base 10) (used to select the memory target to put the digit om str_addr)
	# rcx is the digit asc value
	xor rdi rdi;
	#for_init_code=$({});
	#for_cond_code=$({ asc_digit_count < ilog10_v });
	#for_code="$for_init_code; $for_cond_code; $for_impl_code; $for_step_code";

	# The loop repeats while rax > 0
	# the loop substract from rax the value of the power10 ** rdx
	local codepart2="$({
		xor rcx rcx; # clean up digit asc value each interaction
		local dec_power_code="$({
			# This will run at bottom
			printf "${SUB_ADDR4_rax_rax}$(px $power10_addr $SIZE_32BITS_4BYTES)";
			inc rcx;
		})";
		local loopcode="$({
			# cmp %rax, $power10_addr(,%rdx,8);
			printf "${CMP_rax_ADDR4_rdx_8}$(px "$power10_addr" $SIZE_32BITS_4BYTES)";
			local append_asc_digit="$({
				add $(printf %d \'0) rcx; # add the zero asc value (0x30)
				printf "${MOV_CL_ADDR4_rdi}$(px $str_addr $SIZE_32BITS_4BYTES)"; # append the rcx low byte to str addr
				inc rdi;
				#rdx=$((rdx-1));
				dec rdx;
				# $rdx -lt 0 ] && break;
				cmp rdx 0;
			})";
			local parse_next_digit="$({
				local dec_power_codesize=$(echo -en "${dec_power_code}"| xcnt);
				local xor_size=3;
				local cmp_size=9; # size of cmp rax power_10_addr+rdx*8
				local jng_size=2; # size of jmp before this code;
				printf "${JGE_V1}$(px $(( 0 - $(xcnt <<<"$append_asc_digit") - xor_size - cmp_size - jng_size -1 )) $SIZE_8BITS_1BYTE)"; # TODO: why -1 ?
				local jmpv1_size=2; # it is not in dec_power_code yet because it depends on this block size
				printf "${JMP_V1}$(px $(( dec_power_codesize + jmpv1_size)) $SIZE_8BITS_1BYTE)";
				# continue; # jump back to "xor %rcx, %rcx"
			})";
			jmpsize=$(xcnt <<<"${append_asc_digit}${parse_next_digit}");
			printf "${JNG_V1}$(px ${jmpsize} $SIZE_8BITS_1BYTE)"; # if rax <= power10[rdx] then (quit loop) (goto after_loop)
			printf "${append_asc_digit}";
			printf "${parse_next_digit}"
		})";
		# jg loopcode
		printf "${loopcode}";
		# fix the stack
		# sub power10(rax), rax
		printf "${dec_power_code}";
	})";
	printf "${codepart2}";
	# jmp back
	printf "${JMP_V1}$(px $(( - $(xcnt <<<"${codepart2}") +1 )) $SIZE_8BITS_1BYTE )"; # TODO: why +1 ?
	# code "after_loop"
	# TODO code="${code}${MOV_v0_ADDR4_rdi}$(printEndianValue $str_addr $SIZE_32BITS_4BYTES)"; # append the 00 to close the string
	mov $str_addr rdi;
	ret;
}
