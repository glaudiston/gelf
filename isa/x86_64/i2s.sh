#!/usr/bin/env bash
set -euo pipefail
. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash <<-EOF
	./mov.sh
	./mul.sh
	./add.sh
	./cmp.sh
	../../internal_functions.sh
EOF

internal_function_register ".i2s" i2s

# i2s integer to string
# registers:
# rsp: stack changed and restored
# rax: number to convert
# rcx: digit value
# rdx: decrement by power(10, digit) until less than zero
# rdi: used by ilog10; strlen position
# rsi: used by ilog10
i2s(){
	local int_symbol_value="$1"; # rsp is the expected value for call procedure
	local int_symbol_type="$2";
	local str_addr="$3";# return address(stored pointer)
	debug "i2s to store at $(printf 0x%x "$str_addr")";
	local ilog10_addr="$4";
	local power10_addr="$5";
	local CURRENT_RIP="$6";
	local init_code;
	init_code="$({
		if [ "$int_symbol_type" == "$SYMBOL_TYPE_DYNAMIC" ]; then
			mov rax "${int_symbol_value}";
		elif [ "$int_symbol_type" == "$SYMBOL_TYPE_HARD_CODED" ]; then
			mov rax "${int_symbol_value}";
		else
			:
			# expect to have the value on rax already;
		fi;
		# prepare to read the arguments from the stack
		# set rax to the stack position
		mov rax rsp;
		# add 40 bytes to get to the first arg type
		add rax 40; # arg type: (retval+(previous rbp)+argc+i2s_ptr_tye+i2s_ptr) 8 bytes each;
		mov rdi rax;
		cmp rdi "$SYMBOL_TYPE_HARD_CODED"; # value = 0
		local resolve_value;
		resolve_value=$({
			mov rax [rax]; # resolve the mem, resulting in the int value be in stack
		})
		# move to the first arg value ptr
		add rax 8; # add to rsp+40 (rsp+32+8) (retvaladdr+argc+i2s_ptr_type+i2s_ptr+arg_type) (8 bytes each);
		jz "$(xcnt<<<"$resolve_value")"
		printf %s "$resolve_value";
		mov rax [rax]; # resolve stack addr in reg to mem where the int value is
		cmp rax 0;
		local return_if_zero;
		return_if_zero="$({
			add rax 48; # 0x30; asc digit 0
			mov "[$str_addr]" al;
			mov rdi "$str_addr";
			ret;
		})";
		local displacement;
		displacement=$(echo -n "$return_if_zero" | xcnt);
		jg "$displacement";
		printf %s "${return_if_zero}";
	})";
	printf %s "${init_code}";
	# now rax has the int value
	local ilog10_skip_stack=26; # expected to skip first part of ilog10 code, so it will not try to recover the value from stack. This will break at any change on ilog10 begin code
	local init_codesize;
	init_codesize=$(xcnt<<<"${init_code}");
	local displacement=$(( CURRENT_RIP + init_codesize -ilog10_skip_stack ));
	call_procedure "${ilog10_addr}" "${displacement}";
	# at this point rdx == 3 (log 10 (n))
	# rax is the integer value (0x3e8==1000)
	# rdx is the remaining digit count(base 10) from ilog10
	# rdi is the digit count (base 10) (used to select the memory target to put the digit om str_addr)
	# rcx is the digit asc value
	xor rdi rdi;
	#for_init_code=$({});
	#for_cond_code=$({ asc_digit_count < ilog10_v });
	#for_code="$for_init_code; $for_cond_code; $for_impl_code; $for_step_code";

	# The loop repeats while rax > 0
	# the loop substract from rax the value of the power10 ** rdx
	local jmpv1_size=2; # it is not in dec_power_code yet because it depends on this block size
	xor rcx rcx; # clean up digit asc value
	local codepart2;
	codepart2="$({
		debug "codepart2 start"
		local dec_power_code;
		dec_power_code="$({
			# This will run at bottom
			printf "%s" "$(sub rax "$(px "$power10_addr" "$SIZE_32BITS_4BYTES")")";
			inc rcx;
		})";
		local loopcode;
		loopcode="$({
			debug "i2s loopcode start"
			local append_asc_digit;
			append_asc_digit="$({
				# convert the digit to asc by adding the ascii code for byte zero (0x30)
				add rcx "$(printf %d \'0)"; # add the zero asc value (0x30)
				# set the parsed digit on memory byte:
				printf "${MOV_CL_ADDR4_rdi}$(px "$str_addr" "$SIZE_32BITS_4BYTES")"; # append the rcx low byte to str addr
				inc rdi; # parsed digits count;
				dec rdx; # remaning digits;
				xor rcx rcx; # zeroed for new digit value
			})";
			local parse_next_digit;
			parse_next_digit="$({
				local cmp_size=8; # size of cmp rax power_10_addr+rdx*8
				local jng_size=2; # size of jmp before this code;
				local jge_size=2; # size of jge instr in this code block;
				local cmp_rdx_size=4;
				cmp rdx 0; # [ $rdx -lt 0 ] && break;
				jge $(( 0 - jge_size - cmp_rdx_size - $(xcnt <<<"$append_asc_digit") - jng_size - cmp_size ));
				local dec_power_codesize
				dec_power_codesize=$(xcnt<<<"${dec_power_code}");
				jmp $(( dec_power_codesize + jmpv1_size));
				# continue; # jump back to "xor %rcx, %rcx"
			})";
			# cmp %rax, $power10_addr(,%rdx,8);
			printf "${CMP_rax_ADDR4_rdx_8}$(px "$power10_addr" "$SIZE_32BITS_4BYTES")";
			jng "$(xcnt <<<"${append_asc_digit}${parse_next_digit}")"; # if rax <= power10[rdx] then (quit loop) (goto after_loop)"
			printf %s "${append_asc_digit}";
			printf %s "${parse_next_digit}";
			debug "i2s loopcode end"
		})";
		# jg loopcode
		printf %s "${loopcode}";
		# fix the stack
		# sub power10(rax), rax
		printf %s "${dec_power_code}";
		debug "codepart2 end"
	})";
	printf %s "${codepart2}";
	# jmp back
	jmp "$(( - $(xcnt <<<"${codepart2}") -jmpv1_size ))";
	# code "after_loop"
	mov rdi "$str_addr";
	ret;
	debug "i2s code end: $(backtrace)"
}
