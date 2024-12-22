function system_call_exec()
{
	#TODO we need to map some memory, or use a mapped memory space to store the arrays bytes;
	local PTR_ARGS="$1";
	local args=();
	eval "args=( $2 )";
	local static_map=( );
	eval "static_map=( $3 )";
	local PTR_ENV="$4";
	local pipe_addr="$5";
	local pipe_buffer_addr="$6";
	local pipe_buffer_size="$7";
	local code="";
	local stdout=1;
	local dup2_child="";
	local read_pipe="";
	if [ "$pipe_addr" != "" ]; then
		pipe_in="$pipe_addr";
		pipe_out="$((pipe_addr + 4))";
		dup2_child="$(system_call_dup2 "$pipe_out" "$stdout")";
		# read_pipe will run on the parent pid.
		read_pipe="${read_pipe}$({
			mov $SYS_READ rax;
			mov "${pipe_in}" rdi; mov "(edi)" edi; # fd
			mov "${pipe_buffer_addr}" rsi; # buff
			mov rsi "$((pipe_buffer_addr - 8))"; # set the pointer to the buffer allowing concat to work
			mov "${pipe_buffer_size}" rdx; # count
			syscall;
		})";
	fi;

	# set the args array in memory
	local argc=${#args[@]};
	debug "exec args=$argc = [${args[@]}] == [$2]";
	debug "exec staticmap=${#static_map[@]} = [${static_map[@]}] == [$3]";
	local exec_code="$({
		for (( i=0; i<${argc}; i++ ));
		do {
			mov "${args[$i]}" rax;
			if [ "${static_map[$i]}" == 0 ]; then # it's a dynamic command, resolve it
				mov "(rax)" rax;
			fi;
			mov rax "$(( PTR_ARGS + i*8 ))";
		}; done
		xor rax rax;
		mov rax "$(( PTR_ARGS + ${#args[@]} * 8 ))";
		mov ${args[0]} rdi;
		if [ "${static_map[0]}" == 0 ]; then # it's a dynamic command, resolve it
			mov "(rdi)" rdi;
		fi;
		mov ${PTR_ARGS:=0} rsi;
		mov ${PTR_ENV:=0} rdx; # const char *const envp[]
		mov ${SYS_EXECVE} rax; # sys_execve (3b)
		syscall;
	})";
	# end exec code:
	local pipe_code="";
	if [ "$pipe_addr" != "" ]; then
		local pipe_code=$(system_call_pipe "${pipe_addr}");
	fi;
	# start fork code
	local fork_code="$(system_call_fork)";
	# TODO: CMP ? then (0x3d) rAx, lz
	local TWOBYTE_INSTRUCTION_PREFIX="0f"; # The first byte "0F" is the opcode for the two-byte instruction prefix that indicates the following instruction is a conditional jump.
	fork_code="${fork_code}$(cmp rax 0)"; # 64bit cmp rax, 00
	# rax will be zero on child, on parent will be the pid of the forked child
	# so if non zero (on parent) we will jump over the sys_execve code to not run it twice,
	# and because it will exit after run
	CODE_TO_JUMP="$(px "$(echo -en "${dup2_child}${exec_code}"| xcnt)" ${SIZE_32BITS_4BYTES})"; # 45 is the number of byte instructions of the syscall sys_execve (including the MOV (%rdi), %rdi.
	fork_code="${fork_code}${JNE}${CODE_TO_JUMP}"; # The second byte "85" is the opcode for the JNE instruction. The following four bytes "06 00 00 00" represent the signed 32-bit offset from the current instruction to the target label.
	# end fork code
	local wait_code="$(system_call_wait4)";
	debug wait_code="$wait_code";

	code="${pipe_code}${fork_code}${dup2_child}${exec_code}${wait_code}${read_pipe}";
	echo -en "${code}" | xd2b64;
}
