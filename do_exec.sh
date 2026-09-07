do_exec(){
	# TODO for now positional args are good enough, but the correct is to have args and env as an array each;
	local args=( );
	local static_map=( );
	for (( i=0; i<$(( ${#code_line_elements[@]} - deep )); i++ ));
	do {
		local arg_id="${code_line_elements[$(( i + deep ))]}";
		local arg_snippet="$( echo "$SNIPPETS" | grep "SYMBOL_TABLE,[^,]*,${arg_id}," )";
		local arg_addr="$(echo "$arg_snippet" | cut -d, -f${SNIPPET_COLUMN_DATA_OFFSET} )";
		local arg_is_static=0;
		if is_static_data_snippet "${arg_snippet}"; then
			# if arg is static, the call is different because we pass the address to the string itself
			# instead of the address of the pointer to the string we have when it is dynamic
			# I've choose doing this way because we do less instructions as we don't need to allocate additional
			# bytes to create a pointer to the static string, we can just set the address to the register.
			arg_is_static=1;
		fi;
		args[$i]="$arg_addr";
		static_map[$i]=$arg_is_static;
	};
	done;
	local data_bytes="";
	local env=(); # memory address to the env
	local args_addr="$(( dyn_data_offset ))"; # the array address
	local args_size=$(( 8 * ${#args[@]} + 8 )) # 8 to cmd, 8 for each argument and 8 to null to close the array
	local env_addr=$(( args_addr + args_size ));
	local env_size=8;
	env_size=0;
	env_addr=0; # no support for env, set NULL
	local data_len=$(( args_size + env_size )); # 8 to each array (args and env)
	local argsparam="${args[@]}";
	local staticmapparam="${static_map[@]}";
	local instr_bytes="$(system_call_exec "${args_addr}" "${argsparam}" "${staticmapparam}" "${env_addr}")";
	local instr_len="$(echo "${instr_bytes}" | b64cnt)";
	struct_parsed_snippet \
		"INSTRUCTION" \
		"${SYMBOL_TYPE_SYSCALL}" \
		"sys_execve" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${static_data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"${CODE_LINE_B64}" \
		"1";
	return;
}

