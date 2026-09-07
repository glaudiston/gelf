define_variable_from_exec()
{
	local cmd="$(echo -n "${code_line_elements[$(( 3 + deep-1 ))]}")"
	# TODO for now positional args are good enough, but a better way is to have named args and env as an array or map each;
	local args=( );
	local static_map=( );
	for (( i=0; i<$(( ${#code_line_elements[@]} - deep -2)); i++ ));
	do {
		local arg_id="${code_line_elements[$((i + deep + 2))]}";
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
		args[${i}]="$arg_addr";
		static_map[${i}]=$arg_is_static;
	};
	done;
	local data_bytes="";
	local env=(); # memory address to the env
	local pipe_struct_size=8; # 2 int array; int 4 bytes each
	local pipe_buffer_size=$((16#100));# 256;
	local ptr_to_buffer_size=8; # reserve the first 8 bytes to a pointer to the buffer data (currently 8 bytes ahead), so the concat code will not break trying to resolve a pointer
	local pipe_buffer_addr=$(( dyn_data_offset + ptr_to_buffer_size ));
	local pipe_addr=$(( pipe_buffer_addr + pipe_buffer_size ))
	local args_addr="$(( pipe_addr + pipe_struct_size ))"; # the array address
	local args_size=$(( 8 * ${#args[@]} + 8 )) # 8 to cmd, 8 for each argument and 8 to null to close the array
	local env_addr=$(( args_addr + args_size ));
	local env_size=8;
	env_size=0;
	env_addr=0; # no support for env, set NULL
	local argsparam="${args[@]}";
	local staticmapparam="${static_map[@]}";
	local data_len=$(( ptr_to_buffer_size + pipe_buffer_size + pipe_struct_size + args_size + env_size ));
	local instr_bytes="$(system_call_exec "${args_addr}" "${argsparam}" "${staticmapparam}" "${env_addr}" "${pipe_addr}" "${pipe_buffer_addr}" "${pipe_buffer_size}")";
	local instr_len="$(echo "${instr_bytes}" | b64cnt)";
	struct_parsed_snippet \
		"SYMBOL_TABLE" \
		"${SYMBOL_TYPE_PROCEDURE}" \
		"${symbol_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${dyn_data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"${CODE_LINE_B64}" \
		"1";
	return;
}
