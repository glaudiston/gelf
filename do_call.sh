do_call(){
	local third_elem="${code_line_elements[$(( 2 + deep-1 ))]:-}";
	# internal function calls
	if [[ "$second_elem" == ret ]]; then
	{
		do_ret;
		return;
	}
	fi;
	if [[ "$second_elem" == goto ]]; then
	{
		do_goto;
		return;
	}
	fi;
	if [[ "$second_elem" == .ilog10 ]]; then
		do_ilog10;
		return;
	fi;
	# system calls related code
	if [[ "$second_elem" == sys_write ]]; then
	{
		snippet_write;
		return;
	}
	fi;
	if [[ "$second_elem" == sys_exit ]]; then
	{
		do_exit;
		return;
	}
	fi;
	local target="$second_elem";
	local target_data=$(get_b64_symbol_value "${target}" "${SNIPPETS}");
	local target_type=$(echo "${target_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	if [ "$target_type" == "$SYMBOL_TYPE_ARRAY" ] && is_function_call $target "${SNIPPETS}"; then
	{
		local target_data="$( echo "$SNIPPETS" | grep "SYMBOL_TABLE,${SYMBOL_TYPE_ARRAY},${target}," )";
		local symbol_source_code=$(echo $target_data | cut -d, -f${SNIPPET_COLUMN_SOURCE_CODE});
		local target_fn=$(echo $symbol_source_code | base64 -d| cut -d: -f2- | cut -f4);
		local target_fn_data="$(echo "$SNIPPETS" | grep "PROCEDURE_TABLE,[^,]*,${target_fn},")";
		local target_addr=$(echo $target_fn_data | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET});
		local jmp_size=$(get_jmp_size "${SNIPPETS}" "${target_fn}" );
		target_addr=$(( target_addr + jmp_size ));
		instr_bytes="$(call_procedure "${target_addr}" "${instr_offset}" "${SYMBOL_TYPE_ARRAY}" | xd2b64)";
		local instr_len="$(echo "${instr_bytes}" | base64 -d |  wc -c)";
		struct_parsed_snippet \
			"SNIPPET_CALL" \
			"${SYMBOL_TYPE_PROCEDURE}" \
			"call" \
			"${instr_offset}" \
			"${instr_bytes}" \
			"${instr_len}" \
			"${static_data_offset}" \
			"" \
			"0" \
			"${CODE_LINE_B64}" \
			"1";
		return;
	}
	elif [ "$target_type" == "$SYMBOL_TYPE_PROCEDURE" ]; then
		target_offset="$( echo "$SNIPPETS" | grep "PROCEDURE_TABLE,[^,]*,${target}," | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET} )";
	elif [[ "$third_elem" =~ [?](=|<=|>|>=)$ ]]; then
		conditional_call;
		return;
	else
		do_exec;
		return;
	fi;
	local jmp_size=$(get_jmp_size "${SNIPPETS}" "${target}" );
	local call_bytes="$(call_procedure "$((target_offset + jmp_size))" "${instr_offset}" | xd2b64)";
	local call_len="$(echo "${call_bytes}" | b64cnt)";
	struct_parsed_snippet \
		"SNIPPET_CALL" \
		"${SYMBOL_TYPE_PROCEDURE}" \
		"call" \
		"${instr_offset}" \
		"${call_bytes}" \
		"${call_len}" \
		"${static_data_offset}" \
		"" \
		"0" \
		"${CODE_LINE_B64}" \
		"1";
	return;
}

