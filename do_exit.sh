do_exit(){
	local symbol_id="$third_elem";
	local symbol_data=$(get_b64_symbol_value "${symbol_id}" "${SNIPPETS}");
	local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	local symbol_value=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d | tr -d '\00' );
	local instr_bytes="$(system_call_exit "${symbol_value}" "${symbol_type}" )";
	local instr_len=$(echo "${instr_bytes}" | b64cnt);
	struct_parsed_snippet \
		"INSTRUCTION" \
		"${SYMBOL_TYPE_SYSCALL}" \
		"sys_exit" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${static_data_offset}" \
		"" \
		"0" \
		"${CODE_LINE_B64}" \
		"1";
}

