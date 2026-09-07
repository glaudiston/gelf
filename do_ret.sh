do_ret(){
	local symbol_id="$third_elem";
	local instr_bytes="";
	local code_line="$CODE_LINE_B64";
	if [ "${symbol_id}" != "" ]; then
		local symbol_data=$(get_b64_symbol_value "${symbol_id}" "${SNIPPETS}");
		local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
		local symbol_value=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d | tr -d '\00' );
		instr_bytes="$(ret "${symbol_value}" "${symbol_type}" | xd2b64)";
	else
		instr_bytes="$(ret | xd2b64)";
	fi;
	local instr_len=$(echo "${instr_bytes}" | b64cnt);
	struct_parsed_snippet \
		"INSTRUCTION" \
		"${SYMBOL_TYPE_SYSCALL}" \
		"ret" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${static_data_offset}" \
		"" \
		"0" \
		"${code_line}" \
		"1";
}

