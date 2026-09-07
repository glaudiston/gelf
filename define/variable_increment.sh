define_variable_increment()
{
	local third_arg_idx=$((3 + deep-1));
	local last_arg_idx="${#code_line_elements[@]}";
	local symbol_id="";
	local symbol_data="";
	local symbol_value="";
	local instr_bytes="";
	for ((i=third_arg_idx; i<last_arg_idx; i++)); do
		symbol_id="${code_line_elements[${i}]}";
		symbol_data=$(get_b64_symbol_value "${symbol_id}" "${SNIPPETS}")
		symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
		symbol_value=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d);
		instr_bytes="${instr_bytes}$(set_increment $dyn_data_offset $symbol_value $symbol_type | xd2b64)";
	done
	local instr_len="$(echo "${instr_bytes}" | b64cnt)";
	local data_bytes="";
	local data_len="8";
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
