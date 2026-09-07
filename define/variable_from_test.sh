define_variable_from_test()
{
	#   defines a new symbol based on a boolean condition
	local field_a="${code_line_elements[$(( 3 + deep-1 ))]}";
	local field_data_a=$(get_b64_symbol_value "${field_a}" "${SNIPPETS}")
	local field_a_addr=$(echo "$field_data_a" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR})
	local field_type_a=$(echo "${field_data_a}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	local field_a_v=$(echo "${field_data_a}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d)
	local field_b="${code_line_elements[$(( 4 + deep-1 ))]}";
	local field_data_b=$(get_b64_symbol_value "${field_b}" "${SNIPPETS}");
	local field_b_addr=$(echo "$field_data_b" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR})
	local field_type_b=$(echo "${field_data_b}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	local field_b_v=$(echo "${field_data_b}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d)
	if [ "${1:-}" == string ]; then {
		field_type_a=$SYMBOL_TYPE_DYNAMIC_STRING;
		field_type_b=$SYMBOL_TYPE_DYNAMIC_STRING;
	}
	fi;
	local instr_bytes=$(compare "${field_a_v:=0}" "${field_b_v:=0}" "$field_type_a" "$field_type_b" | xd2b64)
	local instr_len=$(echo "$instr_bytes" | b64cnt);
	local data_bytes="";
	local data_len=0;
	struct_parsed_snippet \
		"SYMBOL_TABLE" \
		"${SYMBOL_TYPE_PROCEDURE}" \
		"${symbol_name}" \
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
