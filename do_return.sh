do_return(){
	local SNIPPETS="$2";
	local symbol_id="$1";
	local symbol_data=$(get_b64_symbol_value "${symbol_id}" "${SNIPPETS}");
	local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	local symbol_value=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d | tr -d '\00' );
	debug "do_return symbol_id=$symbol_id; symbol_type=$symbol_type"
	local snippet_type=$SYMBOL_TYPE_PROCEDURE;
	local instr_offset="$(get_instr_offset "$( echo "$SNIPPETS" | tail -1)")";
	local instr_bytes=$(ret "${symbol_value}" "${symbol_type}" | xd2b64);
	local instr_size="$(echo $instr_bytes | b64cnt)";
	struct_parsed_snippet \
		"PROCEDURE_TABLE" \
		"${snippet_type}" \
		"${snippet_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_size}" \
		"${static_data_offset}" \
		"${data_bytes}" \
		"${data_bytes_sum}" \
		"${outer_code_b64}" \
		"${source_lines_count}" \
		"${usage_count}" \
		"${return}" \
		"${dependencies}";
}
