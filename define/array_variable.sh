# returns internal function list used
# returns array definition bytecode
define_array_variable(){
	local dyn_data_offset="$1";
	local instr_bytes="";
	local first_item_idx=$(( deep + 2 ));
	local first_item="${code_line_elements[$first_item_idx]}";
	local dependencies="";
	if is_function "$first_item"; then
		dependencies="${first_item}";
	fi;
	for (( i=$(( ${#code_line_elements[@]} -1 )); i>$((deep + 1)); i-- ));
	do
		local symbol_name=$(echo -n "${code_line_elements[$i]}");
		local symbol_data=$(get_b64_symbol_value "${symbol_name}" "${SNIPPETS}" )
		local symbol_addr=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR});
		local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
		local symbol_value=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} |base64 -d);
		if [ "${symbol_type}" == $SYMBOL_TYPE_PROCEDURE ]; then
			local proc_instr_len="$( echo "$SNIPPETS" | grep "PROCEDURE_TABLE,[^,]*,${symbol_name}," | tail -1 |
				cut -d, -f${SNIPPET_COLUMN_INSTR_LEN} )";
			local jump_size=2; # instruction length of the jump over before the code
			if [ "$proc_instr_len" -gt 127 ]; then
				jump_size=5;
			fi;
			symbol_addr=$(( symbol_addr + jump_size ));
		fi;
		instr_bytes="${instr_bytes}$(array_add "${dyn_data_offset}" "$((i-deep-1))" "${symbol_addr}" "${symbol_type}" "${symbol_value}" | xd2b64)";
	done;
	local array_size=$(( ${#code_line_elements[@]} - (deep + 1) -1));
	instr_bytes="${instr_bytes}$(array_end "${dyn_data_offset}" "$array_size" | xd2b64)";
	local symbol_name=$(echo -n "${code_line_elements[$(( 1 + deep-1 ))]}" | cut -d: -f1);
	local instr_len=$(echo -n "$instr_bytes" | b64cnt);
	local data_bytes="";
	local data_len=$(( array_size * 8 ));
	local usage_count=0;
	local return_value="";
	local source_line_count=1;
	struct_parsed_snippet \
		"SYMBOL_TABLE" \
		"${SYMBOL_TYPE_ARRAY}" \
		"${symbol_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${dyn_data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"${CODE_LINE_B64}" \
		"${source_line_count}" \
		"${usage_count}" \
		"${return_value}" \
		"${dependencies}";
	return;
}
