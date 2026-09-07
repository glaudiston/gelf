define_concat_variable(){
	debug "define_concat_variable"
	local dyn_args=0;
	local static_value="";
	local instr_bytes="";
	local data_addr=""; # target concatenated data_addr
	for (( i=deep+1; i < ${#code_line_elements[@]}; i++ ));
	do
		local symbol_name=$(echo -n "${code_line_elements[$i]}");
		debug "concat_variable: symbol_name: $symbol_name";
		local symbol_data=$(get_b64_symbol_value "${symbol_name}" "${SNIPPETS}" )
		local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
		local symbol_value=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT});
		local symbol_addr="$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR})";
		local symbol_len="$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_SIZE})";
		local sym_dyn_data_size=$(get_sym_dyn_data_size "${symbol_name}" "${SNIPPETS}")
		if [ "${symbol_type}" == "${SYMBOL_TYPE_STATIC}" ]; then
			static_value="$( echo "${static_value}${symbol_value}" | base64 -d | base64 -w0 )";
			instr_bytes="${instr_bytes}$(concat_symbol_instr "${symbol_addr}" "${dyn_data_offset}" "${symbol_len}" "$i" | xd2b64)";
		else
			dyn_args="$(( dyn_args + 1 ))";
			instr_bytes="${instr_bytes}$(concat_symbol_instr "$(( symbol_addr ))" "${dyn_data_offset}" "-1" "$i" | xd2b64)";
		fi;
	done;
	# if all arguments are static, we can merge them at build time
	local symbol_name=$(echo -n "${code_line_elements[$(( 1 + deep-1 ))]}" | cut -d: -f1);
	if [ "${dyn_args}" -eq 0 ]; then
	{
		local instr_bytes="";
		local instr_len=0;
		local data_bytes="${static_value}";
		local data_len=$(echo -n "$data_bytes" | b64cnt);
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
		return
	}
	fi;
	# if at least one are dynamic we need to set instructions
	local instr_len=$(echo -n "$instr_bytes" | b64cnt);
	local data_bytes="";
	local data_len=8;
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
