snippet_write()
{
	local WRITE_OUTPUT_ELEM=2;
	local WRITE_DATA_ELEM=3;
	local input_symbol_name="${code_line_elements[$(( WRITE_DATA_ELEM + deep-1 ))]}";
	local out=${code_line_elements[$(( WRITE_OUTPUT_ELEM + deep-1 ))]};
	# expected: STDOUT, STDERR, FD...
	local data_output=$(get_b64_symbol_value "${out}" "${SNIPPETS}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d | tr -d '\0' );
	# I think we can remove the parse_data_bytes and force the symbol have the data always
	local symbol_data=$(get_b64_symbol_value "${input_symbol_name}" "${SNIPPETS}");
	local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	local symbol_value=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT});
	local symbol_addr="$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR})";
	local data_bytes=$(echo -n "${symbol_value}");
	local data_bytes_len="$(echo -n "${symbol_data}"| cut -d, -f${B64_SYMBOL_VALUE_RETURN_SIZE})";
	local data_addr_v=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR});
	if [ "${symbol_type}" != "${SYMBOL_TYPE_STATIC}" ]; then
	{
		if [ "${symbol_type}" == "${SYMBOL_TYPE_PROCEDURE}" ]; then
		{
			data_bytes_len=0; # no data to append. just registers used.
			data_bytes="";
			local procedure_addr=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR});
			data_addr_v="${procedure_addr}"; # point to the procedure address
		}
		fi;
	}
	fi;
	# TODO: detect if using dyn data addr and pass it
	local input_symbol_name="${code_line_elements[$(( WRITE_DATA_ELEM + deep-1 ))]}";
	local input_symbol_return="$( echo "$SNIPPETS" | grep "SYMBOL_TABLE,[^,]*,${input_symbol_name}," | cut -d, -f${SNIPPET_COLUMN_RETURN} )";
	if [ "${input_symbol_return}" != "" ]; then
		data_addr_v="${input_symbol_return}";
	elif [ "${data_addr_v}" != "" ]; then
		data_addr_v="$(( data_addr_v ))";
	else
		data_addr_v="$( echo ${symbol_value} | base64 -d)"
	fi;
	local instr_bytes="$(system_call_write "${symbol_type}" "${data_output}" "$data_addr_v" "$data_bytes_len" "${instr_offset}" | xd2b64)";
	data_bytes="";
	data_bytes_len=0;
	#if [ "${symbol_type}" == "${SYMBOL_TYPE_HARD_CODED}" ]; then
	#	data_bytes_len=8; # actually we need to calculate how many bytes we need to print using the hardcoded value
	#fi;
	local instr_size="$(echo -e "$instr_bytes" | b64cnt)";
	struct_parsed_snippet \
		"INSTRUCTION" \
		"${SYMBOL_TYPE_PROCEDURE}" \
		"sys_write" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_size}" \
		"${dyn_data_offset}" \
		"${data_bytes}" \
		"${data_bytes_len}" \
		"${CODE_LINE_B64}" \
		"1";
	return;
}

