#!/usr/bin/env bash

define_variable_from_fn(){
	local -n _SNIPPETS=$1;
	local -n _deep=$2;
	local -n _code_line_elements=$3
	local target="${_code_line_elements[$(( 3 + _deep-1 ))]}";
	local retval_addr;
	retval_addr="${dyn_data_offset}";
	local data_len=8; # for now we don't know if the function does return values, so, consider that it always return something
	local target_fn="$target";
	local data_bytes="";
	if [[ "$target" == sys_geteuid ]]; then
	{
		instr_bytes="$(sys_geteuid "${dyn_data_offset}" | xd2b64)";
		data_len=8;
		data_bytes="";
	}
	elif is_user_function "$target" "${_SNIPPETS}"; then
	{
		local target_fn_data;
		target_fn_data=$(echo "$_SNIPPETS" | grep "PROCEDURE_TABLE,[^,]*,${target},");
		target_offset="$( echo "$target_fn_data" | cut -d, -f"${SNIPPET_COLUMN_INSTR_OFFSET}" )";
		#data_len=$(echo $target_fn_data | cut -d, -f${SNIPPET_COLUMN_DATA_LEN});
		local jmp_size;
		jmp_size=$(get_jmp_size "${_SNIPPETS}" "${target}" );
		instr_bytes="$(call_procedure "$((target_offset + jmp_size))" "${instr_offset}" "" "${retval_addr}" | xd2b64)";
		error "fn call not implemented";
		# create an array with the fn as first arg
		# use the array to call
	}
	else	# if the first item at the array is a function
	{
		local target_data;
		target_data="$( echo "$_SNIPPETS" | grep "SYMBOL_TABLE,${SYMBOL_TYPE_ARRAY},${target}," )";
		local symbol_source_code;
		symbol_source_code=$(echo "$target_data" | cut -d, -f"${SNIPPET_COLUMN_SOURCE_CODE}");
		target_fn=$(echo "$symbol_source_code" | base64 -d| cut -d: -f2- | cut -f4);
		local target_fn_data;
		target_fn_data="$(echo "$_SNIPPETS" | grep "PROCEDURE_TABLE,[^,]*,${target_fn},")";
		local target_addr;
		target_addr=$(echo "$target_fn_data" | cut -d, -f"${SNIPPET_COLUMN_INSTR_OFFSET}");
		if [[ "$target_addr" == "" ]]; then
			error "unable to recover the target address for the target fn [$target_fn]";
		fi;
		#data_len=$(echo $target_fn_data | cut -d, -f${SNIPPET_COLUMN_DATA_LEN});
		local jmp_size;
		jmp_size=$(get_jmp_size "${_SNIPPETS}" "${target_fn}" );
		target_addr=$((target_addr + jmp_size));
		instr_bytes="$(call_procedure "${target_addr}" "${instr_offset}" "${SYMBOL_TYPE_ARRAY}" "${retval_addr}" | xd2b64 )";
	}
	fi;
	instr_len="$(echo "$instr_bytes" | b64cnt)";
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

