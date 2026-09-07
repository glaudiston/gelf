#!/bin/bash
define_read_byte(){
	local SNIPPETS="$1";
	local file_descriptor_name="${code_line_elements[$(( 3 + deep-1 ))]}";
	local file_descriptor_snip=$(get_b64_symbol_value "${file_descriptor_name}" "${SNIPPETS}")
	# sys_open will create a new file descriptor.
	local symbol_type=$(echo "${file_descriptor_snip}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	debug "reading byte from $file_descriptor_name == $symbol_type and storing at $dyn_data_offset";
	# TODO use a better place this is an insecure way, because on this page
	# we have all code, so we can rewrite it.
	local ptr_data_size=8;
	if [ "${symbol_type}" != "${SYMBOL_TYPE_STATIC}" ]; then
		data_bytes="";
		data_bytes_len=0; # no data to append. just registers used.
		sym_dyn_data_size=$(get_sym_dyn_data_size "${input_symbol_name}" "${SNIPPETS}")
		data_addr_v="$(( dyn_data_offset ))";
		data_offset="${dyn_data_offset}";
	else
		data_offset="${static_data_offset}";
	fi;
	local filename_addr=$(get_symbol_addr "${file_descriptor_name}" "$SNIPPETS")
	local size=1;
	local stdin=0;
	local fd=$stdin;
	local read_code="$(system_call_read "${fd}" "${size}" "${dyn_data_offset}" | xd2b64)";
	# it should return the bytecode, the size
	#fd="$(set_symbol_value "${symbol_value} fd" "${SYS_OPEN}")";
	# We should create a new dynamic symbol to have the file descriptor number
	#CODE="${CODE}$(sys_read $)"
	local instr_bytes="${read_code}"
	local instr_len=$(echo -n "${instr_bytes}" | b64cnt )
	local data_bytes="";
	local data_len=1;
	local source_line_count=1;
	local usage_count=0;
	local return_value="";
	local dependencies="";
	struct_parsed_snippet \
		"SYMBOL_TABLE" \
		"${SYMBOL_TYPE_PROCEDURE}" \
		"${symbol_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"${CODE_LINE_B64}" \
		"${source_line_count}" \
		"${usage_count}" \
		"${return_value}" \
		"${dependencies}";
	return;
}
