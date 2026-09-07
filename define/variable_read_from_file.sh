define_variable_read_from_file()
{
	local file_name="${code_line_elements[$(( 3 + deep-1 ))]}";
	local symbol_data=$(get_b64_symbol_value "${file_name}" "${SNIPPETS}")
	# sys_open will create a new file descriptor.
	local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	local input_symbol_name="$file_name"
	# TODO use a better place this is an insecure way, because on this page
	# we have all code, so we can rewrite it.
	local ptr_data_size=8;
	local stat_addr=$(( dyn_data_offset + ptr_data_size ));
	local stat_struct_size=144;
	local data_offset;
	if [ "${symbol_type}" != "${SYMBOL_TYPE_STATIC}" ]; then
		local sym_dyn_data_size data_addr_v;
		data_bytes="";
		data_bytes_len=0; # no data to append. just registers used.
		sym_dyn_data_size=$(get_sym_dyn_data_size "${input_symbol_name}" "${SNIPPETS}")
		data_addr_v="$(( dyn_data_offset ))";
		data_offset="${dyn_data_offset}";
	else
		data_offset="${static_data_offset}";
	fi;
	local filename_addr=$(get_symbol_addr "${file_name}" "$SNIPPETS")
	# Reading file involve some steps.
	# 1. Opening the file, if succeed, we have a file descriptor
	#    in success the rax will have the fd
	local open_code="$(sys_open "${filename_addr}" | xd2b64)";
	# 2. fstat that fd, so we have the information on data size, to allocate properly the memory.
	# TODO guarantee a valid writable memory location
	local fstat_code="$(sys_fstat "${stat_addr}" | xd2b64)";
	# 	To do this we need to have some memory space to set the stat data struct.
	# 	TODO decide if we should mmap every time, or have a program buffer to use.
	# 3.a. in normal files, allocate memory with mmap using the fd.
	# 3.b. in case of virtual file like pipes or nodes(/proc/...) we can't map directly, but we still need to have a memory space to read the data in, so the fstat is still necessary. We should then use the sys_read to copy the data into memory.
	# 4. So we can access the data directly using memory addresses.
	local read_code="$(read_file "${symbol_type}" "${stat_addr}" "${data_offset}" | xd2b64)";
	# it should return the bytecode, the size
	#fd="$(set_symbol_value "${symbol_value} fd" "${SYS_OPEN}")";
	# We should create a new dynamic symbol to have the file descriptor number
	#CODE="${CODE}$(sys_read $)"
	instr_bytes="${open_code}${fstat_code}${read_code}"
	instr_len=$(echo -n "${instr_bytes}" | b64cnt )
	data_bytes="";
	data_len="$(( stat_struct_size + ptr_data_size ))"; # Dynamic length, only at runtime we can know so give it the pointer size
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
		"1" \
		"0" \
		"";
	return;
}
