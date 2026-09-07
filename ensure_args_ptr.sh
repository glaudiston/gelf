#!/bin/bash
import_bash ./get_args_ptr.sh
# ensure_args_ptr is called when we do use arguments;
# on first use it calls mmap to allocate memory and creates a
# snippet to store the memory address dinamically set by sys_mmap
ensure_args_ptr()
{
	local snippets="${1:-}";
	local args_ptr=$(get_args_ptr "$snippets")
	if [ "$args_ptr" != "" ]; then
		return;
	fi;
	local snippet_type="${SYMBOL_TYPE_DYNAMIC}";
	local snippet_name="_INTERNAL_ARGS_MMAP";
	local data_offset="${dyn_data_offset}";
	local instr_bytes="$(sys_mmap $PAGESIZE "" "$data_offset"|xd2b64)";
	local instr_size="$(echo $instr_bytes | b64cnt)"
	local data_bytes="";
	local data_bytes_len="8";
	local bloc_outer_code_b64="$(echo -n "builtin..args_mmap" | base64 -w0)";
	local bloc_source_lines_count="0";
	local bloc_usage_count="0";
	local bloc_return="";
	local bloc_dependencies="";
	struct_parsed_snippet \
		"SYMBOL_TABLE" \
		"${snippet_type}" \
		"${snippet_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_size}" \
		"${data_offset}" \
		"${data_bytes}" \
		"${data_bytes_len}" \
		"${bloc_outer_code_b64}" \
		"${bloc_source_lines_count}" \
		"${bloc_usage_count}" \
		"${bloc_return}" \
		"${bloc_dependencies}";
}
