create_internal_s2i_snippet()
{
	local symbol_name="$1";
	local SNIPPETS="$2";
	local PH_VADDR_V="$3";
	local INSTR_TOTAL_SIZE="$4";
	local snippet_type=$SYMBOL_TYPE_PROCEDURE;
	local snippet_name="$symbol_name";
	local instr_offset="$(get_instr_offset "$( echo "$SNIPPETS" | tail -1)")";
	local zero_data_pos=$(get_zero_data_offset "$PH_VADDR_V" "$INSTR_TOTAL_SIZE");
	local dyn_data_size=$(get_dynamic_data_size "${SNIPPETS}")
	local dynamic_data_offset="$(( zero_data_pos + dyn_data_size ))"
	local instr_bytes="$(s2i | xdr | base64 -w0)";
	local instr_size="$(echo "$instr_bytes" | b64cnt)";
	local jump_bytes="$(jump_relative $instr_size|xd2b64)";
	instr_bytes=$(echo "$jump_bytes$instr_bytes");
	instr_size="$(echo $instr_bytes | b64cnt)";
	local data_bytes="";
	local data_bytes_size="32";
	local bloc_outer_code_b64="$(echo -n "builtin.$symbol_name" | base64 -w0)";
	local bloc_source_lines_count=0;
	local bloc_usage_count=1;
	local bloc_return="";
	local bloc_dependencies="";
	struct_parsed_snippet \
		"PROCEDURE_TABLE" \
		"${snippet_type}" \
		"${snippet_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_size}" \
		"${dynamic_data_offset}" \
		"${data_bytes}" \
		"${data_bytes_size}" \
		"${bloc_outer_code_b64}" \
		"${bloc_source_lines_count}" \
		"${bloc_usage_count}" \
		"${bloc_return}" \
		"${bloc_dependencies}";
}

