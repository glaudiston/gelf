parse_code_bloc_instr(){
	local symbol_name='_init_';
	local instr_bytes=$(init_bloc);
	local instr_len=$(echo $instr_bytes | b64cnt);
	local data_bytes="";
	local data_len=0;
	struct_parsed_snippet \
		"INSTRUCTION" \
		"${SYMBOL_TYPE_PROCEDURE} "\
		"${symbol_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${dyn_data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"" \
		"0";
	instr_offset=$(( instr_offset + instr_len ));
	bloc_inner_code="$(
		echo "${code_bloc}" |
		awk 'NR>2 {print prev}; {prev=$0};' |
		base64 -w0
	)";
	local insideSnips="";
	debug "bloc_inner_code:\n${bloc_inner_code}"
	echo "${bloc_inner_code}" |
		base64 -d | while read l; do
			debug "parse_code_bloc_instr: source line: deep 1; source: $l";
			local parsedLine=$(echo -n "$l" | parse_snippets "${ROUND}" "${PH_VADDR_V}" "${INSTR_TOTAL_SIZE}" "${static_data_size}" "$(echo -e "$SNIPPETS\n${insideSnips}\n")" "$deep")
			insideSnips=$(echo -en "${insideSnips}\n${parsedLine}\n")
			echo "${parsedLine}"
			debug "parse_code_bloc_instr: deep: $deep; insideSnips=[${insideSnips}]";
		done;
}

