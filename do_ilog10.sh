do_ilog10(){
	base="10"
	local target="${code_line_elements[$(( 4 + deep-1 ))]}";
	target_offset="$( echo "$SNIPPETS" | grep "PROCEDURE_TABLE,[^,]*,${target}," | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET} )";
	jmp_bytes="$(call_procedure "$((target_offset + 2))" "${instr_offset}" | xd2b64)";
	jmp_len="$(echo "${jmp_bytes}" | b64cnt)";
	struct_parsed_snippet \
		"SNIPPET_CALL" \
		"${SYMBOL_TYPE_PROCEDURE}" \
		"jmp" \
		"${instr_offset}" \
		"${jmp_bytes}" \
		"${jmp_len}" \
		"${static_data_offset}" \
		"" \
		"0" \
		"${CODE_LINE_B64}" \
		"1";
	return;
}

