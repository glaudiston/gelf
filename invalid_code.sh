invalid_code(){
	error "ignoring invalid code line instruction: [$CODE_LINE_B64][$first_elem]";
	struct_parsed_snippet \
		"INVALID" \
		"${SYMBOL_TYPE_HARD_CODED}" \
		"" \
		"${instr_offset}" \
		"" \
		"0" \
		"${static_data_offset}" \
		"" \
		"0" \
		"${CODE_LINE_B64}" \
		"1";
}

