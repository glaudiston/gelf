direct_bytecode(){
	local instr_bytes="$(echo ${CODE_LINE} | xxd --ps -r | base64 -w0)";
	instr_len="$(echo "${instr_bytes}" | b64cnt)";
	local data_bytes="";
	local data_len="";
	struct_parsed_snippet \
		"INSTRUCTION" \
		"${SYMBOL_TYPE_PROCEDURE}" \
		"bytecode" \
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

