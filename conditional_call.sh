#!/bin/bash
conditional_call(){
	local test_symbol_name="${second_elem}";
	local target="${code_line_elements[$(( 3 + deep-1 ))]}";
	local target_offset="$( echo "$SNIPPETS" | grep "[^,]*,[^,]*,${target}," | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET} )";
	local arguments=(); # TODO implement args
	local arguments_map=();
	# TODO jump or call ?
	local instr_bytes="$(jump_if_equal "$(( target_offset + 2 - (deep-1) * 2 ))" "${instr_offset}" "${arguments:-}" "${arguments_map:-}" )"; # 2 is the jump instr expected to be at the snip first instr, each deep level have 2 bytes for the instr call
	local instr_len="$(echo "${instr_bytes}" | b64cnt)";
	local data_bytes="";
	local data_len=0;
	struct_parsed_snippet \
		"SNIPPET_CALL" \
		"${SYMBOL_TYPE_PROCEDURE}" \
		"je" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${static_data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"${CODE_LINE_B64}" \
		"1";
}

