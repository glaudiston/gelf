parse_code_bloc(){
	local SNIPPETS="$1";
	local instr_bytes="";
	SNIPPET_NAME="$second_elem";
	code_bloc="$(echo "${CODE_LINE}"; read_code_bloc "${deep}")";
	bloc_outer_code_b64="$(echo -n "${code_bloc}" | base64 -w0 )";
	local instr_size=0;
	local data_bytes="";
	local data_size=0;
	local bloc_snip_preview="$(struct_parsed_snippet \
		"PROCEDURE_TABLE" \
		"${SYMBOL_TYPE_PROCEDURE}" \
		"${SNIPPET_NAME}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_size}" \
		"${static_data_offset}" \
		"${data_bytes}" \
		"${data_size}" \
		"" \
		"0";
	)";
	SNIPPETS="$(echo -en "${SNIPPETS}\n${bloc_snip_preview}")";
	recursive_parse=$(parse_code_bloc_instr);
	SNIPPETS="$1";
	instr_bytes=$(echo "$recursive_parse"  |
		cut -d, -f$SNIPPET_COLUMN_INSTR_BYTES
	);
	local innerlines="$(echo "$recursive_parse"  |
		cut -d, -f$SNIPPET_COLUMN_SOURCE_LINES_COUNT |
		awk '{s+=$1}END{print s}'
	)";
	local bloc_source_lines_count=$(( innerlines +2 ))
	local bloc_dependencies="$(echo "$recursive_parse"  |
		cut -d, -f$SNIPPET_COLUMN_DEPENDENCIES | tr "," "\n" | sort | uniq | sed '/^$/d' | tr '\n' ',' | sed 's/,$//g';
	)";
	local instr_size_sum="$( echo "${instr_bytes}" |
		b64cnt |
		awk '{s+=$1}END{print s}';
	)";
	local jump_bytecode_len=0; # jump is a dynamic instr, it can change size based on how far is the target.
	# so we will try until it stop changing the instr size.
	local current_addr=$((PH_VADDR_V + INSTR_TOTAL_SIZE));
	local target_addr=$((current_addr + jump_bytecode_len + instr_size_sum));
	local jump_bytecode="";
	target_addr=$((current_addr + instr_size_sum));
	jump_bytecode=$(jump "$target_addr" "$current_addr" | xd2b64);
	jump_bytecode_len=$(echo $jump_bytecode | b64cnt);
	instr_offset=$(( instr_offset + jump_bytecode_len ));
	SNIPPETS="$(echo -en "${SNIPPETS}\n${bloc_snip_preview}")";
	recursive_parse=$(parse_code_bloc_instr); # parse again with the correct instruction displacement because jump instr size can change over the bloc size
	SNIPPETS="$1";
	instr_bytes=$(echo "$recursive_parse"  |
		cut -d, -f$SNIPPET_COLUMN_INSTR_BYTES
	);
	instr_offset=$(( instr_offset - jump_bytecode_len )); # revert the position because the jump have to be at snippet instr.
	instr_size_sum=$((instr_size_sum + jump_bytecode_len));
	instr_bytes="${jump_bytecode}${instr_bytes}";
	local data_bytes="$(echo "$recursive_parse"  |
		cut -d, -f$SNIPPET_COLUMN_DATA_BYTES )"
	local data_bytes_sum="$( echo "${data_bytes}" |
		b64cnt |
		awk '{s+=$1}END{print s}'
	)";
	local bloc_usage_count=0;
	local bloc_return="";
	out="$(struct_parsed_snippet \
		"PROCEDURE_TABLE" \
		"${SYMBOL_TYPE_PROCEDURE}" \
		"${SNIPPET_NAME}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_size_sum}" \
		"${static_data_offset}" \
		"${data_bytes}" \
		"${data_bytes_sum}" \
		"${bloc_outer_code_b64}" \
		"${bloc_source_lines_count}" \
		"${bloc_usage_count}" \
		"${bloc_return}" \
		"${bloc_dependencies}";
	)";
	echo "$out";
}

