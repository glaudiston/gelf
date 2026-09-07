#!/bin/bash
import_bash <<-EOF
	./struct_parsed_snippet.sh
	./parse_snippet.sh
EOF
# should return multiple struct_parsed_snippet output (one per line)
parse_snippets()
{
	local ROUND="$1";
	local PH_VADDR_V="$2";
	local INSTR_TOTAL_SIZE="$3";
	local static_data_size="$4"
	local SNIPPETS="$5"; # cummulative to allow cross reference between snippets
	local deep="${6-0}";
	local CODE_INPUT;
	read -r -d '' CODE_INPUT;
	(( deep++ )) || :;
	debug "parse_snippets in deep $deep; snippets: $SNIPPETS";
	local instr_offset="0"
	local static_data_offset=0;
	# for now this is just a placeholder for template code before a code line
	# maybe useful for debugging code or something like that.
	struct_parsed_snippet \
		"INSTRUCTION" \
		"${SYMBOL_TYPE_PROCEDURE}" \
		"_before_" \
		"${instr_offset}" \
		"" \
		"0" \
		"${static_data_offset}" \
		"" \
		"0" \
		"" \
		"0";
	IFS='';
	# i think is better to mmap args memory here,
	# but found hard to manage the side effects for now,
	# so keep commented.
	# SNIPPETS=$(echo "$SNIPPETS"; ensure_args_ptr $SNIPPETS);
	echo "${CODE_INPUT}" | while read -r CODE_LINE;
	do
		RESULT=$(parse_snippet "${ROUND}" "${PH_VADDR_V}" "${INSTR_TOTAL_SIZE}" "${static_data_size}" "${CODE_LINE}" "${SNIPPETS}" "${deep}");
		if [ "${#SNIPPETS}" -gt 0 ]; then
			SNIPPETS="$(echo -e "${SNIPPETS}\n$RESULT")";
		else
			SNIPPETS="$RESULT";
		fi
		# the result have multiple lines read so we need to add them to the source lines var
		inner_source_lines=$(echo "$RESULT" | cut -d, -f5);
		# TODO we can deduce the source line number by the snippets
		echo "$RESULT";
	done;
}

