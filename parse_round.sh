#!/bin/bash
import_bash ./parse_snippets.sh
# Round exists because parse_snippets can only trust addresses in final round.
# We can use it to get control of address changes like to detect the args memory spot
ROUND_FIRST=1
ROUND_FINAL=2
# we have to do multiple rounds to figure out dynamic offsets
# first round we know nothing so all will be zero
# second round we already have the values and we need to update all references
# third round we will manage the memory position with the second references set
# TODO we can do better once we have maps and a dynamic way to manage it

parseRound(){
	debug "===== parseRound $1 =====";
	local round="$1";
	local snippets_file="$2";
	internal_snippet_filename="${snippets_file}.internal";
	local internal_snippets=""
	local INSTR_TOTAL_SIZE="";
	local INPUT_SOURCE_CODE;
	INPUT_SOURCE_CODE=$(cat);
	local snippets;
	snippets=$(
		echo "${INPUT_SOURCE_CODE}" |
			parse_snippets \
				"${ROUND_FINAL}" \
				"${PH_VADDR_V}" \
				"${INSTR_TOTAL_SIZE}" \
				"${static_data_size}" \
				"${internal_snippets}"
	);

	echo -e "${internal_snippets}\n${snippets}" >"$snippets_file";
	INSTR_TOTAL_SIZE=$(detect_instruction_size_from_code "${snippets_file}");
	local static_data_size;
	static_data_size=$(detect_static_data_size_from_code "${snippets_file}");
	local internal_dependencies;
	internal_dependencies=$(detect_internal_dependencies "${snippets}" "${internal_snippet_filename}");
	echo -n "" > "${internal_snippet_filename}";
	info "parseRound: internal_dependencies are: $internal_dependencies"
	echo "$internal_dependencies" |
		while read -r dep;
		do
			[ "$dep" == "" ] && continue;
			out="$(create_internal_snippet \
				"$dep" \
				"$(cat "${internal_snippet_filename}")" \
				"${PH_VADDR_V}" \
				"${INSTR_TOTAL_SIZE}"
			)";
			debug "parseRound: dep $dep generated: $out";
			echo "$out" >> "${internal_snippet_filename}";
		done;
	debug "parseRound: a 1"
	local internal_snippets;
	internal_snippets=$(cat "${internal_snippet_filename}");
	debug "parseRound: a 2"
	# update snippets with new addr
	snippets=$(
		echo "${INPUT_SOURCE_CODE}" |
			parse_snippets \
				"${ROUND_FINAL}" \
				"${PH_VADDR_V}" \
				"${INSTR_TOTAL_SIZE}" \
				"${static_data_size}" \
				"${internal_snippets}";
	);
	debug "parseRound: a 3"
	echo -e "${internal_snippets}\n${snippets}" > "$snippets_file";
	debug "parseRound: a 4"
	echo -e "${internal_snippets}\n${snippets}" > "$snippets_file.round-$round";
	debug "parse_round done for $0 $1 $2"
}
