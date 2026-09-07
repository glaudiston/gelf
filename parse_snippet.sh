#!/bin/bash

# parse_snippet given a source code snippet echoes snippet struct to stdout
# allowing a pipeline to read a full instruction or bloc at time;
# it should return a code snippet
parse_snippet()
{
	local ROUND="$1";
	local PH_VADDR_V="$2";
	local INSTR_TOTAL_SIZE="$3";
	local static_data_size="$4"; # full static data length
	local CODE_LINE="$5";
	local SNIPPETS="$6";
	local deep="$7";
	debug "parse_snippet (deep $deep): compiling code line [$CODE_LINE]";
	# Bash issue here. The array parse syntax ( ${CODE_LINE} ) loses spaces.
	# to overcome that I need to write a hack
	local code_line_elements;# =( ${CODE_LINE} );
	# array hack: because ( ${CODE_LINE} ) will trim spaces.
	eval "code_line_elements=( $(echo "${CODE_LINE}" | tr '\t' '\n' | sed 's/^\(.*\)$/"\1"/g') )";
	local first_elem="${code_line_elements[$(( 0 + deep-1 ))]}";
	local second_elem="${code_line_elements[$(( 1 + deep-1 ))]:-}";
	local CODE_LINE_XXD="$( echo -n "${CODE_LINE}" | xxd --ps)";
	local CODE_LINE_B64=$( echo -n "${CODE_LINE}" | base64 -w0);
	local previous_snippet=$( echo "${SNIPPETS}" | tail -1 );
	local instr_offset=$(get_instr_offset "${previous_snippet}");
	local zero_data_offset=$( get_zero_data_offset "$PH_VADDR_V" "$INSTR_TOTAL_SIZE" );
	local static_data_displacement=$(get_current_static_data_displacement "${SNIPPETS}" "${CODE_LINE_B64}");
	local current_static_data_address=$((zero_data_offset + static_data_displacement));
	local dynamic_data_offset=$(get_current_dynamic_data_offset "${SNIPPETS}" "${CODE_LINE_B64}");
	local static_data_offset=$current_static_data_address;
	local dyn_data_offset="$(( zero_data_offset + static_data_size + dynamic_data_offset))";
	debug "first_elem=$first_elem; second_elem=$second_elem;"

	if [ "$CODE_LINE" == "" ]; then
	{
		empty_line;
		return;
	}
	fi;
	if [[ "$first_elem" =~ ^[#] ]]; then # ignoring tabs, starts with pound symbol(#)
	{
		do_comment;
		return;
	}
	fi;
	if [[ "$first_elem" == : ]]; then
	{
		do_define "${dyn_data_offset}" "${deep}";
		return
	}
	fi;
	# calls to internal, system or user functions
	if [[ "$first_elem" == ! ]]; then
	{
		do_call;
		return;
	}
	fi;
	if is_valid_hex "${CODE_LINE}"; then
	{
		direct_bytecode;
		return;
	}
	fi;
	if [[ "$first_elem" == "ret" ]]; then
		do_return "$second_elem" "${SNIPPETS}";
		return;
	fi;
	invalid_code;
	return;
}

