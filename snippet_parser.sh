#!/bin/bash
#
# The concept of the snippet parser is to create a table will all data we need to generate the executable binary output
#
# the result shoulb be a csv line with:
# 1 snippet_type
#    EMPTY|INVALID|COMMENT|INSTRUCTION|SNIPPET|SNIPPET_CALL
# 2 snippet_subname
#    for snippet_type INSTRUCTION: sys_exit, sys_write
#    for snippet_type SNIPPET: the block name
# 3 snippet_instruction_offset
#    The relative address of the first instruction (in bytes) of this snippet.
#    Relative means that the first instruction is 0, the next snippet will have the offset as previous snippet instruction offset+len.
# 4 snippet_offset_data_address
#    The relative address used but the first data entry on this snippet
# 5 snippet_instruction_bytes
#    all instructions generated by this snippet in the final binary in b64
# 6 snippet_data_bytes
#    all data bytes by this snippet in the final binary in b64
# 7 snippet_source_code
#    The base 64 of the source lines to generate this snippet
# 8 snippet_source_lines_count
#    The number of lines envolved from the source bloc code.
#
# useful constants:
SNIPPET_COLUMN_TYPE=1;
SNIPPET_COLUMN_SUBNAME=2;
SNIPPET_COLUMN_INSTR_OFFSET=3;
SNIPPET_COLUMN_INSTR_BYTES=4;
SNIPPET_COLUMN_INSTR_LEN=5;
SNIPPET_COLUMN_DATA_OFFSET=6;
SNIPPET_COLUMN_DATA_BYTES=7;
SNIPPET_COLUMN_DATA_LEN=8;
SNIPPET_COLUMN_SOURCE_CODE=9;
SNIPPET_COLUMN_SOURCE_LINES_COUNT=10;
struct_parsed_snippet(){
	local snippet_type="$(eval echo -n \${$SNIPPET_COLUMN_TYPE})";
	if ! [[ ${snippet_type} =~ (EMPTY|INVALID|COMMENT|INSTRUCTION|SNIPPET|SNIPPET_CALL) ]]; then
		error "Invalid snippet type: $@";
		exit 1;
	fi;

	local snippet_subname="$(eval echo -n \${$SNIPPET_COLUMN_SUBNAME})";
	if [ "${snippet_type}" == INSTRUCTION ] && ! [[ "${snippet_subname}" =~ (sys_exit|sys_write|sys_ret) ]];then
		error "unsupported instruction $snippet_subname";
		exit 2;
	fi;

	local snippet_instruction_offset="$(eval echo -n \${$SNIPPET_COLUMN_INSTR_OFFSET})";
	if ! is_valid_number "$snippet_instruction_offset"; then
		error "snippet_instruction_offset is not a valid number";
		exit 3;
	fi;

	local snippet_instruction_bytes="$(eval echo -n \"\${$SNIPPET_COLUMN_INSTR_BYTES}\" | tr -d '\n')";

	local snippet_instruction_len="$(eval echo -n \${$SNIPPET_COLUMN_INSTR_LEN})"
	local expected_instr_len="$(
		echo -n "$snippet_instruction_bytes" | base64 -d | wc -c
	)";
	if [ "${snippet_instruction_len}" -ne "$expected_instr_len" ]; then
		error "at ${snippet_subname} the instruction len and the instruction bytes does not match, expected ${expected_instr_len} but got ${snippet_instruction_len}"
		exit 4;
	fi;

	local snippet_data_offset="$(eval echo -n \${$SNIPPET_COLUMN_DATA_OFFSET})"
	if ! is_valid_number "${snippet_data_offset}"; then
		error "at ${snippet_type}:${snippet_subname} the snippet data offset is not a valid number"
		exit 5;
	fi;

	local snippet_data_bytes="$(eval echo -n \"\${$SNIPPET_COLUMN_DATA_BYTES}\" | tr -d '\n' )";

	local snippet_data_len="$(eval echo -n \${$SNIPPET_COLUMN_DATA_LEN})";
	local expected_data_len=$( echo -n "$snippet_data_bytes" | base64 -d | wc -c );
	if ! [ "${snippet_data_len}" -eq "${expected_data_len}" ]; then
		error "at ${snippet_type}:${snippet_subname} the data len(${snippet_data_len}) and the data bytes(${expected_data_len}) does not match";
		exit 6;
	fi;

	# SNIPPET_COLUMN_SOURCE_CODE
	local snippet_source_code="$(eval echo -n \"\${$SNIPPET_COLUMN_SOURCE_CODE}\")";

	# SNIPPET_COLUMN_SOURCE_LINES_COUNT
	expected_source_lines_count=$((
		$(
			{
				[ "$snippet_source_code" == "" ] && echo ||
				echo "$snippet_source_code" | base64 -d ;
			} |
			grep -c "" || error "fail at SNIPPET_COLUMN_SOURCE_LINES_COUNT for [$snippet_source_code]"
		)
	));
	local snippet_source_lines_count="$(eval echo -n \${$SNIPPET_COLUMN_SOURCE_LINES_COUNT})";
	if ! is_valid_number "$snippet_source_lines_count" ||
	   [ "$snippet_source_lines_count" -ne "${expected_source_lines_count}" ] ; then
	   error "at ${snippet_subname} the source lines count(${snippet_source_lines_count}) does not match the actual source lines(${expected_source_lines_count}): [$snippet_type][${snippet_source_code}]"
	fi;

	local snippet_result="";
	snippet_result="${snippet_result}${snippet_type}";
	snippet_result="${snippet_result},${snippet_subname}";
	snippet_result="${snippet_result},${snippet_instruction_offset}";
	snippet_result="${snippet_result},${snippet_instruction_bytes}";
	snippet_result="${snippet_result},${snippet_instruction_len}";
	snippet_result="${snippet_result},${snippet_data_offset}";
	snippet_result="${snippet_result},${snippet_data_bytes}";
	snippet_result="${snippet_result},${snippet_data_len}";
	snippet_result="${snippet_result},${snippet_source_code}"
	snippet_result="${snippet_result},${snippet_source_lines_count}"
	local snippet_output_lines=$(echo "${snippet_result}" | wc -l)
	if ! [ "${snippet_output_lines}" -eq 1 ]; then
		error "snippet result was not 1 output line: [$snippet_result], output lines ${snippet_output_lines}";
		exit 7;
	fi

	echo "${snippet_result}";
}

is_valid_number()
{
	[ "$1" -eq "$1" ] 2>/dev/null;
	return $?
}

