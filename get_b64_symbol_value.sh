#!/usr/bin/env bash
#
# it returns
declare -xg \
	B64_SYMBOL_VALUE_RETURN_OUT=1 \
	B64_SYMBOL_VALUE_RETURN_SIZE=2 \
	B64_SYMBOL_VALUE_RETURN_TYPE=3 \
	B64_SYMBOL_VALUE_RETURN_ADDR=4 \
	B64_SYMBOL_VALUE_RETURN_SOURCE_CODE=5;

get_b64_symbol_value()
{
	local symbol_name="$1";
	local SNIPPETS=$2;
	local input="ascii";
	local out="";
	local outsize="";
	# empty value
	if [ "$symbol_name" == "" ]; then
		echo -n ",0,${SYMBOL_TYPE_HARD_CODED},0";
		return;
	fi;
	# hard coded number
	if is_valid_number "$symbol_name"; then {
		out=$(echo -n "$symbol_name" | base64 -w0);
		outsize=$(echo -n "${out}" | b64cnt)
		echo -n "${out},${outsize},${SYMBOL_TYPE_HARD_CODED}"
		return
	}
	fi;
	local symbol_data;
	symbol_data="$(echo "$SNIPPETS" | grep "SYMBOL_TABLE,[^,]*,${symbol_name}," | tail -1)";
	# return default values for known internal words
	if [ "${symbol_name}" == "input" ]; then
	{
		local symbol_instr;
		symbol_instr="$( echo "$symbol_data" | cut -d, -f"${SNIPPET_COLUMN_DATA_BYTES}")";
		local out;
		out=$(echo -n "${symbol_instr}");
		if [ "$out" == "" ]; then
			out=$(echo -n 'ascii' | base64 -w0);
		fi;
		local outsize;
		outsize="$(echo -n "${out}" | b64cnt)";
		echo -n "${out},${outsize},${SYMBOL_TYPE_HARD_CODED}";
		return;
	}
	fi;
	# procedure
	local procedure_data;
	procedure_data="$( echo "$SNIPPETS" | grep "PROCEDURE_TABLE,[^,]*,${symbol_name}," | tail -1)";
	if [ "${procedure_data}" != "" ]; then
		local addr;
		addr=$(echo "${procedure_data}" | cut -d, -f"${SNIPPET_COLUMN_INSTR_OFFSET}");
		echo -n "${out},${outsize},${SYMBOL_TYPE_PROCEDURE},${addr}"
		return 1;
	fi;
	if [ "${symbol_data}" == "" ]; then
	{
		# check syscalls that returns data
		if is_system_function "${symbol_name}"; then
			out=$(echo -n "$symbol_name" | base64 -w0);
			outsize=$(echo -n "${out}" | b64cnt)
			echo -n ${out},${outsize},${SYMBOL_TYPE_SYSCALL}
			return 1;
		fi;
		if is_internal_function "${symbol_name}"; then
			out=$(echo -n "$symbol_name" | base64 -w0);
			outsize=$(echo -n "${out}" | b64cnt);
			echo -n "${out},${outsize},${SYMBOL_TYPE_SYSCALL},0"
			return 1;
		fi;
		error "Expected a integer or a valid variable/constant. But got [$symbol_name][$SNIPPETS]"
		backtrace
		return 1
	}
	fi;
	local symbol_value;
	symbol_value="$( echo "$symbol_data" | cut -d, -f"${SNIPPET_COLUMN_DATA_BYTES}")";
	local symbol_len;
	symbol_len="$( echo "$symbol_data" | cut -d, -f"${SNIPPET_COLUMN_DATA_LEN}")";
	local symbol_type;
	symbol_type="$( echo "$symbol_data" | cut -d, -f"${SNIPPET_COLUMN_SYMBOL_TYPE}")";
	local symbol_addr;
	symbol_addr="$( echo "$symbol_data" | cut -d, -f"${SNIPPET_COLUMN_DATA_OFFSET}")";
	local symbol_source_code;
	symbol_source_code="$( echo "$symbol_data" | cut -d, -f"${SNIPPET_COLUMN_SOURCE_CODE}")";
	if [ "${symbol_value}" == "" ]; then # dynamic or hard-coded?
	{
		if [ "${symbol_len}" == 0 ]; then
			echo -n ",0,${SYMBOL_TYPE_HARD_CODED}"
			return;
		fi;
		# Empty values will be only accessible at runtime, eg: args, arg count...
		out=$(echo -n "${symbol_addr}" | base64 -w0)
		if [ "${symbol_type}" == "$SYMBOL_TYPE_ARRAY" ]; then
			echo -n "${out},${symbol_len},${symbol_type},${symbol_addr},${symbol_source_code}"
			return
		fi
		outsize=${symbol_len}; # normally memory_addr_size ptr (8 bytes);
		                       # but in ptr to open file content it is the stat struct size +mem ptr size;
							   # TODO: this is platform specific, in x64 is 8 bytes
		data_flags="$(echo "${symbol_data}" | cut -d, -f"${SNIPPET_COLUMN_DATA_FLAGS}")"
		if [ "${data_flags}" == "ARGUMENT" ]; then
			echo -n "${out},${outsize},${SYMBOL_TYPE_DYNAMIC_ARGUMENT},${symbol_addr}"
		else
			echo -n "${out},${outsize},${SYMBOL_TYPE_DYNAMIC},${symbol_addr}"
		fi;
		return;
	};
	fi
	if is_valid_number "$(echo "${symbol_value}" | base64 -d | tr -d '\0')"; then
	{
		out="$symbol_value";
		outsize=$(echo -n "${out}" | b64cnt)
		echo -n "${out},${outsize},${SYMBOL_TYPE_HARD_CODED}"
		return
	}
	fi;
	out=$(echo -n "${symbol_value}")
	outsize=$(echo -n "${out}" | b64cnt)
	echo -n "${out},${outsize},${SYMBOL_TYPE_STATIC},${symbol_addr}"
	return
	# TODO, increment usage count in SNIPPETS SYMBOL_TABLE
}
