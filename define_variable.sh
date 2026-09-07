define_variable(){
	local dyn_data_offset="$1";
	local deep="$2";
	# All variables, constants, macros are symbols and should be managed by a symbol table
	# It should have name type, scope and memory address
	# The compiler should updated that items in the first code read
	#
	# Constants should replace the code value before process the code.
	# Constants should not keep in memory, instead should replace the value hardcoded in bytecode.
	# Variables should recover the target address and size at runtime.
	# A variable and constant are defined at the same way. The compiler should consider everything as constant.
	# Once the code changes the variable value, it will be converted to variable.
	# So if a variable is never changed, it will be always a constant hardcoded at the bytecode;
	local symbol_name;
	symbol_name="$second_elem"
	debug "define_variable symbol_name: $symbol_name";
	#local symbol_name="$(echo -n "${symbol_name/:*/}")";
	local sec_arg;
	sec_arg="$(echo -n "${code_line_elements[$(( 2 + deep-1 ))]:-}")"
	debug "define_variable sec_arg=$sec_arg"
	local symbol_data;
	symbol_data="$(echo "$SNIPPETS" | grep "SYMBOL_TABLE,[^,]*,${symbol_name}," | tail -1)";
	if [ "$sec_arg" == "?s" ]; then # define a test
	{
		debug "def a string test";
		define_variable_from_test string
		return
	}
	fi;
	if [ "$sec_arg" == "?" ]; then # define a test
	{
		debug "define a test";
		define_variable_from_test
		return
	}
	fi;
	if [[ "${sec_arg}" =~ \<=$ ]]; then # read from file into var
	{
		debug "def var read from file";
		define_variable_read_from_file
		return
	}
	fi;
	if [ "$sec_arg" == "+" ]; then # increment a variable
	{
		debug "def increment var";
		define_variable_increment
		return
	}
	fi;
	if [[ "$sec_arg" =~ ^@[0-9]*$ ]]; then # capture the argument into variable
	{
		debug "capt arg into var";
		dynamic_data_offset=$(get_current_dynamic_data_offset "${SNIPPETS}" "${CODE_LINE_B64}");
		static_data_offset="$current_static_data_address";
		dyn_data_offset="$(( zero_data_offset + static_data_size + dynamic_data_offset))";
		define_variable_arg "$SNIPPETS";
		return;
	}
	fi
	if [[ "$sec_arg" =~ ^@[$]$ ]]; then # capture the argument count into variable
	{
		debug "capture arg count into var";
		# create a new dynamic symbol called ${symbol_name}
		# That should point to the rbp register first 8 bytes (int)
		# argc_addr: memory address to put the argc
		#   should i use the snippets data?
		argc_pos=$dyn_data_offset;
		instr_bytes="$(get_arg_count $argc_pos | xd2b64)";
		instr_len=$(echo -n "${instr_bytes}" | b64cnt );
		data_bytes="";
		data_len="8"; # pointer size
		struct_parsed_snippet \
			"SYMBOL_TABLE" \
			"${SYMBOL_TYPE_PROCEDURE}" \
			"${symbol_name}" \
			"${instr_offset}" \
			"${instr_bytes}" \
			"${instr_len}" \
			"${dyn_data_offset}" \
			"${data_bytes}" \
			"${data_len}" \
			"${CODE_LINE_B64}" \
			"1";
		return;
	}
	fi;
	if [ "$sec_arg" == "!" ]; then # exec and capture output into variable
	{
		debug "exec fn and capture out into var";
		# TODO: if the first array position is a function
		local array_symbol="${code_line_elements[$((3 + deep - 1))]}";
		if is_function_call $array_symbol "${SNIPPETS}"; then
			debug "call function $array_symbol"
			define_variable_from_fn SNIPPETS deep code_line_elements;
		else
			debug "exec external command $array_symbol"
			define_variable_from_exec;
		fi;
		return;
	}
	fi;
	if [ "$sec_arg" == "[]" ]; then # exec and capture output into variable
	{
		debug "# exec and capture output into var"
		define_array_variable "${dyn_data_offset}";
		return;
	}
	fi;
	if [ "$sec_arg" == "<b" ]; then #read byte
	{
		debug "#define_read_byte";
		define_read_byte "${SNIPPETS}"
		return;
	}
	fi;
	debug "code_line_elements[0] = [${code_line_elements[0]:-}]";
	debug "code_line_elements[1] = [${code_line_elements[1]:-}]";
	debug "code_line_elements[2] = [${code_line_elements[2]:-}]";
	debug "code_line_elements[3] = [${code_line_elements[3]:-}]";
	debug "code_line_elements[4] = [${code_line_elements[4]:-}]";
	debug "code_line_elements[5] = [${code_line_elements[5]:-}]";
	debug "before check code_line_elements [${#code_line_elements[@]}] for $(( 3 + deep -1 ))"
	if [ "${#code_line_elements[@]}" == "$(( 3 + deep - 1 ))" ]; then
	{
		debug "# New symbol";
		symbol_value="${sec_arg}";
		instr_bytes="";
		instr_len=0;
		data_bytes="$(set_symbol_value "${symbol_value}" "${SNIPPETS}")";
		data_len="$( echo -n "${data_bytes}" | b64cnt)";
		local symbol_type=${SYMBOL_TYPE_DYNAMIC}
		if is_static_value "${data_bytes}"; then
			symbol_type=${SYMBOL_TYPE_STATIC}
		fi;
		if is_hard_coded_value "${data_bytes}" "${symbol_name}"; then
			data_len=0; # hard-coded values does not use data space
			symbol_type=${SYMBOL_TYPE_HARD_CODED}
		fi;
		# if this is not the first static variable, we need to append 1 to the static_data_offset,
		# because it should be an \x00(null byte) between static data.
		struct_parsed_snippet \
			"SYMBOL_TABLE" \
			"${symbol_type}" \
			"${symbol_name}" \
			"${instr_offset}" \
			"${instr_bytes}" \
			"${instr_len}" \
			"${static_data_offset}" \
			"${data_bytes}" \
			"${data_len}" \
			"${CODE_LINE_B64}" \
			"1";
		return;
	}
	fi;
	# concat all symbols in a new one
	define_concat_variable
	return;
}

