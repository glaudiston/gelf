#!/bin/bash
#
# This is a script with functions used to generate ELF files.
#
# see:
# - man elf
# - /usr/include/elf.h: has all information including enums
# - https://www.airs.com/blog/archives/38
# - http://www.sco.com/developers/gabi/latest/ch4.eheader.html
# - https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-83432/index.html
#
# we use base64 everywhere because bash does not support \x0 on strings
. $(dirname $(realpath $BASH_SOURCE))/pragma_once.sh || return 0
# init bloc
ARCH=$(uname -m)
# I have no idea why, but when using execve without env, a bash call can not resolve the "uname -m" call above. maybe because the PATH is not set so it is unable to call uname?
ARCH=${ARCH:=x86_64}
# include bloc
. $(dirname $(realpath $BASH_SOURCE))/elf_constants.sh
. $(dirname $(realpath $BASH_SOURCE))/types.sh
. $(dirname $(realpath $BASH_SOURCE))/utils.sh
. $(dirname $(realpath $BASH_SOURCE))/encoding.sh
. $(dirname $(realpath $BASH_SOURCE))/logger.sh
. $(dirname $(realpath $BASH_SOURCE))/endianness.sh
. $(dirname $(realpath $BASH_SOURCE))/arch/${ARCH}/bytecode.sh
. $(dirname $(realpath $BASH_SOURCE))/snippet_parser.sh
. $(dirname $(realpath $BASH_SOURCE))/elf/index.sh
. $(dirname $(realpath $BASH_SOURCE))/read_code_bloc.sh
. $(dirname $(realpath $BASH_SOURCE))/parse_code_line_elements.sh
. $(dirname $(realpath $BASH_SOURCE))/get_symbol_addr.sh
. $(dirname $(realpath $BASH_SOURCE))/get_symbol_usages.sh
. $(dirname $(realpath $BASH_SOURCE))/get_b64_symbol_value.sh
. $(dirname $(realpath $BASH_SOURCE))/set_symbol_value.sh
. $(dirname $(realpath $BASH_SOURCE))/is_a_valid_number_on_base.sh
. $(dirname $(realpath $BASH_SOURCE))/parse_data_bytes.sh
. $(dirname $(realpath $BASH_SOURCE))/is_static_value.sh
. $(dirname $(realpath $BASH_SOURCE))/is_hard_coded_value.sh
. $(dirname $(realpath $BASH_SOURCE))/get_symbol_type.sh
. $(dirname $(realpath $BASH_SOURCE))/is_internal_snippet.sh
. $(dirname $(realpath $BASH_SOURCE))/is_dynamic_snippet.sh
. $(dirname $(realpath $BASH_SOURCE))/get_snippets_until_line.sh
. $(dirname $(realpath $BASH_SOURCE))/get_snippets_until_symbol.sh
. $(dirname $(realpath $BASH_SOURCE))/is_static_data_snippet.sh
. $(dirname $(realpath $BASH_SOURCE))/get_zero_data_offset.sh
. $(dirname $(realpath $BASH_SOURCE))/get_current_static_data_displacement.sh
. $(dirname $(realpath $BASH_SOURCE))/get_current_dynamic_data_offset.sh
. $(dirname $(realpath $BASH_SOURCE))/get_sym_dyn_data_size.sh
. $(dirname $(realpath $BASH_SOURCE))/is_valid_hex.sh
. $(dirname $(realpath $BASH_SOURCE))/define/variable_increment.sh
. $(dirname $(realpath $BASH_SOURCE))/define/variable_arg.sh
. $(dirname $(realpath $BASH_SOURCE))/define/variable_read_from_file.sh
. $(dirname $(realpath $BASH_SOURCE))/define/variable_from_exec.sh
. $(dirname $(realpath $BASH_SOURCE))/define/concat_variable.sh
. $(dirname $(realpath $BASH_SOURCE))/define/variable_from_test.sh
. $(dirname $(realpath $BASH_SOURCE))/define/array_variable.sh
. $(dirname $(realpath $BASH_SOURCE))/define/read_byte.sh
. $(dirname $(realpath $BASH_SOURCE))/is_system_function.sh

# functions coded by the gelf language that will have and address to be called as a function
is_internal_function(){
	local YES=0;
	local NO=1;
	local symbol_name="$1";
	if [[ "$symbol_name" =~ ^(.ilog10|.s2i|.i2s)$ ]]; then
		return $YES;
	fi;
	return $NO;
}

# functions defined by user source code
is_user_function(){
	local YES=0;
	local NO=1;
	local symbol_name="$1";
	local SNIPPETS="$2";
	local symbol_data=$(get_b64_symbol_value "${symbol_name}" "${SNIPPETS}");
	local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	if [ "$symbol_type" == "$SYMBOL_TYPE_PROCEDURE" ]; then
		return $YES
	fi
	return $NO
}

is_function(){
	local YES=0;
	local NO=1;
	local symbol_name="$1";
	local snippets="$2";
	if \
		is_system_function $symbol_name ||
		is_internal_function $symbol_name ||
		is_user_function "$symbol_name" "${SNIPPETS}";
	then
		return $YES
	fi;
	return $NO
}
# is_function_call: given a symbol name of type array,
# check the first array item if it is a procedure
# that can be executed with a direct bytecode call
is_function_call(){
	local YES=0;
	local NO=1;
	local symbol_name="$1";
	local SNIPPETS="$2";
	local symbol_data=$(get_b64_symbol_value "${symbol_name}" "${SNIPPETS}" )
	local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	local symbol_value=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT});
	local symbol_addr="$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR})";
	local symbol_len="$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_SIZE})";
	local symbol_source_code="$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_SOURCE_CODE})";
	if [ "$symbol_type" == $SYMBOL_TYPE_SYSCALL ]; then
		return $YES;
	fi;
	if [ "$symbol_type" == $SYMBOL_TYPE_PROCEDURE ]; then
		return $YES;
	fi;
	if [ "$symbol_type" == $SYMBOL_TYPE_ARRAY ]; then
		# check if the first item at the array is a function
		first_array_arg=$(echo $symbol_source_code | base64 -d| cut -d: -f2- | cut -f4);
		if is_function "$first_array_arg"; then
			return $YES;
		fi
	fi;
	if is_function "$symbol_name"; then
		$YES
	fi;
	return $NO;
}

get_jmp_size(){
	local SNIPPETS="$1";
	local target="$2";
	local jmp_size=2; # all procedures have a jmp instruction at begining. it can be 2 or 5 bytes. 2 if the procedure body is smaller than 128 bytes;
	local target_instr_size="$( echo "$SNIPPETS" | grep "PROCEDURE_TABLE,[^,]*,${target}," | cut -d, -f${SNIPPET_COLUMN_INSTR_LEN} )";
	if [ "${target_instr_size:=0}" -gt 127 ]; then
		jmp_size=5;
	fi;
	echo $jmp_size;
}

define_variable_from_fn(){
	local SNIPPETS="${SNIPPETS}";
	local target="${code_line_elements[$(( 3 + deep-1 ))]}";
	local retval_addr="${dyn_data_offset}";
	local data_len=8; # for now we don't know if the function does return values, so, consider that it always return something
	local target_fn="$target";
	if [[ "$target" == sys_geteuid ]]; then
	{
		instr_bytes="$(sys_geteuid "${dyn_data_offset}" | xd2b64)";
		data_len=8;
		data_bytes="";
	}
	elif is_user_function "$target" "${SNIPPETS}"; then
	{
		local target_fn_data=$(echo "$SNIPPETS" | grep "PROCEDURE_TABLE,[^,]*,${target},");
		target_offset="$( echo $target_fn_data | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET} )";
		#data_len=$(echo $target_fn_data | cut -d, -f${SNIPPET_COLUMN_DATA_LEN});
		local jmp_size=$(get_jmp_size "${SNIPPETS}" "${target}" );
		instr_bytes="$(call_procedure "$((target_offset + jmp_size))" "${instr_offset}" "" "${retval_addr}" | xd2b64)";
		error "fn call not implemented";
		# create an array with the fn as first arg
		# use the array to call
	}
	else	# if the first item at the array is a function
	{
		local target_data="$( echo "$SNIPPETS" | grep "SYMBOL_TABLE,${SYMBOL_TYPE_ARRAY},${target}," )";
		local symbol_source_code=$(echo $target_data | cut -d, -f${SNIPPET_COLUMN_SOURCE_CODE});
		target_fn=$(echo $symbol_source_code | base64 -d| cut -d: -f2- | cut -f4);
		local target_fn_data="$(echo "$SNIPPETS" | grep "PROCEDURE_TABLE,[^,]*,${target_fn},")";
		local target_addr=$(echo $target_fn_data | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET});
		#data_len=$(echo $target_fn_data | cut -d, -f${SNIPPET_COLUMN_DATA_LEN});
		local jmp_size=$(get_jmp_size "${SNIPPETS}" "${target_fn}" );
		target_addr=$((target_addr + jmp_size));
		instr_bytes="$(call_procedure "${target_addr}" "${instr_offset}" "${SYMBOL_TYPE_ARRAY}" "${retval_addr}" | xd2b64 )";
	}
	fi;
	instr_len="$(echo $instr_bytes | b64cnt)";
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


define_variable(){
	local dyn_data_offset="$1";
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
	local symbol_name="$second_elem"
	debug "define_variable symbol_name: $symbol_name";
	#local symbol_name="$(echo -n "${symbol_name/:*/}")";
	local sec_arg="$(echo -n "${code_line_elements[$(( 2 + deep-1 ))]}")"
	debug "define_variable sec_arg=$sec_arg"
	local symbol_data="$(echo "$SNIPPETS" | grep "SYMBOL_TABLE,[^,]*,${symbol_name}," | tail -1)";
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
		static_data_offset=$current_static_data_address;
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
			define_variable_from_fn "${SNIPPETS}";
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

do_define(){
	local dyn_data_offset="$1";
	if [[ "${CODE_LINE_XXD}" =~ .*097b$ ]]; then # check if ends with ":\t{" ... so it's a code block function
	{
		define_code_block
		return;
	}
	fi;
	define_variable "${dyn_data_offset}";
}

parse_code_bloc_instr(){
	local symbol_name='_init_';
	local instr_bytes=$(init_bloc);
	local instr_len=$(echo $instr_bytes | b64cnt);
	local data_bytes="";
	local data_len=0;
	struct_parsed_snippet \
		"INSTRUCTION" \
		"${SYMBOL_TYPE_PROCEDURE} "\
		"${symbol_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${dyn_data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"" \
		"0";
	instr_offset=$(( instr_offset + instr_len ));
	bloc_inner_code="$(
		echo "${code_bloc}" |
		awk 'NR>2 {print prev}; {prev=$0};' |
		base64 -w0
	)";
	local insideSnips="";
	debug "bloc_inner_code:\n${bloc_inner_code}"
	echo "${bloc_inner_code}" |
		base64 -d | while read l; do
			debug "parse_code_bloc_instr: source line: deep 1; source: $l";
			local parsedLine=$(echo -n "$l" | parse_snippets "${ROUND}" "${PH_VADDR_V}" "${INSTR_TOTAL_SIZE}" "${static_data_size}" "$(echo -e "$SNIPPETS\n${insideSnips}\n")" "$deep")
			insideSnips=$(echo -en "${insideSnips}\n${parsedLine}\n")
			echo "${parsedLine}"
			debug "parse_code_bloc_instr: deep: $deep; insideSnips=[${insideSnips}]";
		done;
}

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

define_code_block(){
	# TODO add identation validation
	#
	# TODO prepend a jump move over the end of this block, so this code will be executed only if a explicit goto or call is requested.
	new_bloc="$(parse_code_bloc "$SNIPPETS")";
	local bloc_name=$(echo "$new_bloc" | cut -d, -f${SNIPPET_COLUMN_SUBNAME})
	if [ "$SNIPPETS" == "" ]; then
		SNIPPETS="$( echo "$new_bloc")";
	else
		SNIPPETS="$( echo -e "$SNIPPETS\n$new_bloc")";
	fi;
	echo "$new_bloc";
}

conditional_call(){
	local test_symbol_name="${second_elem}";
	local target="${code_line_elements[$(( 3 + deep-1 ))]}";
	local target_offset="$( echo "$SNIPPETS" | grep "[^,]*,[^,]*,${target}," | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET} )";
	local arguments=(); # TODO implement args
	local arguments_map=();
	# TODO jump or call ?
	local instr_bytes="$(jump_if_equal "$(( target_offset + 2 - (deep-1) * 2 ))" "${instr_offset}" "${arguments}" "${arguments_map}" )"; # 2 is the jump instr expected to be at the snip first instr, each deep level have 2 bytes for the instr call
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

get_instr_offset()
{
	local previous_snippet="$1";
	local previous_instr_offset=$(echo "${previous_snippet}" | cut -d, -f$SNIPPET_COLUMN_INSTR_OFFSET);
	previous_instr_offset="${previous_instr_offset:=$((PH_VADDR_V + EH_SIZE + PH_SIZE))}"
	local previous_instr_sum=$(echo "${previous_snippet}" | cut -d, -f$SNIPPET_COLUMN_INSTR_LEN | tail -1);
	local instr_offset="$(( ${previous_instr_offset} + previous_instr_sum ))";
	echo -n "${instr_offset}";
}

snippet_write()
{
	local WRITE_OUTPUT_ELEM=2;
	local WRITE_DATA_ELEM=3;
	local input_symbol_name="${code_line_elements[$(( WRITE_DATA_ELEM + deep-1 ))]}";
	local out=${code_line_elements[$(( WRITE_OUTPUT_ELEM + deep-1 ))]};
	# expected: STDOUT, STDERR, FD...
	local data_output=$(get_b64_symbol_value "${out}" "${SNIPPETS}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d | tr -d '\0' );
	# I think we can remove the parse_data_bytes and force the symbol have the data always
	local symbol_data=$(get_b64_symbol_value "${input_symbol_name}" "${SNIPPETS}");
	local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	local symbol_value=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT});
	local symbol_addr="$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR})";
	local data_bytes=$(echo -n "${symbol_value}");
	local data_bytes_len="$(echo -n "${symbol_data}"| cut -d, -f${B64_SYMBOL_VALUE_RETURN_SIZE})";
	local data_addr_v=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR});
	if [ "${symbol_type}" != "${SYMBOL_TYPE_STATIC}" ]; then
	{
		if [ "${symbol_type}" == "${SYMBOL_TYPE_PROCEDURE}" ]; then
		{
			data_bytes_len=0; # no data to append. just registers used.
			data_bytes="";
			local procedure_addr=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR});
			data_addr_v="${procedure_addr}"; # point to the procedure address
		}
		fi;
	}
	fi;
	# TODO: detect if using dyn data addr and pass it
	local input_symbol_return="$( echo "$SNIPPETS" | grep "SYMBOL_TABLE,[^,]*,${input_symbol_name}," | cut -d, -f${SNIPPET_COLUMN_RETURN} )";
	if [ "${input_symbol_return}" != "" ]; then
		data_addr_v="${input_symbol_return}";
	elif [ "${data_addr_v}" != "" ]; then
		data_addr_v="$(( data_addr_v ))";
	else
		data_addr_v="$( echo ${symbol_value} | base64 -d)"
	fi;
	local instr_bytes="$(system_call_write "${symbol_type}" "${data_output}" "$data_addr_v" "$data_bytes_len" "${instr_offset}" | xd2b64)";
	data_bytes="";
	data_bytes_len=0;
	#if [ "${symbol_type}" == "${SYMBOL_TYPE_HARD_CODED}" ]; then
	#	data_bytes_len=8; # actually we need to calculate how many bytes we need to print using the hardcoded value
	#fi;
	local instr_size="$(echo -e "$instr_bytes" | b64cnt)";
	struct_parsed_snippet \
		"INSTRUCTION" \
		"${SYMBOL_TYPE_PROCEDURE}" \
		"sys_write" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_size}" \
		"${dyn_data_offset}" \
		"${data_bytes}" \
		"${data_bytes_len}" \
		"${CODE_LINE_B64}" \
		"1";
	return;
}

do_call(){
	local third_elem="${code_line_elements[$(( 2 + deep-1 ))]}";
	# internal function calls
	if [[ "$second_elem" == ret ]]; then
	{
		do_ret;
		return;
	}
	fi;
	if [[ "$second_elem" == goto ]]; then
	{
		do_goto;
		return;
	}
	fi;
	if [[ "$second_elem" == .ilog10 ]]; then
		do_ilog10;
		return;
	fi;
	# system calls related code
	if [[ "$second_elem" == sys_write ]]; then
	{
		snippet_write;
		return;
	}
	fi;
	if [[ "$second_elem" == sys_exit ]]; then
	{
		do_exit;
		return;
	}
	fi;
	local target="$second_elem";
	local target_data=$(get_b64_symbol_value "${target}" "${SNIPPETS}");
	local target_type=$(echo "${target_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	if [ "$target_type" == "$SYMBOL_TYPE_ARRAY" ] && is_function_call $target "${SNIPPETS}"; then
	{
		local target_data="$( echo "$SNIPPETS" | grep "SYMBOL_TABLE,${SYMBOL_TYPE_ARRAY},${target}," )";
		local symbol_source_code=$(echo $target_data | cut -d, -f${SNIPPET_COLUMN_SOURCE_CODE});
		local target_fn=$(echo $symbol_source_code | base64 -d| cut -d: -f2- | cut -f4);
		local target_fn_data="$(echo "$SNIPPETS" | grep "PROCEDURE_TABLE,[^,]*,${target_fn},")";
		local target_addr=$(echo $target_fn_data | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET});
		local jmp_size=$(get_jmp_size "${SNIPPETS}" "${target_fn}" );
		target_addr=$(( target_addr + jmp_size ));
		instr_bytes="$(call_procedure "${target_addr}" "${instr_offset}" "${SYMBOL_TYPE_ARRAY}" | xd2b64)";
		local instr_len="$(echo "${instr_bytes}" | base64 -d |  wc -c)";
		struct_parsed_snippet \
			"SNIPPET_CALL" \
			"${SYMBOL_TYPE_PROCEDURE}" \
			"call" \
			"${instr_offset}" \
			"${instr_bytes}" \
			"${instr_len}" \
			"${static_data_offset}" \
			"" \
			"0" \
			"${CODE_LINE_B64}" \
			"1";
		return;
	}
	elif [ "$target_type" == "$SYMBOL_TYPE_PROCEDURE" ]; then
		target_offset="$( echo "$SNIPPETS" | grep "PROCEDURE_TABLE,[^,]*,${target}," | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET} )";
	elif [[ "$third_elem" =~ [?](=|<=|>|>=)$ ]]; then
		conditional_call;
		return;
	else
		do_exec;
		return;
	fi;
	local jmp_size=$(get_jmp_size "${SNIPPETS}" "${target}" );
	local call_bytes="$(call_procedure "$((target_offset + jmp_size))" "${instr_offset}" | xd2b64)";
	local call_len="$(echo "${call_bytes}" | b64cnt)";
	struct_parsed_snippet \
		"SNIPPET_CALL" \
		"${SYMBOL_TYPE_PROCEDURE}" \
		"call" \
		"${instr_offset}" \
		"${call_bytes}" \
		"${call_len}" \
		"${static_data_offset}" \
		"" \
		"0" \
		"${CODE_LINE_B64}" \
		"1";
	return;
}
do_exec(){
	# TODO for now positional args are good enough, but the correct is to have args and env as an array each;
	local args=( );
	local static_map=( );
	for (( i=0; i<$(( ${#code_line_elements[@]} - deep )); i++ ));
	do {
		local arg_id="${code_line_elements[$(( i + deep ))]}";
		local arg_snippet="$( echo "$SNIPPETS" | grep "SYMBOL_TABLE,[^,]*,${arg_id}," )";
		local arg_addr="$(echo "$arg_snippet" | cut -d, -f${SNIPPET_COLUMN_DATA_OFFSET} )";
		local arg_is_static=0;
		if is_static_data_snippet "${arg_snippet}"; then
			# if arg is static, the call is different because we pass the address to the string itself
			# instead of the address of the pointer to the string we have when it is dynamic
			# I've choose doing this way because we do less instructions as we don't need to allocate additional
			# bytes to create a pointer to the static string, we can just set the address to the register.
			arg_is_static=1;
		fi;
		args[$i]="$arg_addr";
		static_map[$i]=$arg_is_static;
	};
	done;
	local data_bytes="";
	local env=(); # memory address to the env
	local args_addr="$(( dyn_data_offset ))"; # the array address
	local args_size=$(( 8 * ${#args[@]} + 8 )) # 8 to cmd, 8 for each argument and 8 to null to close the array
	local env_addr=$(( args_addr + args_size ));
	local env_size=8;
	env_size=0;
	env_addr=0; # no support for env, set NULL
	local data_len=$(( args_size + env_size )); # 8 to each array (args and env)
	local argsparam="${args[@]}";
	local staticmapparam="${static_map[@]}";
	local instr_bytes="$(system_call_exec "${args_addr}" "${argsparam}" "${staticmapparam}" "${env_addr}")";
	local instr_len="$(echo "${instr_bytes}" | b64cnt)";
	struct_parsed_snippet \
		"INSTRUCTION" \
		"${SYMBOL_TYPE_SYSCALL}" \
		"sys_execve" \
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
do_goto(){
	target="$third_elem"
	target_offset="$( echo "$SNIPPETS" | grep "PROCEDURE_TABLE,[^,]*,${target}," | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET} )";
	jmp_bytes="$(jump "$((target_offset + 2))" "${instr_offset}" | xd2b64)";
	jmp_len="$(echo "${jmp_bytes}" | b64cnt)";
	struct_parsed_snippet \
		"SNIPPET_CALL" \
		"${SYMBOL_TYPE_PROCEDURE}" \
		"jmp" \
		"${instr_offset}" \
		"${jmp_bytes}" \
		"${jmp_len}" \
		"${static_data_offset}" \
		"" \
		"0" \
		"${CODE_LINE_B64}" \
		"1";
	return;
}
do_ilog10(){
	base="10"
	local target="${code_line_elements[$(( 4 + deep-1 ))]}";
	target_offset="$( echo "$SNIPPETS" | grep "PROCEDURE_TABLE,[^,]*,${target}," | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET} )";
	jmp_bytes="$(call_procedure "$((target_offset + 2))" "${instr_offset}" | xd2b64)";
	jmp_len="$(echo "${jmp_bytes}" | b64cnt)";
	struct_parsed_snippet \
		"SNIPPET_CALL" \
		"${SYMBOL_TYPE_PROCEDURE}" \
		"jmp" \
		"${instr_offset}" \
		"${jmp_bytes}" \
		"${jmp_len}" \
		"${static_data_offset}" \
		"" \
		"0" \
		"${CODE_LINE_B64}" \
		"1";
	return;
}
do_ret(){
	local symbol_id="$third_elem";
	local instr_bytes="";
	local code_line="$CODE_LINE_B64";
	if [ "${symbol_id}" != "" ]; then
		local symbol_data=$(get_b64_symbol_value "${symbol_id}" "${SNIPPETS}");
		local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
		local symbol_value=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d | tr -d '\00' );
		instr_bytes="$(ret "${symbol_value}" "${symbol_type}" | xd2b64)";
	else
		instr_bytes="$(ret | xd2b64)";
	fi;
	local instr_len=$(echo "${instr_bytes}" | b64cnt);
	struct_parsed_snippet \
		"INSTRUCTION" \
		"${SYMBOL_TYPE_SYSCALL}" \
		"ret" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${static_data_offset}" \
		"" \
		"0" \
		"${code_line}" \
		"1";
}
do_exit(){
	local symbol_id="$third_elem";
	local symbol_data=$(get_b64_symbol_value "${symbol_id}" "${SNIPPETS}");
	local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	local symbol_value=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d | tr -d '\00' );
	local instr_bytes="$(system_call_exit "${symbol_value}" "${symbol_type}" )";
	local instr_len=$(echo "${instr_bytes}" | b64cnt);
	struct_parsed_snippet \
		"INSTRUCTION" \
		"${SYMBOL_TYPE_SYSCALL}" \
		"sys_exit" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${static_data_offset}" \
		"" \
		"0" \
		"${CODE_LINE_B64}" \
		"1";
}
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
do_comment(){
	struct_parsed_snippet \
		"COMMENT" \
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
empty_line(){
	struct_parsed_snippet \
		"EMPTY" \
		"${SYMBOL_TYPE_HARD_CODED}" \
		"" \
		"${instr_offset}" \
		"" \
		"0" \
		"${statc_data_offset}" \
		"" \
		"0" \
		"${CODE_LINE_B64}" \
		"1";
}
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
	local second_elem="${code_line_elements[$(( 1 + deep-1 ))]}";
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
		do_define "${dyn_data_offset}";
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

do_return(){
	local SNIPPETS="$2";
	local symbol_id="$1";
	local symbol_data=$(get_b64_symbol_value "${symbol_id}" "${SNIPPETS}");
	local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	local symbol_value=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d | tr -d '\00' );
	debug "do_return symbol_id=$symbol_id; symbol_type=$symbol_type"
	local snippet_type=$SYMBOL_TYPE_PROCEDURE;
	local instr_offset="$(get_instr_offset "$( echo "$SNIPPETS" | tail -1)")";
	local instr_bytes=$(ret "${symbol_value}" "${symbol_type}" | xd2b64);
	local instr_size="$(echo $instr_bytes | b64cnt)";
	struct_parsed_snippet \
		"PROCEDURE_TABLE" \
		"${snippet_type}" \
		"${snippet_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_size}" \
		"${static_data_offset}" \
		"${data_bytes}" \
		"${data_bytes_sum}" \
		"${outer_code_b64}" \
		"${source_lines_count}" \
		"${usage_count}" \
		"${return}" \
		"${dependencies}";
}

# should return multiple struct_parsed_snippet output (one per line)
parse_snippets()
{
	local ROUND="$1";
	local PH_VADDR_V="$2";
	local INSTR_TOTAL_SIZE="$3";
	local static_data_size="$4"
	local SNIPPETS="$5"; # cummulative to allow cross reference between snippets
	local deep="${6-0}";
	local CODE_INPUT=$(cat);
	let deep++;
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
	echo "${CODE_INPUT}" | while read CODE_LINE;
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

# detect_instruction_size_from_code should return the bytes used by the instructions code bloc.
# That includes NONE OF the data section (string table, the elf and program headers
detect_instruction_size_from_code()
{
	[ -e "$1" ] &&
	cat $1 | grep -E "^(INSTRUCTION|SNIPPET_CALL|SYMBOL_TABLE|PROCEDURE_TABLE)," |
	cut -d, -f${SNIPPET_COLUMN_INSTR_LEN} |
	awk '{s+=$1}END{print s}'
}

detect_static_data_size_from_code()
{
	local static_data_size=$(
		[ -e "$1" ] && cat $1 | while read l;
		do
			if [ "${l}" == "" ]; then
				continue;
			fi;
			local snip_data_len=$(echo "${l}" | cut -d, -f$SNIPPET_COLUMN_DATA_LEN);
			if [ "${snip_data_len:=0}" -gt 0 ]; then
				if is_static_data_snippet "${l}"; then
					echo ${snip_data_len:=0};
					echo 1; # add 1 to the \x00 null byte between the static data
					c=$((c+1));
				fi;
			fi;
		done | awk '{s+=$1}END{print s}';
	)
	echo ${static_data_size:=0}
}

create_internal_ilog10_snippet()
{
	local symbol_name="$1";
	local SNIPPETS="$2";
	local PH_VADDR_V="$3";
	local INSTR_TOTAL_SIZE="$4";
	local snippet_type=$SYMBOL_TYPE_PROCEDURE;
	local snippet_name="$symbol_name";
	local instr_offset="$(get_instr_offset "$( echo "$SNIPPETS" | tail -1)")";
	local static_data_offset="$(( $(get_zero_data_offset "$PH_VADDR_V" "$INSTR_TOTAL_SIZE") + $(get_static_data_size "${SNIPPETS}") ))";
	local ilog10_map_addr="$((static_data_offset))";
	local ilog10_return_addr="${static_data_offset}";
	local instr_bytes="$(ilog10 "" "" "${ilog10_map_addr}" "${ilog10_return_addr}" | xdr | base64 -w0)";
	local instr_size="$(echo $instr_bytes | b64cnt)";
	local jump_bytes="$(jump_relative $instr_size|xd2b64)";
	instr_bytes=$(echo "$jump_bytes$instr_bytes");
	instr_size="$(echo $instr_bytes | b64cnt)";
	local data_bytes="$({
		# data for ilog10; each byte in this array define,
		# given the bsr for a number, which index on the next ilo10 data table should we use?
		# samples:
		# 1 : bsr=0; idx: 0; < 10
		# 2 ; bsr=1; idx: 0; < 10
		# 4 ; bsr=2; idx: 0; < 10
		# 8 ; bsr=3; idx: 0; < 10
		# 16; bsr=4; idx: 1; < 100
		# 32; bsr=5; idx: 1; < 100
		# 64; bsr=6; idx: 1; < 100
		# 128; bsr=7; idx: 2; < 1000
		# but we always subtract 1, because bsr returns the bit index instead of how many bits;
		for (( i=1; i<32; i++));
		do
			v=$(( 2 ** i ));
			l=$(echo "scale=8;l($v)/l(10)" | bc -l);
			l=${l/.*/};
			printf %02x ${l:=0};
		# data for ilog10;
		done | xxd --ps -r | base64 -w0;
		for (( i=0; i<12; i++ ));
		do
			v=$(( 10 ** i ));
			echo -en "$(printEndianValue ${v} $SIZE_64BITS_8BYTES)" | base64 -w0;
		done;
	})";
	local data_bytes_sum=$(echo $data_bytes | b64cnt);
	local bloc_outer_code_b64="$(echo -n "builtin..ilog10" | base64 -w0)";
	local bloc_source_lines_count=0;
	local bloc_usage_count=1;
	local bloc_return="";
	local bloc_dependencies="";
	struct_parsed_snippet \
		"PROCEDURE_TABLE" \
		"${snippet_type}" \
		"${snippet_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_size}" \
		"${static_data_offset}" \
		"${data_bytes}" \
		"${data_bytes_sum}" \
		"${bloc_outer_code_b64}" \
		"${bloc_source_lines_count}" \
		"${bloc_usage_count}" \
		"${bloc_return}" \
		"${bloc_dependencies}";
}

get_internal_addr()
{
	local symbol_name="$1";
	local snippets="$2";
	local addr=$(echo "$snippets" | grep ",$symbol_name," | cut -d, -f$SNIPPET_COLUMN_INSTR_OFFSET);
	if [ "$addr" == "" ]; then
		error "internal function $symbol_name not defined"
	fi;
	echo $((addr));
}
get_power10_addr()
{
	local snippets="$1";
	local symbol_name=".ilog10";
	local addr=$(echo "$snippets" | grep ",$symbol_name," | cut -d, -f$SNIPPET_COLUMN_DATA_OFFSET);
	if [ "$addr" == "" ]; then
		error "internal function $symbol_name not defined"
	fi;
	echo $(( addr + ilog10_guess_map_size ));
}
create_internal_s2i_snippet()
{
	local symbol_name="$1";
	local SNIPPETS="$2";
	local PH_VADDR_V="$3";
	local INSTR_TOTAL_SIZE="$4";
	local snippet_type=$SYMBOL_TYPE_PROCEDURE;
	local snippet_name="$symbol_name";
	local instr_offset="$(get_instr_offset "$( echo "$SNIPPETS" | tail -1)")";
	local zero_data_pos=$(get_zero_data_offset "$PH_VADDR_V" "$INSTR_TOTAL_SIZE");
	local dyn_data_size=$(get_dynamic_data_size "${SNIPPETS}")
	local dynamic_data_offset="$(( zero_data_pos + dyn_data_size ))"
	local instr_bytes="$(s2i | xdr | base64 -w0)";
	local instr_size="$(echo "$instr_bytes" | b64cnt)";
	local jump_bytes="$(jump_relative $instr_size|xd2b64)";
	instr_bytes=$(echo "$jump_bytes$instr_bytes");
	instr_size="$(echo $instr_bytes | b64cnt)";
	local data_bytes="";
	local data_bytes_size="32";
	local bloc_outer_code_b64="$(echo -n "builtin.$symbol_name" | base64 -w0)";
	local bloc_source_lines_count=0;
	local bloc_usage_count=1;
	local bloc_return="";
	local bloc_dependencies="";
	struct_parsed_snippet \
		"PROCEDURE_TABLE" \
		"${snippet_type}" \
		"${snippet_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_size}" \
		"${dynamic_data_offset}" \
		"${data_bytes}" \
		"${data_bytes_size}" \
		"${bloc_outer_code_b64}" \
		"${bloc_source_lines_count}" \
		"${bloc_usage_count}" \
		"${bloc_return}" \
		"${bloc_dependencies}";
}
create_internal_i2s_snippet()
{
	local symbol_name="$1";
	local SNIPPETS="$2";
	local PH_VADDR_V="$3";
	local INSTR_TOTAL_SIZE="$4";
	local snippet_type=$SYMBOL_TYPE_PROCEDURE;
	local snippet_name="$symbol_name";
	local instr_offset="$(get_instr_offset "$( echo "$SNIPPETS" | tail -1)")";
	local zero_data_pos=$(get_zero_data_offset "$PH_VADDR_V" "$INSTR_TOTAL_SIZE");
	local dyn_data_size=$(get_dynamic_data_size "${SNIPPETS}")
	local dynamic_data_offset="$(( zero_data_pos + dyn_data_size ))"
	local ilog10_addr=$(get_internal_addr .ilog10 "${SNIPPETS}");
	local power10_addr=$(get_power10_addr "${SNIPPETS}");
	local instr_bytes="$(i2s "" "" "${dynamic_data_offset}" "${ilog10_addr}" "${power10_addr}" "${instr_offset}" | xd2b64)";
	local instr_size="$(echo "$instr_bytes" | b64cnt)";
	local jump_bytes="$(jump_relative $instr_size | xd2b64)";
	instr_bytes=$(echo "$jump_bytes$instr_bytes");
	instr_size="$(echo $instr_bytes | b64cnt)";
	local data_bytes="";
	local data_bytes_size="32";
	local bloc_outer_code_b64="$(echo -n "builtin.$symbol_name" | base64 -w0)";
	local bloc_source_lines_count=0;
	local bloc_usage_count=1;
	local bloc_return="";
	local bloc_dependencies="";
	struct_parsed_snippet \
		"PROCEDURE_TABLE" \
		"${snippet_type}" \
		"${snippet_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_size}" \
		"${dynamic_data_offset}" \
		"${data_bytes}" \
		"${data_bytes_size}" \
		"${bloc_outer_code_b64}" \
		"${bloc_source_lines_count}" \
		"${bloc_usage_count}" \
		"${bloc_return}" \
		"${bloc_dependencies}";
}

create_internal_snippet()
{
	local symbol_name="$1";
	local SNIPPETS="$2";
	local PH_VADDR_V="$3";
	local INSTR_TOTAL_SIZE="$4";
	if ! is_internal_function $symbol_name; then
		error "not an internal function: [$symbol_name]";
		return 1;
	fi;
	if [ "$symbol_name" == ".ilog10" ]; then
		create_internal_ilog10_snippet "$symbol_name" "$SNIPPETS" "$PH_VADDR_V" "$INSTR_TOTAL_SIZE";
		return;
	fi;
	if [ "$symbol_name" == ".s2i" ]; then
		create_internal_s2i_snippet "$symbol_name" "$SNIPPETS" "$PH_VADDR_V" "$INSTR_TOTAL_SIZE";
		return;
	fi;
	if [ "$symbol_name" == ".i2s" ]; then
		local ilog10_snip="$(echo "$SNIPPETS" | grep -q ",.ilog10," )";
		if [ "$ilog10_snip" == "" ] ; then
			ilog10_snip=$(create_internal_ilog10_snippet ".ilog10" "$SNIPPETS" "$PH_VADDR_V" "$INSTR_TOTAL_SIZE");
			echo $ilog10_snip;
		fi;
		local ilog10_instr_size=$(echo $ilog10_snip | cut -d, -f$SNIPPET_COLUMN_INSTR_LEN);
		INSTR_TOTAL_SIZE=$(( INSTR_TOTAL_SIZE + ilog10_instr_size ))
		create_internal_i2s_snippet "$symbol_name" "$(echo -e "$SNIPPETS\n$ilog10_snip")" "$PH_VADDR_V" "$INSTR_TOTAL_SIZE";
		return;
	fi;
}

detect_internal_dependencies(){
	local snippets="$1";
	local tmpfile="${2}.tmp"
	echo -n "" > $tmpfile;
	unsorted_deps="$(
		echo "$snippets" |
			cut -d, -f$SNIPPET_COLUMN_DEPENDENCIES |
			tr "," "\n" | uniq | sed '/^$/d' |
		while read dep;
		do
			if is_internal_function $dep; then
				echo $dep;
			fi;
		done;
	)";
	echo "$unsorted_deps" |
	while read dep;
	do
		if grep -q $dep $tmpfile; then
			continue;
		fi;
		echo "$dep" >> $tmpfile;
	done;
	cat $tmpfile;
}

parseRound(){
	debug "===== parseRound $1 =====";
	local round="$1";
	local snippets_file="$2";
	internal_snippet_filename="${snippets_file}.internal";
	local internal_snippets=""
	local INSTR_TOTAL_SIZE="";
	local INPUT_SOURCE_CODE=$(cat);
	local snippets=$(
		echo "${INPUT_SOURCE_CODE}" |
			parse_snippets \
				"${ROUND_FINAL}" \
				"${PH_VADDR_V}" \
				"${INSTR_TOTAL_SIZE}" \
				"${static_data_size}" \
				"${internal_snippets}"
	);

	echo -e "${internal_snippets}\n${snippets}" > $snippets_file;
	INSTR_TOTAL_SIZE=$(detect_instruction_size_from_code "${snippets_file}");
	local static_data_size=$(detect_static_data_size_from_code "${snippets_file}");
	local internal_dependencies=$(detect_internal_dependencies "${snippets}" "${internal_snippet_filename}");
	echo -n "" > "${internal_snippet_filename}";
	echo "$internal_dependencies" |
		while read dep;
		do
			[ "$dep" == "" ] && continue;
			out="$(create_internal_snippet \
				"$dep" \
				"$(cat ${internal_snippet_filename})" \
				"${PH_VADDR_V}" \
				"${INSTR_TOTAL_SIZE}"
			)";
			echo "$out" >> "${internal_snippet_filename}";
		done;
	local internal_snippets=$(cat "${internal_snippet_filename}"|:);
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
	echo -e "${internal_snippets}\n${snippets}" > $snippets_file;
	echo -e "${internal_snippets}\n${snippets}" > $snippets_file.round-$round;
}
# Round exists because parse_snippets can only trust addresses in final round.
# We can use it to get control of address changes like to detect the args memory spot
ROUND_FIRST=1
ROUND_FINAL=2
write_elf()
{
	local ELF_FILE_OUTPUT="$1";
	# Virtual Memory Offset
	local PH_VADDR_V=$(./ph_vaddr_v)
	if [ "$PH_VADDR_V" == "" ]; then
		# mmap_min_addr kernel config says where is the minimum valid segment to load the elf
		PH_VADDR_V=$(cat /proc/sys/vm/mmap_min_addr)
	fi;
	if [ "$PH_VADDR_V" == "" ]; then
		PH_VADDR_V=$(( 1 << 16 )); # 64KiB
	fi;
	local SH_COUNT=$(get_section_headers_count "");
	local INPUT_SOURCE_CODE="$(cat)";
	local INIT_CODE="
	mmap 1 page 4096 bytes (private);
	mmap 1 page 4096 bytes (shared); ?
	reserve space for:
		array of mapped pages with struct
		* page addr
		* free page left;
		* shared page left;
	in private page should put:
		* argc is $rsp
		 (gdb) print *((int*)$rsp)
		* argv is $rsp + 8
		 (gdb) print *((char**)($rsp + 8))
	";
	local static_data_size=0;
	local snippets_file="${ELF_FILE_OUTPUT}.snippets";
	# this can be simplified once we have maps; so we can create a template and replace the memory position variables;
	# for future thinking: what about and encoded text, base64, where i can replace the variables with b64 values?
	echo "$INPUT_SOURCE_CODE" | parseRound 1 "${snippets_file}"; # Detect instruction size; static and dynamic data size;
	echo "$INPUT_SOURCE_CODE" | parseRound 2 "${snippets_file}"; # Detect internal dependencies size; upate instructions, static and dynamic data size;
	echo "$INPUT_SOURCE_CODE" | parseRound 3 "${snippets_file}"; # final parse with correct addresses displacements;

	local elf_size=0;
	for ((i=0; i<2; i++));
	do {
		# need to do twice because we don't have the final file size on first time;
		# could be better just to replace the filesz on program segment header (LOAD type);
		local ELF_BODY="$(
			print_elf_body \
				"${PH_VADDR_V}" \
				"${SH_COUNT}" \
				"$snippets_file" \
				"$elf_size";
		)";
		local ELF_FILE_HEADER="$(
			print_elf_file_header \
				"${PH_VADDR_V}" \
				"${SH_COUNT}" | xd2b64;
		)";
		echo -ne "${ELF_FILE_HEADER}${ELF_BODY}" |
			base64 -d > $ELF_FILE_OUTPUT;
		elf_size=$(wc -c<$ELF_FILE_OUTPUT)
	};
	done;
}
