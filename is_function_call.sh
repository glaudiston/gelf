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

