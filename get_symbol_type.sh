get_symbol_type()
{
	local symbol_name="$1";
	local SNIPPETS="$2";
	local symbol_data=$(get_b64_symbol_value "${symbol_name}" "${SNIPPETS}" )
	echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE};
}
