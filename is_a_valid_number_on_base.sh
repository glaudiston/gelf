
is_a_valid_number_on_base(){
	SNIPPETS=$2
	base=$(get_b64_symbol_value "base" "${SNIPPETS}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d);
	echo -n "$(( ${base:10}#${raw_data_bytes} ))" 2>&1 >/dev/null ||
		return 1;
	echo "${base:10}"
	return;
}
