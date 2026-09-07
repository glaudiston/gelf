
set_symbol_value()
{
	local symbol_value="$1";
	local SNIPPETS="$2";
	local data_bytes="${symbol_value}";
	local input="${symbol_value}";
	if [ "${symbol_name}" != "input" ]; then
		input=$(get_b64_symbol_value "input" "$SNIPPETS" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d | tr -d '\0');
		if [ "$input" == "" ]; then
			error "failed to recover the input: symbol_name=$symbol_name; snip=\n$SNIPPETS";
		fi;
	fi;
	if [ "${symbol_name}" != "input" -a "${input}" == "base64" ]; then
		data_bytes="$(echo -ne "${symbol_value}")"; # with NULL Suffix
	else
		data_bytes="$(echo -ne "${symbol_value}" | base64 -w0)";
	fi;
	if [ "$symbol_name" != input ] && echo "${input[@]}" | grep -q "evaluate"; then
		#TODO detect eval type. if all operations are static, and not call or jump is used(between the definition and evaluation).
		eval_type="static";
		if [ "${eval_type}" == "static" ]; then
			# then we can just evaluate the expression.
			echo -n "$(( $( echo $( echo "${data_bytes}" | base64 -d ) ) ))"
			return
		fi
	# else, we need to set it as a runtime expression
	# any jump or call after this can change this behavior.
	# then all code that uses jump or call should validate and update this.
		echo -n "$(( data_bytes ))"
		return
	fi;

	echo -n "${data_bytes}"
}
