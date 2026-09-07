#!/bin/bash

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
