#!/bin/bash

is_function(){
	local YES=0;
	local NO=1;
	local symbol_name="$1";
	local snippets="${2:-}";
	if \
		is_system_function $symbol_name ||
		is_internal_function $symbol_name ||
		is_user_function "$symbol_name" "${SNIPPETS}";
	then
		return $YES
	fi;
	return $NO
}

