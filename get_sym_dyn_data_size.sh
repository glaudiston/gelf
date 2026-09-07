#!/bin/bash
import_bash get_dynamic_data_size.sh
import_bash get_snippets_until_symbol.sh
get_sym_dyn_data_size()
{
	local symbol_name="$1";
	local SNIPPETS="$(get_snippets_until_symbol "$symbol_name" "$1")";
	get_dynamic_data_size "$SNIPPETS"
}
