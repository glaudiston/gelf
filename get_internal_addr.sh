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

