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

