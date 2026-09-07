
get_symbol_addr()
{
	local symbol_name="$1"
	local SNIPPETS=$2;
	local symbol_addr="$(
	    echo "$SNIPPETS" |
		grep "SYMBOL_TABLE,[^,]*,${symbol_name}," |
		tail -1 |
		cut -d, -f${SNIPPET_COLUMN_DATA_OFFSET}
	)";
	echo "${symbol_addr}";
}
