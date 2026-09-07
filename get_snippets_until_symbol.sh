#!/bin/bash
get_snippets_until_symbol()
{
	local symbol_name="$1";
	local SNIPPETS="$2";
	echo "$SNIPPETS" | while read l;
	do
		item=$(echo "$l" | cut -d, -f$SNIPPET_COLUMN_SUBNAME);
		if [ "$item" == "$symbol_name" ]; then
			break;
		fi;
		echo "$l";
	done;
}
