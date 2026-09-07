#!/bin/bash

get_snippets_until_line()
{
	local line="$1";
	local SNIPPETS="$2";
	echo "$SNIPPETS" | while read l;
	do
		item=$(echo "$l" | cut -d, -f$SNIPPET_COLUMN_SOURCE_CODE);
		if [ "$item" == "$line" ]; then
			break;
		fi;
		echo "$l";
	done;
}
