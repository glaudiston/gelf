#!/bin/bash

is_internal_snippet()
{
	local l="$l";
	local name=$(echo "$l" | cut -d, -f$SNIPPET_COLUMN_SUBNAME);
	if [[ "$name" =~ ^(.ilog10|.s2i|.i2s)$ ]]; then
		return 0;
	fi;
	return 1;
}
