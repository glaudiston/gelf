#!/bin/bash
import_bash ./encoding.sh
is_dynamic_snippet()
{
	local l="$1";
	local snip_data_wc=$(
	    echo "${l}" |
		cut -d, -f$SNIPPET_COLUMN_DATA_BYTES |
	    b64cnt
	);
	local snip_data_len=$(
	    echo "${l}" |
		cut -d, -f$SNIPPET_COLUMN_DATA_LEN
	);
	if [ "$snip_data_wc" -lt "$snip_data_len" ]; then
		return 0;
	fi
	return 1;
}
