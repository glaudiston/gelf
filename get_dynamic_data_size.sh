#!/bin/bash
import_bash ./is_dynamic_snippet.sh
import_bash ./is_internal_snippet.sh
get_dynamic_data_size()
{
	local SNIPPETS="$1";
	local dyn_data_size=$(
		echo "$SNIPPETS" | while read l;
		do
			if [ "${l}" == "" ]; then
				continue;
			fi;
			local snip_data_len=$(echo "${l}" | cut -d, -f$SNIPPET_COLUMN_DATA_LEN);
			if [ "${snip_data_len:=0}" -gt 0 ]; then
				if is_dynamic_snippet "${l}" || is_internal_snippet "${l}"; then
					echo $snip_data_len;
				fi;
			fi;
		done | awk '{s+=$1}END{print s}';
	)
	echo ${dyn_data_size:=0}
}

