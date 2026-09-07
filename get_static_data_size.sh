#!/bin/bash

import_bash ./get_sym_dyn_data_size.sh;
# returns the bytes used in elf by the static data section,
# it ignores the implict "hard coded" values like numbers that does not uses data space
get_static_data_size()
{
	local SNIPPETS="$1";
	local static_data_size=$(
		echo "$SNIPPETS" | while read l;
		do
			if [ "${l}" == "" ]; then
				continue;
			fi;
			local snip_data_len=$(echo "${l}" | cut -d, -f$SNIPPET_COLUMN_DATA_LEN);
			if [ "${snip_data_len:=0}" -gt 0 ]; then
				if is_static_data_snippet "${l}"; then
					echo $snip_data_len;
				fi;
			fi;
		done | awk '{s+=$1}END{print s}';
	)
	local static_data_count=$(count_static_data "$SNIPPETS");
	if [ "${static_data_count:=0}" -gt 0 ]; then
	{
		static_data_size=$((static_data_size+static_data_count));
	}
	fi;
	echo ${static_data_size:=0}
}
