
is_static_data_snippet()
{
	local snip="$1";
	local snip_name=$(echo "$snip" | cut -d, -f"$SNIPPET_COLUMN_SUBNAME");
	local snip_type=$(echo "$snip" | cut -d, -f"$SNIPPET_COLUMN_TYPE");
	if [ "$snip_type" == $SYMBOL_TYPE_STATIC ]; then
		return 0;
	fi;
	if [ "$snip_type" == $SYMBOL_TYPE_HARD_CODED ]; then
		return 1;
	fi;
	local snip_data_bytes=$(echo "$snip" | cut -d, -f "$SNIPPET_COLUMN_DATA_BYTES");
	if is_hard_coded_value "${snip_data_bytes}"; then
		return 1;
	fi;
	local snip_data_size=$(echo "$snip" | cut -d, -f"$SNIPPET_COLUMN_DATA_LEN");
	if [ "$snip_data_size" != "$(echo "$snip_data_bytes" | b64cnt)" ]; then
		return 1;
	fi;
	return 0;
}

count_static_data()
{
	local snippets="$1";
	local static_data_count=$(
		echo "$snippets" | while read l;
		do
			if [ "${l}" == "" ]; then
				continue;
			fi;
			local snip_data_len=$(echo "${l}" | cut -d, -f$SNIPPET_COLUMN_DATA_LEN);
			if [ "${snip_data_len:=0}" -gt 0 ]; then
				if is_static_data_snippet "${l}"; then
					echo 1;
				fi;
			fi;
		done | awk '{s+=$1}END{print s}';
	);
	echo ${static_data_count:=0}
}
