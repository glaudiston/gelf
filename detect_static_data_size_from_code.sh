detect_static_data_size_from_code()
{
	local static_data_size=$(
		local c=0;
		[ -e "$1" ] && cat $1 | while read l;
		do
			if [ "${l}" == "" ]; then
				continue;
			fi;
			local snip_data_len=$(echo "${l}" | cut -d, -f$SNIPPET_COLUMN_DATA_LEN);
			if [ "${snip_data_len:=0}" -gt 0 ]; then
				if is_static_data_snippet "${l}"; then
					echo ${snip_data_len:=0};
					echo 1; # add 1 to the \x00 null byte between the static data
					c=$((c+1));
				fi;
			fi;
		done | awk '{s+=$1}END{print s}';
	)
	echo ${static_data_size:=0}
}

