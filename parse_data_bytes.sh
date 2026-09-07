
parse_data_bytes()
{
	local raw_data_bytes="$1";
	local SNIPPETS="$2";
	if [ "${raw_data_bytes:0:1}" == "'" ]; then
		echo -n "${raw_data_bytes}" | base64 -w0;
		return;
	fi;
	if [ "${raw_data_bytes:0:1}" == '"' ]; then
		#TODO: replace variables
		echo -n "${raw_data_bytes}" | base64 -w0;
		return;
	fi;
	local based_value=$(is_a_valid_number_on_base "${raw_data_bytes}" "${SNIPPETS}")
	if [ "$?" == 0 ] ; then
		#convert to base 10;
		#TODO detect the current base
		base=16
		echo -n "${based_value}" | base64 -d;
		return
	fi;
	# TODO detect the current base set and validate if the given data is a valid number on that base
	if [ "${raw_data_bytes:0:2}" ]; then
		echo -n "${raw_data_bytes}" | base64 -w0;
		return;
	fi;
	if ! { echo "${raw_data_bytes}" | base64 -d 2>&1 >/dev/null; }; then
		echo "${raw_data_bytes}" | base64 -w0
		return;
	fi
	echo -n "${raw_data_bytes}"
}
