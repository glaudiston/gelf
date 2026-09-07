
# parse_code_line_elements returns a base array with all given elements
parse_code_line_elements()
{
	local code_line="$1";
	IFS=$'\t'
	read -ra elements <<< "${code_line}"
	encoded_array="$( encode_array_to_b64_csv "${elements[@]}" )"
	echo -n "${encoded_array}"
}
