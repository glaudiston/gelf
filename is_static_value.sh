
is_static_value()
{
	local symbol_name=$(echo $1 | base64 -d| tr -d '\0');
	local symbol_data="$(echo "$SNIPPETS" | grep -E "^[^,]*,[^,]*,${symbol_name}," |grep -vE "^COMMENT"| tail -1)";
	if [ "$symbol_data" == "" ]; then
		return 0;
	fi;
	return 1;
}
