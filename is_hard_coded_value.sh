
is_hard_coded_value()
{
	local NO_ERR=0;
	local ERR=1;
	# TODO: implement a better way this one just work for numbers
	# binary null values will report somethink like:
	# elf_fn.sh: line 502: warning: command substitution: ignored null byte in input
	local v="$(echo "$1" | base64 -d | xxd --ps)";
	local symbol_name="${2:-}";
	if [ "$v" == "" ];then
		return $NO_ERR;
	fi;
	if [ "${symbol_name}" == "input" ]; then
		return $NO_ERR;
	fi;
	if is_valid_number "$(echo -n $v | xxd --ps -r | tr -d "\0")"; then
		return $NO_ERR;
	fi;
	return $ERR;
}
