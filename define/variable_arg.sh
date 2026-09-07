. $(dirname $(realpath $BASH_SOURCE))/../ensure_args_ptr.sh
define_variable_arg()
{
	local snippets="$1";
	local a=$(ensure_args_ptr $snippets);
	echo $a;
	snippets=$({
		echo -e "$snippets\n$a";
	});
	if [ "$a" != "" ]; then
		instr_len=$(echo -n $a | cut -d, -f$SNIPPET_COLUMN_INSTR_LEN);
		instr_offset=$(( instr_offset + instr_len ));
		dyn_data_offset="$(( dyn_data_offset + 8 ))";
	fi;
	local args_ptr=$(get_args_ptr "$snippets");
	local arg_number="${sec_arg/@/}";
	# create a new dynamic symbol called ${symbol_name}
	local instr_bytes="$(get_arg $args_ptr $arg_number $dyn_data_offset| xd2b64)";
	local instr_len=$(echo -n "${instr_bytes}" | b64cnt );
	# this address will receive the point to the arg variable set in rsp currently;
	# a better solution would be not have this space in binary but in memory.
	# but it is good enough for now. because we don't really have a dynamic memory now
	local data_bytes="";
	data_len="8"; # pointer size (to the reserved mmap space for this arg)
	struct_parsed_snippet \
		"SYMBOL_TABLE" \
		"${SYMBOL_TYPE_PROCEDURE}" \
		"${symbol_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${dyn_data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"${CODE_LINE_B64}" \
		"1" \
		"" \
		"" \
		"" \
		"ARGUMENT";
	return;
}
