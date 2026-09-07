do_define(){
	local dyn_data_offset="$1";
	local deep="$2";
	if [[ "${CODE_LINE_XXD}" =~ .*097b$ ]]; then # check if ends with ":\t{" ... so it's a code block function
	{
		define_code_block
		return;
	}
	fi;
	define_variable "${dyn_data_offset}" "${deep}";
}

