get_jmp_size(){
	local SNIPPETS="$1";
	local target="$2";
	local jmp_size=2; # all procedures have a jmp instruction at begining. it can be 2 or 5 bytes. 2 if the procedure body is smaller than 128 bytes;
	local target_instr_size="$( echo "$SNIPPETS" | grep "PROCEDURE_TABLE,[^,]*,${target}," | cut -d, -f${SNIPPET_COLUMN_INSTR_LEN} )";
	if [ "${target_instr_size:=0}" -gt 127 ]; then
		jmp_size=5;
	fi;
	echo $jmp_size;
}

