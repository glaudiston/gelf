get_instr_offset()
{
	local previous_snippet="$1";
	local previous_instr_offset=$(echo "${previous_snippet}" | cut -d, -f$SNIPPET_COLUMN_INSTR_OFFSET);
	previous_instr_offset="${previous_instr_offset:=$((PH_VADDR_V + EH_SIZE + PH_SIZE))}"
	local previous_instr_sum=$(echo "${previous_snippet}" | cut -d, -f$SNIPPET_COLUMN_INSTR_LEN | tail -1);
	local instr_offset="$(( ${previous_instr_offset} + previous_instr_sum ))";
	echo -n "${instr_offset}";
}

