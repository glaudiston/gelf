
get_zero_data_offset()
{
	local PH_VADDR_V="$1";
	local INSTR_TOTAL_SIZE="$2";
	echo $(( PH_VADDR_V + EH_SIZE + PH_SIZE + INSTR_TOTAL_SIZE ));
}
