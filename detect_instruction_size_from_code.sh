#
# detect_instruction_size_from_code should return the bytes used by the instructions code bloc.
# That includes NONE OF the data section (string table, the elf and program headers
detect_instruction_size_from_code()
{
	[ -e "$1" ] &&
	cat $1 | grep -E "^(INSTRUCTION|SNIPPET_CALL|SYMBOL_TABLE|PROCEDURE_TABLE)," |
	cut -d, -f${SNIPPET_COLUMN_INSTR_LEN} |
	awk '{s+=$1}END{print s}'
}

