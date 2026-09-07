#!/usr/bin/env bash

#TODO refactor to use strategy pattern
create_internal_snippet()
{
	local symbol_name="$1";
	local SNIPPETS="$2";
	local PH_VADDR_V="$3";
	local INSTR_TOTAL_SIZE="$4";
	info "creating internal snippet for $1 $2 $3 $4";
	if ! is_internal_function "$symbol_name"; then
		error "not an internal function: [$symbol_name]";
		return 1;
	fi;
	if [ "$symbol_name" == ".ilog10" ]; then
		create_internal_ilog10_snippet "$symbol_name" "$SNIPPETS" "$PH_VADDR_V" "$INSTR_TOTAL_SIZE";
		return;
	fi;
	if [ "$symbol_name" == ".s2i" ]; then
		create_internal_s2i_snippet "$symbol_name" "$SNIPPETS" "$PH_VADDR_V" "$INSTR_TOTAL_SIZE";
		return;
	fi;
	if [ "$symbol_name" == ".i2s" ]; then
		local ilog10_snip;
		ilog10_snip="$(echo "$SNIPPETS" | grep -q ",.ilog10," )";
		if [ "$ilog10_snip" == "" ] ; then
			ilog10_snip=$(create_internal_ilog10_snippet ".ilog10" "$SNIPPETS" "$PH_VADDR_V" "$INSTR_TOTAL_SIZE");
			echo "$ilog10_snip";
		fi;
		local ilog10_instr_size;
		ilog10_instr_size=$(echo "$ilog10_snip" | cut -d, -f"$SNIPPET_COLUMN_INSTR_LEN");
		INSTR_TOTAL_SIZE=$(( INSTR_TOTAL_SIZE + ilog10_instr_size ))
		create_internal_i2s_snippet "$symbol_name" "$(echo -e "$SNIPPETS\n$ilog10_snip")" "$PH_VADDR_V" "$INSTR_TOTAL_SIZE";
		return;
	fi;
}

