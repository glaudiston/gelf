create_internal_ilog10_snippet()
{
	local symbol_name="$1";
	local SNIPPETS="$2";
	local PH_VADDR_V="$3";
	local INSTR_TOTAL_SIZE="$4";
	local snippet_type=$SYMBOL_TYPE_PROCEDURE;
	local snippet_name="$symbol_name";
	local instr_offset="$(get_instr_offset "$( echo "$SNIPPETS" | tail -1)")";
	local static_data_offset="$(( $(get_zero_data_offset "$PH_VADDR_V" "$INSTR_TOTAL_SIZE") + $(get_static_data_size "${SNIPPETS}") ))";
	local ilog10_map_addr="$((static_data_offset))";
	local ilog10_return_addr="${static_data_offset}";
	local instr_bytes="$(ilog10 "" "" "${ilog10_map_addr}" "${ilog10_return_addr}" | xdr | base64 -w0)";
	local instr_size="$(echo $instr_bytes | b64cnt)";
	local jump_bytes="$(jump_relative $instr_size|xd2b64)";
	instr_bytes=$(echo "$jump_bytes$instr_bytes");
	instr_size="$(echo $instr_bytes | b64cnt)";
	local data_bytes="$({
		# data for ilog10; each byte in this array define,
		# given the bsr for a number, which index on the next ilo10 data table should we use?
		# samples:
		# 1 : bsr=0; idx: 0; < 10
		# 2 ; bsr=1; idx: 0; < 10
		# 4 ; bsr=2; idx: 0; < 10
		# 8 ; bsr=3; idx: 0; < 10
		# 16; bsr=4; idx: 1; < 100
		# 32; bsr=5; idx: 1; < 100
		# 64; bsr=6; idx: 1; < 100
		# 128; bsr=7; idx: 2; < 1000
		# but we always subtract 1, because bsr returns the bit index instead of how many bits;
		for (( i=1; i<32; i++));
		do
			v=$(( 2 ** i ));
			l=$(echo "scale=8;l($v)/l(10)" | bc -l);
			l=${l/.*/};
			printf %02x ${l:=0};
		# data for ilog10;
		done | xxd --ps -r | base64 -w0;
		for (( i=0; i<12; i++ ));
		do
			v=$(( 10 ** i ));
			echo -en "$(printEndianValue ${v} $SIZE_64BITS_8BYTES)" | base64 -w0;
		done;
	})";
	local data_bytes_sum=$(echo $data_bytes | b64cnt);
	local bloc_outer_code_b64="$(echo -n "builtin..ilog10" | base64 -w0)";
	local bloc_source_lines_count=0;
	local bloc_usage_count=1;
	local bloc_return="";
	local bloc_dependencies="";
	struct_parsed_snippet \
		"PROCEDURE_TABLE" \
		"${snippet_type}" \
		"${snippet_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_size}" \
		"${static_data_offset}" \
		"${data_bytes}" \
		"${data_bytes_sum}" \
		"${bloc_outer_code_b64}" \
		"${bloc_source_lines_count}" \
		"${bloc_usage_count}" \
		"${bloc_return}" \
		"${bloc_dependencies}";
}

