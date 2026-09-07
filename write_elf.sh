#!/bin/bash

import_bash <<-EOF
	./elf/get_section_headers_count.sh
	./parse_round.sh
	./elf/get_program_segment_headers.sh
EOF

get_ph_vaddr_v(){
	local PH_VADDR_V;
	read -r PH_VADDR_V < <(./ph_vaddr_v)
	if [ "$PH_VADDR_V" == "" ]; then
		# mmap_min_addr kernel config says where is the minimum valid segment to load the elf
		read -r PH_VADDR_V</proc/sys/vm/mmap_min_addr
	fi;
	if [ "$PH_VADDR_V" == "" ]; then
		PH_VADDR_V=$(( 1 << 16 )); # 64KiB
	fi;
	echo -n $PH_VADDR_V;
}

write_elf()
{
	debug write_file
	local ELF_FILE_OUTPUT="$1";
	# Virtual Memory Offset
	local PH_VADDR_V; 
	PH_VADDR_V=$(get_ph_vaddr_v);
	local SH_COUNT;
	SH_COUNT=$(get_section_headers_count);
	local INPUT_SOURCE_CODE; read -r -d '' INPUT_SOURCE_CODE || true; # read stdin into INPUT_SOURCE_CODE variable array
	local INIT_CODE="
	mmap 1 page 4096 bytes (private);
	mmap 1 page 4096 bytes (shared); ?
	reserve space for:
		array of mapped pages with struct
		* page addr
		* free page left;
		* shared page left;
	in private page should put:
		* argc is $rsp
		 (gdb) print *((int*)$rsp)
		* argv is $rsp + 8
		 (gdb) print *((char**)($rsp + 8))
	";
	local static_data_size=0;
	local snippets_file="${ELF_FILE_OUTPUT}.snippets";
	# this can be simplified once we have maps; so we can create a template and replace the memory position variables;
	# for future thinking: what about and encoded text, base64, where i can replace the variables with b64 values?
	debug before parseRoute
	echo "$INPUT_SOURCE_CODE" | parseRound 1 "${snippets_file}"; # Detect instruction size; static and dynamic data size;
	echo "$INPUT_SOURCE_CODE" | parseRound 2 "${snippets_file}"; # Detect internal dependencies size; upate instructions, static and dynamic data size;
	echo "$INPUT_SOURCE_CODE" | parseRound 3 "${snippets_file}"; # final parse with correct addresses displacements;

	local elf_size=0;
	for ((i=0; i<2; i++));
	do {
		# need to do twice because we don't have the final file size on first time;
		# could be better just to replace the filesz on program segment header (LOAD type);
		local ELF_BODY;
		local PROGRAM_HEADERS;
		PROGRAM_HEADERS="$(get_program_segment_headers "$PH_VADDR_V" "$elf_size")";
		ELF_BODY="$(
			print_elf_body \
				"${PROGRAM_HEADERS}" \
				"${SH_COUNT}" \
				"$snippets_file" \
				"$elf_size";
		)";
		local ELF_FILE_HEADER;
		ELF_FILE_HEADER="$(
			print_elf_file_header \
				"${PH_VADDR_V}" \
				"${SH_COUNT}" | xd2b64;
		)";
		echo -ne "${ELF_FILE_HEADER}${ELF_BODY}" |
			base64 -d > "$ELF_FILE_OUTPUT";
		elf_size=$(wc -c<"$ELF_FILE_OUTPUT")
	};
	done;
	debug write_file done
}
