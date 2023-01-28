#!/bin/bash
# see man elf - /usr/include/elf.h has all information including enums
# https://www.airs.com/blog/archives/38
# http://www.sco.com/developers/gabi/latest/ch4.eheader.html
# https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-83432/index.html
#
# we use base64 everywhere because bash does not support \x0 on strings

# init bloc
ARCH=$(uname -m)

# include bloc
. elf_constants.sh
. types.sh
. logger.sh
. endianness.sh
. ./arch/system_call_linux_$ARCH.sh
. snippet_parser.sh

get_program_headers_count()
{
	echo 1;
}

# functions bloc
print_elf_file_header()
{
	local PH_VADDR_V="$1";
	local SH_COUNT="$2";
	local FIRST_CODE_OFFSET="$3";

	local SH_SIZE="$SH_SIZE"; # use the constant in local scope to allow change it locally

	# SECTION ELF HEADER START
	EI_CLASS="\x00";	# Arch 2 bytes
	[ "$ARCH" == "x86" ] && {
		EI_CLASS="\x01";
		EM_386=3
		EM=$EM_386
	}
	[ "$ARCH" == "x86_64" ] && {
		EI_CLASS="\x02";
		EM_X86_64=62
		EM=$EM_X86_64
	}
	[ "$ARCH" == "aarch64" ] && {
		EI_CLASS="\x02";
		EM_AARCH64=183
		EM=$EM_AARCH64
		ELFCLASS64="\x02";
		EI_CLASS=$ELFCLASS64
	}

	# TODO replace all printEndianValue to use print_with_value
	EI_DATA="$(printEndianValue $(detect_endianness) ${SIZE_8BITS_1BYTE})" # get endianness from current bin
	EI_VERSION="\x01";	# ELF VERSION 1 (current)
	ELFOSABI_SYSV=0;
	ELFOSABI_HPUX=1;
	EI_OSABI="\x00";	# Operation System Applications Binary Interface (UNIX - System V-NONE)
	EI_ABIVERSION="\x00";
	EI_PAD="$(printEndianValue 0)"; # reserved non used pad bytes
	ET_EXEC=2;	# Executable file
	EI_ETYPE="$(printEndianValue $ET_EXEC $Elf64_Half)";		# DYN (Shared object file) code 3
	EI_MACHINE="$(printEndianValue $EM $Elf64_Half)";
	EI_MACHINE_VERSION="$(printEndianValue 1 $Elf64_Word)";

	PH_COUNT=$(get_program_headers_count);
	PH_TOTAL_SIZE=$(( PH_SIZE * PH_COUNT ));
	SH_TOTAL_SIZE=$(( SH_SIZE * SH_COUNT ));
	local SHOFF_V=$(( EH_SIZE + PH_SIZE ))
	if [ $SH_COUNT -eq 0 ]; then
		SHOFF_V=0;
		SH_SIZE=0; # some tools like readelf have issues when no sections but section size reported.
	fi;
	local ENTRY_V=$((
	PH_VADDR_V +
	EH_SIZE +
	PH_TOTAL_SIZE +
	SH_TOTAL_SIZE +
	FIRST_CODE_OFFSET
	));
	EI_ENTRY="$(printEndianValue ${ENTRY_V} $Elf64_Addr)";	# VADDR relative program code entry point uint64_t
	EI_PHOFF="$(printEndianValue "${EH_SIZE}" $Elf64_Off)";# program header offset in bytes, starts immediatelly after header, so the offset is the header size
	EI_SHOFF="$(printEndianValue ${SHOFF_V} $Elf64_Off)";			# section header offset in bytes
	EI_FLAGS="$(printEndianValue 0 $Elf64_Word)";			# uint32_t
	EI_EHSIZE="$(printEndianValue ${EH_SIZE} $Elf64_Half)";	# elf header size in bytes
	EI_PHENTSIZE="$(printEndianValue $PH_SIZE $Elf64_Half)";	# program header entry size (constant = sizeof(Elf64_Phdr))
	EI_PHNUM="$(printEndianValue $PH_COUNT $Elf64_Half)"; 			# number of program header entries
	# section table def
	EI_SHENTSIZE="$(printEndianValue $SH_SIZE $Elf64_Half)";	# section header size in bytes(contant sizeof(Elf64_Shdr))
	EI_SHNUM="$(printEndianValue $SH_COUNT $Elf64_Half)"; 		# section header count
	EI_SHSTRNDX="$(printEndianValue 0 $Elf64_Half)"; 	# section header table index of entry of section name string table

	# 00-0f
	SECTION_ELF_HEADER="${ELFMAG}${EI_CLASS}${EI_DATA}${EI_VERSION}${EI_OSABI}${EI_PAD}"; # 16 bytes
	# 10-1f
	SECTION_ELF_HEADER="${SECTION_ELF_HEADER}${EI_ETYPE}${EI_MACHINE}${EI_MACHINE_VERSION}${EI_ENTRY}";
	# 20-2f
	SECTION_ELF_HEADER="${SECTION_ELF_HEADER}${EI_PHOFF}${EI_SHOFF}";
	# 30-3f
	SECTION_ELF_HEADER="${SECTION_ELF_HEADER}${EI_FLAGS}${EI_EHSIZE}${EI_PHENTSIZE}${EI_PHNUM}${EI_SHENTSIZE}${EI_SHNUM}${EI_SHSTRNDX}";

	# SECTION ELF HEADER END
	echo -en "${SECTION_ELF_HEADER}" | base64 -w0;
}

# https://stackoverflow.com/questions/16812574/elf-files-what-is-a-section-and-why-do-we-need-it
get_program_segment_headers()
{
	local PH_VADDR_V="$1";

	# https://www.airs.com/blog/archives/45
	# this point the current segment offset is 0x40
	PH_TYPE="$(printEndianValue $PT_LOAD $Elf64_Word)"	# Elf64_Word p_type 4;
	PH_FLAGS="$(printEndianValue $(( PF_X + PF_R )) $Elf64_Word)"	# Elf64_Word p_flags 4;
	# offset, vaddr and p_align are stringly related.
	PH_OFFSET="$(printEndianValue 0 $Elf64_Off)"	# Elf64_Off p_offset 8;
	PH_VADDR="$(printEndianValue $PH_VADDR_V $Elf64_Addr)"	# VADDR where to load program
       							# must be after the current program size. Elf64_Addr p_vaddr 8;
	PH_PADDR="$(printEndianValue 0 $Elf64_Addr)"	# Elf64_Addr p_paddr 8;
							# Physical address is deprecated and ignored for executables, libs and shared obj files.
	# PH_FILESZ and PH_MEMSZ should point to the first code position in elf
	# 16#78 == (EH_SIZE == x40 == 64) + (PH_SIZE == x38 == 56)
	PH_FILESZ="$(printEndianValue $(( EH_SIZE + PH_SIZE )) $Elf64_Xword)"	# Elf64_Xword p_filesz 8;
	PH_MEMSZ="$(printEndianValue $(( EH_SIZE + PH_SIZE )) $Elf64_Xword)"	# Elf64_Xword p_memsz 8;
	# p_align: Loadable process segments must have congruent values for p_vaddr and p_offset,
	#          modulo the page size.
	#          This member gives the value to which the segments are aligned in memory and in the file.
	#          Values 0 and 1 mean no alignment is required.
	#          Otherwise, p_align should be a positive, integral power of 2,
	#           and p_vaddr should equal p_offset, modulo p_align.
	#          See "Program Loading (Processor-Specific)".
	PH_ALIGN="$(printEndianValue 0 $Elf64_Xword)"	# Elf64_Xword p_align 8;

	# 40-43
	PROGRAM_HEADERS="${PH_TYPE}";
	# 44-47
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_FLAGS}";
	# 48-4f
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_OFFSET}";
	# 50
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_VADDR}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_PADDR}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_FILESZ}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_MEMSZ}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_ALIGN}"; # Elf64_Phdr[]

	echo -en "$PROGRAM_HEADERS" | base64 -w0
	# SECTION PROGRAM HEADERS END
}

# given a list of section headers names, comma separeted, return the count
get_section_headers_count()
{
	local sh_names="$1"
	echo -n "${sh_names}" | tr , '\n' | grep -c ""
}

# TODO make use of string_table
string_table=""
get_tbl_index() {
	echo $(( 16#0 ));
	return
	str=$( base64 -w0 <<< $1)
	idx=$(grep -q "$str" <<< $string_table | cut -d: -f1)
	if [ "$idx" == "" ]; then
		string_table="${string_table}$str";
		grep -c "" <<< "$string_table"
		return
	fi
	# echo $(( $idx - 1 ))
	echo $(( 16#100da )) # for now just set to the first string vaddr
}

get_shn_undef()
{
	local SHT_NULL=0;	# String table
	local sh_name=$(printEndianValue 0 $Elf64_Word);	# Section name (string tbl index)
	local sh_type=$(printEndianValue $SHT_NULL $Elf64_Word);	# Section type
	local sh_flags=$(printEndianValue 0 $Elf64_Xword);	# Section flags
	local sh_addr=$(printEndianValue 0 $Elf64_Addr); 	# Section virtual addr at execution
	local sh_offset=$(printEndianValue 0 $Elf64_Off); 	# Section file offset
	local sh_size=$(printEndianValue 0 $Elf64_Xword); 	# Section size in bytes
	local sh_link=$(printEndianValue 0 $Elf64_Word);	# Link to another section
	local sh_info=$(printEndianValue 0 $Elf64_Word);	# Additional section information
	local sh_addralign=$(printEndianValue 0 $Elf64_Xword);	# Section alignment
	local sh_entsize=$(printEndianValue 0 $Elf64_Xword);	# Entry size if section holds table

	local SECTION_HEADERS=""
	# 16 bytes per line
	SECTION_HEADERS="${SECTION_HEADERS}${sh_name}${sh_type}${sh_flags}";
	SECTION_HEADERS="${SECTION_HEADERS}${sh_addr}${sh_offset}";
	SECTION_HEADERS="${SECTION_HEADERS}${sh_size}${sh_link}${sh_info}";
	SECTION_HEADERS="${SECTION_HEADERS}${sh_addralign}${sh_entsize}";
	echo -en "${SECTION_HEADERS}" | base64 -w0
}

get_sht_strtab()
{
	local SHT_STRTAB=3;	# String table
	local sh_name=$(printEndianValue $(get_tbl_index "string table") $Elf64_Word);	# Section name (string tbl index)
	local sh_type=$(printEndianValue $SHT_STRTAB $Elf64_Word);	# Section type
	local SHF_STRINGS="$(( 1 << 5 ))";	# Contains nul-terminated strings */
	local sh_flags=$(printEndianValue $SHF_STRINGS $Elf64_Xword);	# Section flags
	local sh_addr=$(printEndianValue 0 $Elf64_Addr); 	# Section virtual addr at execution
	local sh_offset=$(printEndianValue $(( 16#106 )) $Elf64_Off); 	# Section file offset
	local sh_size=$(printEndianValue $((64 + 7)) $Elf64_Xword); 	# Section size in bytes
	local sh_link=$(printEndianValue 0 $Elf64_Word);	# Link to another section
	local sh_info=$(printEndianValue 0 $Elf64_Word);	# Additional section information
	local sh_addralign=$(printEndianValue 1 $Elf64_Xword);	# Section alignment
	local sh_entsize=$(printEndianValue 16 $Elf64_Xword);	# Entry size if section holds table

	local SECTION_HEADERS=""
	# 16 bytes per line
	SECTION_HEADERS="${SECTION_HEADERS}${sh_name}${sh_type}${sh_flags}";
	SECTION_HEADERS="${SECTION_HEADERS}${sh_addr}${sh_offset}";
	SECTION_HEADERS="${SECTION_HEADERS}${sh_size}${sh_link}${sh_info}";
	SECTION_HEADERS="${SECTION_HEADERS}${sh_addralign}${sh_entsize}";
	echo -en "${SECTION_HEADERS}" | base64 -w0
}

get_section_headers()
{
	local tiny_mode=true
	if [ "${tiny_mode}" != "true" ]; then
		get_shn_undef
		get_sht_strtab
	fi;
}

# the elf body is the whole elf file after the elf file header(that ends at position 0x3f)
# the elf body has the program headers, segments and sections
print_elf_body()
{
	local PH_VADDR_V="$1";
	local SH_COUNT="$2";
	local INPUT_SOURCE_CODE="$3";
	local OLD_SNIPPETS="$4";

	local SH_TOTAL_SIZE="$(( SH_COUNT * SH_SIZE ))";

	PROGRAM_HEADERS=$(get_program_segment_headers "$PH_VADDR_V" );

	SECTION_HEADERS="$(get_section_headers)"; # test empty

	local INSTR_TOTAL_SIZE=$(echo -en "${OLD_SNIPPETS}" | detect_instruction_size_from_code);
	local SNIPPETS="$(echo "${INPUT_SOURCE_CODE}" | parse_snippets "${PH_VADDR_V}" "${INSTR_TOTAL_SIZE}")";
	local INSTR_ALL=$(echo -en "${SNIPPETS}" |
		cut -d, -f${SNIPPET_COLUMN_INSTR_BYTES}
	);

	DATA_ALL="$(echo "${SNIPPETS}" | cut -d, -f$SNIPPET_COLUMN_DATA_BYTES)"

	local SECTION_ELF_DATA="";
	SECTION_ELF_DATA="${SECTION_ELF_DATA}${PROGRAM_HEADERS}";
	SECTION_ELF_DATA="${SECTION_ELF_DATA}${SECTION_HEADERS}";
	SECTION_ELF_DATA="${SECTION_ELF_DATA}${INSTR_ALL}";
	SECTION_ELF_DATA="${SECTION_ELF_DATA}${DATA_ALL}";

	echo -en "${SECTION_ELF_DATA}";
}

read_until_bloc_closes()
{
	while read; do
		echo "$REPLY";
		# end of bloc
		if [[ "$(echo -n "$REPLY" | xxd --ps )" =~ ^(09)*7d$ ]]; then # ignore tabs and has closed brackets("}") at end of line
			if [ ! "$inbloc" == true ]; then
				return
			fi;
		fi;
	done;
}

# parse_snippet given a source code snippet echoes snippet struct to stdout
# allowing a pipeline to read a full instruction or bloc at time;
# it should return a code snippet
parse_snippet()
{
	local PH_VADDR_V="$1"
	local INSTR_TOTAL_SIZE="$2";
	local CODE_LINE="$3";
	local SNIPPETS="$4";
	local deep="$5";

	local CODE_LINE_XXD="$( echo -n "${CODE_LINE}" | xxd --ps)";
	local CODE_LINE_B64=$( echo -n "${CODE_LINE}" | base64 -w0);
	local previous_snippet=$( echo "${SNIPPETS}" | tail -1 );
	local previous_instr_offset=$(echo "${previous_snippet}" | cut -d, -f$SNIPPET_COLUMN_INSTR_OFFSET);
	previous_instr_offset="${previous_instr_offset:=$((PH_VADDR_V + EH_SIZE + PH_SIZE))}"
	local previous_instr_sum=$(echo "${previous_snippet}" | cut -d, -f$SNIPPET_COLUMN_INSTR_LEN);
	local instr_offset="$(( ${previous_instr_offset} + previous_instr_sum ))";
	local previous_data_offset=$(echo "${previous_snippet}" | cut -d, -f$SNIPPET_COLUMN_DATA_OFFSET);
	local previous_data_len=$(echo "${previous_snippet}" | cut -d, -f$SNIPPET_COLUMN_DATA_LEN);
	previous_data_offset="${previous_data_offset:=$(( PH_VADDR_V + EH_SIZE + PH_SIZE + INSTR_TOTAL_SIZE ))}"
	local data_offset="$(( previous_data_offset + previous_data_len ))";
	if [[ "${CODE_LINE_XXD}" =~ .*3a097b$ ]]; then # check if ends with ":\t{"
	{
		new_bloc="$(
			SNIPPET_NAME="$(echo "$CODE_LINE" |cut -d: -f1 | tr -d '\t')";
			bloc_outer_code="$(echo "${CODE_LINE}"; read_until_bloc_closes)";
			bloc_outer_code_b64="$(echo -n "${bloc_outer_code}" | base64 -w0 )"
			bloc_inner_code="$(
				echo "${bloc_outer_code}" |
				awk 'NR>2 {print prev}; {prev=$0};' |
				base64 -w0
			)";
			recursive_parse="$(
				echo "$bloc_inner_code" |
				base64 -d |
				parse_snippets "${PH_VADDR_V}" "${INSTR_TOTAL_SIZE}" "$SNIPPETS" "$deep"
			)";
			innerlines="$(echo "$recursive_parse"  |
				cut -d, -f$SNIPPET_COLUMN_SOURCE_LINES_COUNT |
				awk '{s+=$1}END{print s}'
			)"
			local bloc_source_lines_count=$(( innerlines +2 ))
			local instr_bytes=$(echo "$recursive_parse"  |
				cut -d, -f$SNIPPET_COLUMN_INSTR_BYTES
			)
			local instr_size_sum="$( echo "${instr_bytes}" |
				base64 -d | wc -c |
				awk '{s+=$1}END{print s}'
			)"
			local data_bytes="$(echo "$recursive_parse"  |
				cut -d, -f$SNIPPET_COLUMN_DATA_BYTES )"
			local data_bytes_sum="$( echo "${data_bytes}" |
				base64 -d | wc -c |
				awk '{s+=$1}END{print s}'
			)";
			out="$(struct_parsed_snippet \
				"SNIPPET" \
				"${SNIPPET_NAME}" \
				"${instr_offset}" \
				"${instr_bytes}" \
				"${instr_size_sum}" \
				"${data_offset}" \
				"${data_bytes}" \
				"${data_bytes_sum}" \
				"${bloc_outer_code_b64}" \
				"${bloc_source_lines_count}";
			)";
			echo "$out";
		)";
		local bloc_name=$(echo "$new_bloc" | cut -d, -f${SNIPPET_COLUMN_SUBNAME})
		if [ "$SNIPPETS" == "" ]; then
			SNIPPETS="$( echo "$new_bloc" | base64 -w0)";
		else
			SNIPPETS="$( echo -e "$SNIPPETS\n$new_bloc"| base64 -w0)";
		fi;
		echo "$new_bloc";
		return $?;
	}
	fi;
	if [[ "${CODE_LINE_XXD}" =~ ^(09)*23 ]]; then # ignoring tabs, starts with pound symbol(#)
	{
		struct_parsed_snippet \
			"COMMENT" \
			"" \
			"${instr_offset}" \
			"" \
			"0" \
			"${data_offset}" \
			"" \
			"0" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	}
	fi;
	if [[ "${CODE_LINE_XXD}" =~ ^(09)*777269746509 ]]; then # write
	{
		data_output="$( echo -n "${CODE_LINE/*write/}" | cut -f2 )"
		data_bytes="$( echo -n "${CODE_LINE/*write/}" | cut -f3 )"
		data_bytes_len="$( echo -n "${data_bytes}"| base64 -d | wc -c)";
		data_addr_v="${data_offset}"
		instr_bytes="$(system_call_write "$data_addr_v" "$data_bytes_len")";
		struct_parsed_snippet \
			"INSTRUCTION" \
			"sys_write" \
			"${instr_offset}" \
			"${instr_bytes}" \
			"${system_call_write_len}" \
			"${data_offset}" \
			"${data_bytes}" \
			"${data_bytes_len}" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	}
	fi;
	if [[ "${CODE_LINE_XXD}" =~ ^(09)*726574 ]]; then # ret
		ret_value="$( echo -n "${CODE_LINE/ret/}" | tr -s " " | cut -d " " -f2 )"
		bytecode_return="$(bytecode_ret "${ret_value}")"
		instr_bytes="$(echo $bytecode_return | cut -d, -f1)"
		instr_size="$(echo $bytecode_return | cut -d, -f2)"
		struct_parsed_snippet \
			"INSTRUCTION" \
			"sys_ret" \
			"${instr_offset}" \
			"${instr_bytes}" \
			"${instr_size}" \
			"${data_offset}" \
			"" \
			"0" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	fi;
	if [[ "${CODE_LINE_XXD}" =~ ^(09)*65786974 ]]; then # exit
		exit_value="$( echo -n "${CODE_LINE/exit/}" | tr -s " " | cut -d " " -f2 )"
		instr_bytes="$(system_call_exit ${exit_value})"
		struct_parsed_snippet \
			"INSTRUCTION" \
			"sys_exit" \
			"${instr_offset}" \
			"${instr_bytes}" \
			"${system_call_exit_len}" \
			"${data_offset}" \
			"" \
			"0" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	fi;
	if [ "$CODE_LINE" == "" ]; then
		struct_parsed_snippet \
			"EMPTY" \
			"" \
			"${instr_offset}" \
			"" \
			"0" \
			"${data_offset}" \
			"" \
			"0" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	fi;
	if [[ "${CODE_LINE_XXD}" =~ ^(09)*676f746f09 ]]; then # goto
		target="${CODE_LINE/goto }"
		debug "GOTO [$target]"
		target_offset="$( echo "$SNIPPETS" | grep "SNIPPET,${target}" | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET} )";
		jmp_result="$(system_call_jump "${target_offset}" "${instr_offset}" )";
		debug jmp_result=$jmp_result
		jmp_bytes="$(echo "${jmp_result}" | cut -d, -f1)";
		jmp_len="$(echo "${jmp_result}" | cut -d, -f2)";
		debug goto instruction offset $( printf %x $instr_offset )
		struct_parsed_snippet \
			"SNIPPET_CALL" \
			"jmp" \
			"${instr_offset}" \
			"${jmp_bytes}" \
			"${jmp_len}" \
			"${data_offset}" \
			"" \
			"0" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	fi;
	if echo "$SNIPPETS" | grep -q "${CODE_LINE}"; then
		target="${CODE_LINE/}"
		target_offset="$( echo "$SNIPPETS" | grep "SNIPPET,${target}" | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET} )";
		local call_bytecode="$(system_call_procedure "${target_offset}" "${instr_offset}" )";
		local call_bytes="$(echo "${call_bytecode}" | cut -d, -f1)";
		local call_len="$(echo "${call_bytecode}" | cut -d, -f2)";
		struct_parsed_snippet \
			"SNIPPET_CALL" \
			"call" \
			"${instr_offset}" \
			"${call_bytes}" \
			"${call_len}" \
			"${data_offset}" \
			"" \
			"0" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	fi;
	error "invalid instr: [$CODE_LINE_B64]"
	struct_parsed_snippet \
		"INVALID" \
		"" \
		"${instr_offset}" \
		"" \
		"0" \
		"${data_offset}" \
		"" \
		"0" \
		"${CODE_LINE_B64}" \
		"1";
	return $?;
}

# should return multiple struct_parsed_snippet output (one per line)
parse_snippets()
{
	local PH_VADDR_V="$1";
	local INSTR_TOTAL_SIZE="$2";
	local SNIPPETS="$3"; # cummulative to allow cross reference between snippets
	local deep="${4-0}";
	local CODE_INPUT=$(cat);
	let deep++;
	echo "${CODE_INPUT}" | while read CODE_LINE;
	do
		RESULT=$(parse_snippet "${PH_VADDR_V}" "${INSTR_TOTAL_SIZE}" "${CODE_LINE}" "${SNIPPETS}" "${deep}");
		if [ ${#SNIPPETS} -gt 0 ]; then
			SNIPPETS="$(echo -e "${SNIPPETS}\n$RESULT")"
		else
			SNIPPETS="$RESULT";
		fi
		# the result have multiple lines read so we need to add them to the source lines var
		inner_source_lines=$(echo "$RESULT" | cut -d, -f5)
		# TODO we can deduce the source line number by the snippets
		echo "$RESULT"
	done;
}

# get_first_code_offset should return the size of all instructions before the first call that is outside a bloc
get_first_code_offset()
{
	local SNIPPETS="$(cat)";
	local i=0;
	echo "${SNIPPETS}" |
	cut -d, -f${SNIPPET_COLUMN_TYPE},${SNIPPET_COLUMN_INSTR_LEN} |
	while IFS=, read k s;
	do
		[ $k == INSTRUCTION -o $k == SNIPPET_CALL ] && break;
		i=$(( i + s ));
		echo "$i";
	done | tail -1;
}

# detect_instruction_size_from_code should return the bytes used by the instructions code bloc.
# That includes NONE OF the data section (string table, the elf and program headers
detect_instruction_size_from_code()
{
	grep -E "^(SNIPPET|INSTRUCTION|SNIPPET_CALL)," |
	cut -d, -f${SNIPPET_COLUMN_INSTR_LEN} |
	awk '{s+=$1}END{print s}'
}

arg()
{
	echo -ne "$@" | base64 -w0 || error arg fail [$0];
}

write_elf()
{
	local ELF_FILE_OUTPUT="$1";
	# Virtual Memory Offset
	local PH_VADDR_V="$(( 1 << 16 ))" # 65536, 0x10000
	local SH_COUNT=$(get_section_headers_count "");
	local INPUT_SOURCE_CODE="$(cat)";
	local parsed_snippets="$(echo "${INPUT_SOURCE_CODE}" | parse_snippets "${PH_VADDR_V}" "${INSTR_TOTAL_SIZE-0}")";
	local FIRST_CODE_OFFSET="$( echo "$parsed_snippets" | get_first_code_offset)";
	local ELF_FILE_HEADER="$(
		print_elf_file_header \
			"${PH_VADDR_V}" \
			"${SH_COUNT}" \
			"${FIRST_CODE_OFFSET}";
	)";
	# now we have the all information parsed
	# but the addresses are just offsets
	# we need to redo the addresses references
	local ELF_BODY="$(echo "$parsed_snippets" |
		print_elf_body \
			"${PH_VADDR_V}" \
			"${SH_COUNT}" \
			"${INPUT_SOURCE_CODE}" \
			"${parsed_snippets}";
	)";
	echo -ne "${ELF_FILE_HEADER}${ELF_BODY}" |
		base64 -d > $ELF_FILE_OUTPUT;
}
