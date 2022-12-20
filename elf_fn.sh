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
. logger.sh
. endianness.sh
. types.sh
. system_call_linux_$ARCH.sh

# functions bloc
print_elf_file_header()
{
	local ELF_HEADER_SIZE="${1:-0}";
	local PH_VADDR_V="$2";
	local EH_SIZE=64;
	local PH_SIZE="$3";
	local SH_SIZE="$4";
	local SH_COUNT="$5";
	local FIRST_CODE_OFFSET="$6";
	# SECTION ELF HEADER START
	ELFMAG="\x7fELF"; 	# ELF Index Magic 4 bytes, positions form 0 to 3
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
	debug SH_TOTAL_SIZE=$SH_TOTAL_SIZE
	debug FIRST_CODE_OFFSET=$FIRST_CODE_OFFSET
	local SHOFF_V=$(( EH_SIZE + PH_SIZE ))
	if [ $SH_COUNT -eq 0 ]; then
		SHOFF_V=0;
		SH_SIZE=0;
	fi;
	local ENTRY_V=$((
	PH_VADDR_V +
	ELF_HEADER_SIZE +
	PH_TOTAL_SIZE +
	SH_TOTAL_SIZE +
	FIRST_CODE_OFFSET
	));
	EI_ENTRY="$(printEndianValue ${ENTRY_V} $Elf64_Addr)";	# VADDR relative program code entry point uint64_t
	EI_PHOFF="$(printEndianValue "${ELF_HEADER_SIZE}" $Elf64_Off)";# program header offset in bytes, starts immediatelly after header, so the offset is the header size
	EI_SHOFF="$(printEndianValue ${SHOFF_V} $Elf64_Off)";			# section header offset in bytes
	EI_FLAGS="$(printEndianValue 0 $Elf64_Word)";			# uint32_t
	EI_EHSIZE="$(printEndianValue ${ELF_HEADER_SIZE} $Elf64_Half)";	# elf header size in bytes
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

get_program_headers_count()
{
	echo 1;
}

# given a list of section headers names, comma separeted, return the count
get_section_headers_count()
{
	local sh_names="$1"
	echo -n "${sh_names}" | tr , '\n' | grep -c ""
}

# https://stackoverflow.com/questions/16812574/elf-files-what-is-a-section-and-why-do-we-need-it
get_program_segment_headers()
{
	local ELF_HEADER_SIZE="$1";
	local PH_VADDR_V="$2";
	local PH_SIZE="$3";

	# https://www.airs.com/blog/archives/45
	# this point the current segment offset is 0x40
	PT_LOAD=1 # Loadable program segment
	PH_TYPE="$(printEndianValue $PT_LOAD $Elf64_Word)"	# Elf64_Word p_type 4;
	PF_X=$(( 1 << 0 )) # executable
	PF_W=$(( 1 << 1 )) # writable
	PF_R=$(( 1 << 2 )) # readable
	PH_FLAGS="$(printEndianValue $(( PF_X + PF_R )) $Elf64_Word)"	# Elf64_Word p_flags 4;
	# offset, vaddr and p_align are stringly related.
	PH_OFFSET="$(printEndianValue 0 $Elf64_Off)"	# Elf64_Off p_offset 8;
	PH_VADDR="$(printEndianValue $PH_VADDR_V $Elf64_Addr)"	# VADDR where to load program
       							# must be after the current program size. Elf64_Addr p_vaddr 8;
	PH_PADDR="$(printEndianValue 0 $Elf64_Addr)"	# Elf64_Addr p_paddr 8;
							# Physical address is deprecated and ignored for executables, libs and shared obj files.
	# PH_FILESZ and PH_MEMSZ should point to the first code position in elf
	# 16#78 == (ELF_HEADER_SIZE == x40 == 64) + (PH_SIZE == x38 == 56)
	PH_FILESZ="$(printEndianValue $(( ELF_HEADER_SIZE + PH_SIZE )) $Elf64_Xword)"	# Elf64_Xword p_filesz 8;
	PH_MEMSZ="$(printEndianValue $(( ELF_HEADER_SIZE + PH_SIZE )) $Elf64_Xword)"	# Elf64_Xword p_memsz 8;
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

	debug "PH_SIZE=${PH_SIZE}==$(echo -en "${PROGRAM_HEADERS}" | wc -c)"

	echo -en "$PROGRAM_HEADERS" | base64 -w0
	# SECTION PROGRAM HEADERS END
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
	return;
	get_shn_undef
	get_sht_strtab
}
# the elf body is the whole elf file after the elf file header(that ends at position 0x3f)
# the elf body has the program headers, segments and sections
print_elf_body()
{
	local ELF_HEADER_SIZE="$1";
	local PH_VADDR_V="$2";
	local PH_SIZE="$3";
	local SH_TOTAL_SIZE="$4";
	local SH_COUNT="$5";
	PROGRAM_HEADERS=$(get_program_segment_headers \
		"$ELF_HEADER_SIZE" \
		"$PH_VADDR_V" \
		"$PH_SIZE");
	debug "PROGRAM_HEADERS=[${PROGRAM_HEADERS}]";

	SECTION_HEADERS="$(get_section_headers)"; # test empty
	debug "SECTION_HEADERS=[${SECTION_HEADERS}]";

	# code section start
	# to define the final code we need the header address,
	# but it depends on code size, because it is after the code.
	# so, first do a first run to get the code size
	local ELF_SHELL_CODE="$(cat)";
	local CODE_SIZE=$(echo -en "$ELF_SHELL_CODE" | detect_instruction_size_from_code);
	local CODE=$(echo -en "$ELF_SHELL_CODE" |
		get_elf_code_and_data \
			"$PH_VADDR_V" \
			"${ELF_HEADER_SIZE}" \
			"${PH_SIZE}" \
			"${SH_TOTAL_SIZE}" \
			"${CODE_SIZE}"
	);
	debug CODE=${CODE};
	SECTION_ELF_DATA="${PROGRAM_HEADERS}${SECTION_HEADERS}${CODE}";

	echo -en "${SECTION_ELF_DATA}";
}

# return the instruction size in bytes, do not consider the data size.
instruction_bloc_size() {
	local INSTR="";
	grep "" | while read INSTR; do {
		if [ "${INSTR}" == "" ];then
			echo 0;
			continue;
		fi;
		if [[ "${INSTR}" =~ ^[#] ]];then
			echo 0;
			continue;
		fi;
		if [[ "${INSTR}" =~ ^[\	\ ]*write\  ]]; then
			echo $system_call_write_len;
			continue;
		fi;
		if [ "${INSTR:0:5}" == "exit " ]; then
			echo $system_call_exit_len;
			continue;
		fi;
		# TODO if a valid function call
		# return function call size
		if [ "${INSTR:0:4}" == "main" ]; then
			echo 0;
			continue;
		fi
		echo 0;
		error "[instruction_size]INVALID INSTRUCTION [$INSTR]";
	};
	done;
}

instruction_data()
{
	local INSTR="$1"
	if [ "${INSTR}" == "$(echo)" ];then
		return;
	fi;
	if [[ "${INSTR}" =~ ^[\	\ ]*write\  ]]; then
		V="$(tr " " "\n" <<<"$INSTR"| tail -1 )"
		debug "*** instruction_data[$V]";
		echo -n "${V}";
		return;
	fi;
	if [[ "${INSTR:0:5}" =~ ^[\	\ ]*exit ]]; then
		return;
	fi;
	error "INVALID INSTRUCTION (2) [$INSTR]"
}

start_code_bloc()
{
	debug WARN start_code_bloc not implemented
	:
}

end_code_bloc()
{
	debug WARN end_code_bloc not implemented
	:
}

# instruction_code translate the code instruction to machine code
# on the current kernel and processor archtecture
# this returns a CSV base64 line with one line, that can have two fields
# the instruction in base64 and the data to append on the data_section
instruction_code()
{
	debug "instruction_code..."
	local DATA_SECTION="$1";
	local INSTR="$2";
	local PH_VADDR_V="$3";
	local ELF_HEADER_SIZE="$4";
	local PH_SIZE="$5";
	local SH_TOTAL_SIZE="$6";
	local CODE_SIZE="$7"
	if [ "${INSTR}" == "$(echo)" ];then
		return;
	fi;
	if [[ "${INSTR}" =~ ^[\	\ ]*write\  ]]; then
		data_text="$(instruction_data "${INSTR}")";
		data_section_size=$(echo "${DATA_SECTION}" | base64 -d | wc -c)
		data_size="$( echo -n "${data_text}" | base64 -d | wc -c)";
		debug data_size=$data_size;
		data_addr_v="$(get_next_data_address \
			"${PH_VADDR_V}" \
			"${ELF_HEADER_SIZE}" \
			"${PH_SIZE}" \
			"${SH_TOTAL_SIZE}" \
			"${CODE_SIZE}" \
			"${data_section_size}";
		)";
		debug "data_addr_v=[$(printf %x $data_addr_v) == $data_addr_v]" ;
		# let's return the code instruction and the data to update on the section
		echo "$(system_call_write "$data_addr_v" "$data_size"),$(echo "$data_text")";
		return;
	fi;
	if [[ "${INSTR}" =~ ^[\	\ ]*exit\  ]]; then
		debug "translating exit"
		echo "$(system_call_exit ${INSTR:5}),"
		return;
	fi;
	if [[ "${INSTR}" =~ ^[\	\ ]*[a-zA-Z0-9]*:\ \{ ]]; then
		start_code_bloc;
		return;
	fi;

	if [[ "${INSTR}" =~ ^[\	\ ]*\} ]]; then
		end_code_bloc;
		return
	fi;
	error "INVALID INSTRUCTION (3) [$INSTR]";
}

read_until_bloc_closes()
{
	while read; do
		# end of bloc
		if [[ "$REPLY" =~ [}] ]]; then
			if [ ! "$inbloc" == true ]; then
				return
			fi;
		fi;
		echo "$REPLY";
	done;
}

# parse_code_bloc reads stdin and echoes bloc to stdout
# allowing a pipeline to read a full instruction or bloc at time;
parse_code_bloc()
{
	local CODE_LINE="$1";
	if [[ "${CODE_LINE}" =~ .*\:\ \{ ]]; then
		debug "parsing the bloc: $CODE_LINE ..."
		bloc_code="$(read_until_bloc_closes | base64 -w0)";
		debug "bloc code: $bloc_code"
		recursive_parse="$(
			echo "$bloc_code" |
			base64 -d |
			parse_code_blocs
			)";
		debug recursive_parse=[$recursive_parse]
		instructions_size_sum=$(echo "$recursive_parse" |
			cut -d, -f4 | awk '{s+=$1}END{print s}' );
					echo "BLOCK,$( echo -n "${bloc_code}" |
					base64 -w0
					),$(echo "$recursive_parse" |
					cut -d, -f3 |
					base64 -w0),$instructions_size_sum";
		return;
	fi;
	if [[ "${CODE_LINE}" =~ \# ]]; then
		echo "COMMENT,$(echo "$CODE_LINE" | base64 -w0),,0";
		return;
	fi;
	if [[ "${CODE_LINE}" =~ .*write ]]; then
		echo "INSTRUCTION,$( echo -n "${CODE_LINE}" | base64 -w0),sys_write,$system_call_write_len";
		return;
	fi;
	if [[ "${CODE_LINE}" =~ .*exit ]]; then
		echo "INSTRUCTION,$( echo -n "${CODE_LINE}" | base64 -w0),sys_exit,$system_call_exit_len";
		return;
	fi;
	echo "INVALID,$( echo -n "${CODE_LINE}" | base64 -w0),,0";
	return;
}

parse_code_blocs()
{
	grep "" | while read CODE_LINE;
	do
		parse_code_bloc "$CODE_LINE";
	done;
}

# get_first_code_offset should retorn the size of all instructions before the first call that is outside a bloc
get_first_code_offset()
{
	local CODE="$(cat)";
	local FIRST_CODE_OFFSET=$(
		local sum=0;
		echo -en "$CODE" | parse_code_blocs |
		grep "" |while read bloc;
		do
			if [ "$(echo "$bloc" | cut -d, -f1 )" == INSTRUCTION ]; then
				echo -n "$sum";
				return;
			fi;
			sum=$(( sum + $(echo "$bloc" | cut -d, -f4) ))
		done;
	);
	echo -n "${FIRST_CODE_OFFSET:=0}";
}

# detect_instruction_size_from_code should return the bytes used by the instructions code bloc.
# That includes NONE OF the data section (string table, the elf and program headers
detect_instruction_size_from_code()
{
	local CODE="$(cat)";
	local CODE_SIZE=$(
		local sum=$(
			echo -en "$CODE" | parse_code_blocs |
			while read bloc;
			do
				echo "$bloc" | cut -d, -f4;
				debug CODE ADD SIZE=$(echo "$bloc" | cut -d, -f4;), $bloc
			done |
		 awk '{s+=$1}END{print s}');
		debug "TOTAL INSTRUCTION CODE SIZE SUM=$sum"
		echo $sum
	);
	debug CODE_SIZE=$CODE_SIZE
	echo -n "${CODE_SIZE:=0}";
}

# parse_next_code_bloc should returns a CSV with:
#  code bloc type,
#  base64 of parsed code bloc,
#  code bloc instruction size,
#  code bloc data size,
#  unparsed code_bloc;
#  types should be: COMMENT, INSTRUCTION, BLOCK_DEFINITION, BLOCK_CALL
get_next_code_bloc()
{
	bloc=$( read_instruction_bloc )
	bloc_type=$(echo "$bloc" | instruction_bloc_type )
	bloc_instruction_b64=$(echo -n "$bloc" | instruction | base64 -w0)
	code_bloc_data_size=$(echo "$bloc" | blocsize)
	bloc_source_b64=$(echo -n "$bloc" | base64 -w0)
	debug "code size=[$sum]";
	# we can validate that value by getting the hex dump position(from where data section should start) - ph_size(56) - header size (64)
	echo -n $sum;
}

append_data()
{
	local DATA_SECTION="$1";
	local TEXT="$2";
	echo "$DATA_SECTION$TEXT";
}

get_data()
{
	local CODE="$1"
	local data=$(echo -e "$CODE" | while read; do
		echo -n "$(instruction_data "${REPLY}")"
	done);
	# we can validate that value by getting the hex dump position(from where data section should start) - ph_size(56) - header size (64)
	echo -n "$data";
}

get_instructions()
{
	local DATA_SECTION="";
	local CODE="$1";
	local ELF_HEADER_SIZE="$2";
	local PH_SIZE="$3";
	local SH_TOTAL_SIZE="$4";
	local CODE_SIZE="$5";

	#sum=$( echo -e "$CODE" | read_instruction_bloc | instruction_bloc_size | awk '{s+=$1}END{print s}' )

	local RESP=$(echo -e "$CODE" | while read; do
		debug "PARSING INSTRUCTION [$REPLY]";
		RET=$(instruction_code \
			"${DATA_SECTION}" \
		        "${REPLY}" \
		        "${PH_VADDR_V}" \
		        "${ELF_HEADER_SIZE}" \
		        "${PH_SIZE}" \
		        "${SH_TOTAL_SIZE}" \
		        "${CODE_SIZE}";
	       )
		DATA_SECTION="${DATA_SECTION}$(echo -n "$RET"| cut -d, -f2)"
		echo "${RET}";
	done);
	echo "$(echo -n "$RESP" |
		cut -d, -f1 |
		tr -d '\n'),$(
			echo -n "$RESP" |
				cut -d, -f2 |
				tr -d '\n')" ;
}

get_elf_code_and_data()
{
	local PH_VADDR_V="$1"
	local ELF_HEADER_SIZE="$2";
	local PH_SIZE="$3";
	local SH_TOTAL_SIZE="$4"
	local CODE_SIZE="$5";
	local ELF_SHELL_CODE="$(cat)";

	local INSTR="$(get_instructions \
		"${ELF_SHELL_CODE}" \
		"${ELF_HEADER_SIZE}" \
		"${PH_SIZE}" \
		"${SH_TOTAL_SIZE}" \
		"${CODE_SIZE}"
	)";
	local CODE=$(echo "$INSTR" | cut -d, -f1);
	local DATA_SECTION=$(echo "$INSTR" | cut -d, -f2);
	echo -n "${CODE}${DATA_SECTION}";
	return;
}

# get_next_data_address return the message addr, dynamic because every new code instruction changes it.
get_next_data_address()
{
	# is the start address of the DATA_SECTION... composed of 00010000 + ELF_HEADER_SIZE + ELF_BODY_SIZE (without DATA_SECTION)"
	local PH_VADDR="$1"
	local ELF_HEADER_SIZE="$2"
	local PH_SIZE="$3"
	local SH_TOTAL_SIZE="$4"
	local CODE_SIZE="$5"
	local DATA_SECTION_SIZE="$6";

	local ELF_BODY_SIZE="$(( PH_SIZE + SH_TOTAL_SIZE + CODE_SIZE ))"
	local DATA_ADDRESS_BEGIN_AT=$(( PH_VADDR + ELF_HEADER_SIZE + ELF_BODY_SIZE ))
	local NEXT_DATA_ADDRESS=$(( DATA_ADDRESS_BEGIN_AT + DATA_SECTION_SIZE))
	echo -n "${NEXT_DATA_ADDRESS}";
}

arg()
{
	echo -ne "$@" | base64;
}

write_elf()
{
	local ELF_FILE="$1"
	local ELF_HEADER="";
	# If we want to keep header size dynamic we can use:
	# local ELF_HEADER_SIZE="$( echo -ne "$(print_elf_file_header)" | wc -c )";
	# but for it is a constant of 64 bytes (at least on 64bit arch)
	local ELF_FILE_HEADER_SIZE=64 # 0x40, 1<<6
	local PH_VADDR_V="$(( 1 << 16 ))" # 65536, 0x10000
	local PH_SIZE=$(( 16#38 )) #56
	local SH_SIZE=64;
	local SH_COUNT=$(get_section_headers_count "");
	local SH_TOTAL_SIZE=$(( SH_SIZE * SH_COUNT ));
	local ELF_SHELL_CODE="$(cat)";
	local FIRST_CODE_OFFSET="$( echo "$ELF_SHELL_CODE" |
		get_first_code_offset)";
	local ELF_FILE_HEADER="$(
		print_elf_file_header \
			"${ELF_FILE_HEADER_SIZE}" \
			"${PH_VADDR_V}" \
			"${PH_SIZE}" \
			"${SH_SIZE}" \
			"${SH_COUNT}" \
			"${FIRST_CODE_OFFSET}";
	)"; # now we have size
	local ELF_BODY="$(echo "$ELF_SHELL_CODE" |
		print_elf_body \
			"${ELF_FILE_HEADER_SIZE}" \
			"${PH_VADDR_V}" \
			"${PH_SIZE}" \
			"${SH_TOTAL_SIZE}" \
			"${SH_COUNT}";
		)";
	debug ELF_BODY=$ELF_BODY;
	echo -ne "${ELF_FILE_HEADER}${ELF_BODY}" |
		base64 -d > $ELF_FILE;
}
