#!/bin/bash
#
# This is a script with functions used to generate ELF files.
#
# see man elf - /usr/include/elf.h has all information including enums
# https://www.airs.com/blog/archives/38
# http://www.sco.com/developers/gabi/latest/ch4.eheader.html
# https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-83432/index.html
#
# we use base64 everywhere because bash does not support \x0 on strings

# init bloc
ARCH=$(uname -m)
# I have no idea why, but when using execve without env, a bash call can not resolve the "uname -m" call above.
ARCH=${ARCH:=x86_64}
# include bloc
. elf_constants.sh
. types.sh
. utils.sh
. logger.sh
. endianness.sh
. ./arch/system_call_linux_${ARCH}.sh
. snippet_parser.sh

get_program_headers_count()
{
	# for now we only have it hard coded 
	# TODO implement it to dynamically detect and set a value.
	echo 1;
}

# functions bloc
print_elf_file_header()
{
	local PH_VADDR_V="$1";
	local SH_COUNT="$2";

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
	SH_TOTAL_SIZE
	));
	EI_ENTRY="$(printEndianValue ${ENTRY_V} $Elf64_Addr)";	# VADDR relative program code entry point uint64_t
	EI_PHOFF="$(printEndianValue "${EH_SIZE}" $Elf64_Off)";	# program header offset in bytes, starts immediatelly after header, so the offset is the header size
	EI_SHOFF="$(printEndianValue ${SHOFF_V} $Elf64_Off)";	# section header offset in bytes
	EI_FLAGS="$(printEndianValue 0 $Elf64_Word)";		# uint32_t
	EI_EHSIZE="$(printEndianValue ${EH_SIZE} $Elf64_Half)";	# elf header size in bytes
	EI_PHENTSIZE="$(printEndianValue $PH_SIZE $Elf64_Half)";# program header entry size (constant = sizeof(Elf64_Phdr))
	EI_PHNUM="$(printEndianValue $PH_COUNT $Elf64_Half)"; 	# number of program header entries
	# section table def
	EI_SHENTSIZE="$(printEndianValue $SH_SIZE $Elf64_Half)";# section header size in bytes(contant sizeof(Elf64_Shdr))
	EI_SHNUM="$(printEndianValue $SH_COUNT $Elf64_Half)"; 	# section header count
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
	PH_TYPE="$(printEndianValue $PT_LOAD $Elf64_Word)"		# Elf64_Word p_type 4;
	# TODO: this PF_W is insecure and can allow rewrite the memory code. should not be used in this context. For now it is ok because i am lazy. and I want to use this memory page to store stat on read file context.
	PH_FLAGS="$(printEndianValue $(( PF_X + PF_W + PF_R )) $Elf64_Word)"	# Elf64_Word p_flags 4;
	# offset, vaddr and p_align are stringly related.
	PH_OFFSET="$(printEndianValue 0 $Elf64_Off)"		# Elf64_Off p_offset 8;
	PH_VADDR="$(printEndianValue $PH_VADDR_V $Elf64_Addr)"	# VADDR where to load program
								# must be after the current program size. Elf64_Addr p_vaddr 8;
	PH_PADDR="$(printEndianValue 0 $Elf64_Addr)"		# Elf64_Addr p_paddr 8;
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
	local SHT_NULL=0;						# String table
	local sh_name=$(printEndianValue 0 $Elf64_Word);		# Section name (string tbl index)
	local sh_type=$(printEndianValue $SHT_NULL $Elf64_Word);	# Section type
	local sh_flags=$(printEndianValue 0 $Elf64_Xword);		# Section flags
	local sh_addr=$(printEndianValue 0 $Elf64_Addr); 		# Section virtual addr at execution
	local sh_offset=$(printEndianValue 0 $Elf64_Off); 		# Section file offset
	local sh_size=$(printEndianValue 0 $Elf64_Xword); 		# Section size in bytes
	local sh_link=$(printEndianValue 0 $Elf64_Word);		# Link to another section
	local sh_info=$(printEndianValue 0 $Elf64_Word);		# Additional section information
	local sh_addralign=$(printEndianValue 0 $Elf64_Xword);		# Section alignment
	local sh_entsize=$(printEndianValue 0 $Elf64_Xword);		# Entry size if section holds table

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
	local snippets_file=$3

	local PROGRAM_HEADERS=$(get_program_segment_headers "$PH_VADDR_V" );

	local SH_TOTAL_SIZE="$(( SH_COUNT * SH_SIZE ))";
	local SECTION_HEADERS="$(get_section_headers)"; # test empty

	local INSTR_ALL=$(cat "${snippets_file}" |
		cut -d, -f${SNIPPET_COLUMN_INSTR_BYTES}
	);

	local static_data_count=0;
	local DATA_ALL="$(cat "${snippets_file}" | 
		while read d;
		do
			local dt=$(echo -en "$d" | cut -d, -f${SNIPPET_COLUMN_TYPE});
			local ds=$(echo -en "$d" | cut -d, -f$SNIPPET_COLUMN_DATA_LEN);
			local dbl=$(echo -en "$d" | cut -d, -f$SNIPPET_COLUMN_DATA_BYTES | base64 -d | wc -c);
			if [ "$dt" == "SYMBOL_TABLE" ]; then
				if [ "${ds:=0}" -gt 0 -a "${dbl:=0}" -gt 0 ]; then # avoid hard coded values
					echo -en "$d" | cut -d, -f$SNIPPET_COLUMN_DATA_BYTES;
					echo -en "\x00" | base64 -w0; # ensure a null byte to split data
					let static_data_count++;
				fi;
			fi;
		done; 
	)";

	local SECTION_ELF_DATA="";
	SECTION_ELF_DATA="${SECTION_ELF_DATA}${PROGRAM_HEADERS}";
	SECTION_ELF_DATA="${SECTION_ELF_DATA}${SECTION_HEADERS}";
	SECTION_ELF_DATA="${SECTION_ELF_DATA}${INSTR_ALL}";
	SECTION_ELF_DATA="${SECTION_ELF_DATA}${DATA_ALL}";

	echo -en "${SECTION_ELF_DATA}";
}

# about the functions, I don't really want the {} brackets ... but it is easier to prase this way. since I need to read until detect it is closed, and without it I will be reading the next line outside the function.
read_code_bloc()
{
	local deep="$1"
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

# parse_code_line_elements returns a base array with all given elements
parse_code_line_elements()
{
	local code_line="$1";
	IFS=$'\t'
	read -ra elements <<< "${code_line}"
	encoded_array="$( encode_array_to_b64_csv "${elements[@]}" )"
	echo -n "${encoded_array}"
}

get_symbol_addr()
{
	local symbol_name="$1"
	local SNIPPETS=$2;
	local symbol_addr="$(echo "$SNIPPETS" | grep "SYMBOL_TABLE,${symbol_name}," | tail -1 | cut -d, -f${SNIPPET_COLUMN_DATA_OFFSET})";
	echo "${symbol_addr}";
}

get_symbol_usages()
{
	local symbol_name="$1"
	local SNIPPETS=$2;
	local symbol_addr="$(echo "$SNIPPETS" | grep "SYMBOL_TABLE,${symbol_name}," | tail -1 | cut -d, -f${SNIPPET_COLUMN_USAGE_COUNT})";
	echo "${symbol_addr}";
}

# it returns
B64_SYMBOL_VALUE_RETURN_OUT=1;
B64_SYMBOL_VALUE_RETURN_SIZE=2;
B64_SYMBOL_VALUE_RETURN_TYPE=3;
B64_SYMBOL_VALUE_RETURN_ADDR=4;
get_b64_symbol_value()
{
	local symbol_name="$1";
	local SNIPPETS=$2;
	local input="ascii";
	# empty value
	if [ "$symbol_name" == "" ]; then
		echo -n ",0,${SYMBOL_TYPE_HARD_CODED},0";
	fi;
	# hard coded number
	if is_valid_number "$symbol_name"; then {
		out=$(echo -n "$symbol_name" | base64 -w0);
		outsize=$(echo -n "${out}" | base64 -d | wc -c)
		echo -n ${out},${outsize},${SYMBOL_TYPE_HARD_CODED}
		return
	}
	fi;
	local symbol_data="$(echo "$SNIPPETS" | grep "SYMBOL_TABLE,${symbol_name}," | tail -1)";
	# return default values for known internal words
	if [ "${symbol_name}" == "input" ]; then
	{
		local symbol_instr="$( echo "$symbol_data" | cut -d, -f${SNIPPET_COLUMN_DATA_BYTES})";
		local out=$(echo -n "${symbol_instr}");
		if [ "$out" == "" ]; then
			out=$(echo -n 'ascii' | base64 -w0);
		fi;
		local outsize="$(echo -n "${out}" | base64 -d | wc -c)";
		echo -n "${out},${outsize},${SYMBOL_TYPE_HARD_CODED}";
		return;
	}
	fi;
	# procedure
	local procedure_data="$( echo "$SNIPPETS" | grep "PROCEDURE_TABLE,${symbol_name}," | tail -1)";
	if [ "${procedure_data}" != "" ]; then
		local addr=$(echo "${procedure_data}" | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET});
		echo -n ${out},${outsize},${SYMBOL_TYPE_PROCEDURE},${addr}
		return 1;
	fi
	if [ "${symbol_data}" == "" ]; then
	{
		error "Expected a integer or a valid variable/constant. But got [$symbol_name][$SNIPPETS]"
		backtrace
		return 1
	}
	fi;
	local symbol_value="$( echo "$symbol_data" | cut -d, -f${SNIPPET_COLUMN_DATA_BYTES})";
	local symbol_len="$( echo "$symbol_data" | cut -d, -f${SNIPPET_COLUMN_DATA_LEN})";
	local symbol_addr="$( echo "$symbol_data" | cut -d, -f${SNIPPET_COLUMN_DATA_OFFSET})";
	if [ "${symbol_value}" == "" ];then
	{
		if [ "${symbol_len}" == 0 ]; then
			echo -n ",0,${SYMBOL_TYPE_HARD_CODED}"
			return;
		fi;
		# Empty values will be only accessible at runtime, eg: args, arg count...
		out=$(echo -n "${symbol_addr}" | base64 -w0)
		outsize=8; # memory_addr_size; TODO: this is platform specific, in x64 is 8 bytes
		echo -n ${out},${outsize},${SYMBOL_TYPE_DYNAMIC},${symbol_addr}
		return;
	};
	fi
	if is_valid_number "$(echo "${symbol_value}" | base64 -d)"; then {
		out="$symbol_value";
		outsize=$(echo -n "${out}" | base64 -d | wc -c)
		echo -n ${out},${outsize},${SYMBOL_TYPE_HARD_CODED}
		return
	}
	fi;
	out=$(echo -n "${symbol_value}")
	outsize=$(echo -n "${out}" | base64 -d | wc -c)
	echo -n ${out},${outsize},${SYMBOL_TYPE_STATIC},${symbol_addr}
	return
	# TODO, increment usage count in SNIPPETS SYMBOL_TABLE
}

set_symbol_value()
{
	local symbol_value="$1";
	local SNIPPETS="$2";
	local data_bytes="${symbol_value}";
	local input="${symbol_value}";
	if [ "${symbol_name}" != "input" ]; then
		input=$(get_b64_symbol_value "input" "$SNIPPETS" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d | tr -d '\0');
		if [ "$input" == "" ]; then
			error "failed to recover the input: symbol_name=$symbol_name; snip=\n$SNIPPETS";
		fi;
	fi;
	if [ "${symbol_name}" != "input" -a "${input}" == "base64" ]; then
		data_bytes="$(echo -ne "${symbol_value}")"; # with NULL Suffix
	else
		data_bytes="$(echo -ne "${symbol_value}" | base64 -w0)";
	fi;
	if [ "$symbol_name" != input ] && echo "${input[@]}" | grep -q "evaluate"; then
		#TODO detect eval type. if all operations are static, and not call or jump is used(between the definition and evaluation).
		eval_type="static";
		if [ "${eval_type}" == "static" ]; then
			# then we can just evaluate the expression.
			echo -n "$(( $( echo $( echo "${data_bytes}" | base64 -d ) ) ))"
			return
		fi
	# else, we need to set it as a runtime expression
	# any jump or call after this can change this behavior.
	# then all code that uses jump or call should validate and update this.
		echo -n "$(( data_bytes ))"
		return
	fi;

	echo -n "${data_bytes}"
}

is_a_valid_number_on_base(){
	SNIPPETS=$2
	base=$(get_b64_symbol_value "base" "${SNIPPETS}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d);
	echo -n "$(( ${base:10}#${raw_data_bytes} ))" 2>&1 >/dev/null || 
		return 1;
	echo "${base:10}"
	return;
}

parse_data_bytes()
{
	local raw_data_bytes="$1";
	local SNIPPETS="$2";
	if [ "${raw_data_bytes:0:1}" == "'" ]; then
		echo -n "${raw_data_bytes}" | base64 -w0;
		return;
	fi;
	if [ "${raw_data_bytes:0:1}" == '"' ]; then
		#TODO: replace variables
		echo -n "${raw_data_bytes}" | base64 -w0;
		return;
	fi;
	local based_value=$(is_a_valid_number_on_base "${raw_data_bytes}" "${SNIPPETS}")
	if [ "$?" == 0 ] ; then
		#convert to base 10;
		#TODO detect the current base
		base=16
		echo -n "${based_value}" | base64 -d;
		return
	fi;
	# TODO detect the current base set and validate if the given data is a valid number on that base
	if [ "${raw_data_bytes:0:2}" ]; then
		echo -n "${raw_data_bytes}" | base64 -w0;
		return;
	fi;
	if ! { echo "${raw_data_bytes}" | base64 -d 2>&1 >/dev/null; }; then
		echo "${raw_data_bytes}" | base64 -w0
		return;
	fi
	echo -n "${raw_data_bytes}"
}

is_hard_coded_value()
{
	local NO_ERR=0;
	local ERR=1;
	# TODO: implement a better way this one just work for numbers
	local v="$(echo "$1" | base64 -d)";
	local symbol_name="$2";
	if [ "$v" == "" ];then
		return $NO_ERR;
	fi;
	if [ "${symbol_name}" == "input" ]; then
		return $NO_ERR;
	fi;
	if is_valid_number "$v"; then
		return $NO_ERR;
	fi;
	return $ERR;
}

get_symbol_type()
{
	local symbol_name="$1";
	local SNIPPETS="$2";
	local symbol_data=$(get_b64_symbol_value "${symbol_name}" "${SNIPPETS}" )
	echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE};
}

is_dynamic_snippet()
{
	local l="$1";
	local snip_data_wc=$(echo "${l}" | cut -d, -f$SNIPPET_COLUMN_DATA_BYTES | base64 -d | wc -c);
	local snip_data_len=$(echo "${l}" | cut -d, -f$SNIPPET_COLUMN_DATA_LEN );
	if [ "$snip_data_wc" -lt "$snip_data_len" ]; then
		return 0;
	fi
	return 1;
}

# returns the bytes used in elf by the static data section,
# it ignores the implict "hard coded" values like numbers that does not uses data space
get_static_data_size()
{
	local SNIPPETS="$1";
	local static_data_size=$(
		echo "$SNIPPETS" | while read l;
		do
			if [ "${l}" == "" ]; then
				continue;
			fi;
			local snip_data_len=$(echo "${l}" | cut -d, -f$SNIPPET_COLUMN_DATA_LEN);
			if [ "${snip_data_len:=0}" -gt 0 ]; then
				if is_static_data_snippet "${l}"; then
					echo $snip_data_len;
				fi;
			fi;
		done | awk '{s+=$1}END{print s}';
	)
	local static_data_count=$(count_static_data "$SNIPPETS");
	if [ "${static_data_count:=0}" -gt 0 ]; then
	{
		static_data_size=$((static_data_size+static_data_count));
	}
	fi;
	echo ${static_data_size:=0}
}

get_dynamic_data_size()
{
	local SNIPPETS="$1";
	local dyn_data_size=$(
		echo "$SNIPPETS" | while read l;
		do
			if [ "${l}" == "" ]; then
				continue;
			fi;
			local snip_data_len=$(echo "${l}" | cut -d, -f$SNIPPET_COLUMN_DATA_LEN);
			if [ "${snip_data_len:=0}" -gt 0 ]; then
				if is_dynamic_snippet "${l}"; then
					echo $snip_data_len;
				fi;
			fi;
		done | awk '{s+=$1}END{print s}';
	)
	echo ${dyn_data_size:=0}
}

get_snippets_until_line()
{
	local line="$1";
	local SNIPPETS="$2";
	echo "$SNIPPETS" | while read l;
	do 
		item=$(echo "$l" | cut -d, -f$SNIPPET_COLUMN_SOURCE_CODE);
		if [ "$item" == "$symbol_name" ]; then
			break;
		fi;
		echo "$l";
	done;
}
get_snippets_until_symbol()
{
	local symbol_name="$1";
	local SNIPPETS="$2";
	echo "$SNIPPETS" | while read l;
	do 
		item=$(echo "$l" | cut -d, -f$SNIPPET_COLUMN_SUBNAME);
		if [ "$item" == "$symbol_name" ]; then
			break;
		fi;
		echo "$l";
	done;
}

is_static_data_snippet()
{
	local snip="$1";
	local snip_type=$(echo "$snip" | cut -d, -f"$SNIPPET_COLUMN_TYPE");
	if [ "$snip_type" != SYMBOL_TABLE ]; then
		return 1;
	fi
	local snip_data_bytes=$(echo "$snip" | cut -d, -f "$SNIPPET_COLUMN_DATA_BYTES");
	if is_hard_coded_value "${snip_data_bytes}"; then
		return 1;
	fi;
	local snip_data_size=$(echo "$snip" | cut -d, -f"$SNIPPET_COLUMN_DATA_LEN");
	if [ "$snip_data_size" != "$(echo "$snip_data_bytes" | base64 -d | wc -c)" ]; then
		return 1;
	fi;
	return 0;
}

count_static_data()
{
	local snippets="$1";
	local static_data_count=$(
		echo "$snippets" | while read l;
		do
			if [ "${l}" == "" ]; then
				continue;
			fi;
			local snip_data_len=$(echo "${l}" | cut -d, -f$SNIPPET_COLUMN_DATA_LEN);
			if [ "${snip_data_len:=0}" -gt 0 ]; then
				if is_static_data_snippet "${l}"; then
					echo 1;
				fi;
			fi;
		done | awk '{s+=$1}END{print s}';
	)
	echo ${static_data_count:=0}
}

get_current_static_data_displacement()
{
	local snippets="$1";
	local current_line="$2";
	local SNIPPETS="$(get_snippets_until_line "$current_line" "$snippets")";
	local static_data_offset=$(get_static_data_size "$SNIPPETS");
	echo -n "$static_data_offset";
}

get_current_dynamic_data_offset()
{
	local snippets="$1";
	local current_line="$2";
	local SNIPPETS="$(get_snippets_until_line "$current_line" "$snippets")";
	get_dynamic_data_size "$SNIPPETS"
}

get_sym_dyn_data_size()
{
	local symbol_name="$1";
	local SNIPPETS="$(get_snippets_until_symbol "$symbol_name" "$2")";
	get_dynamic_data_size "$SNIPPETS"
}

is_valid_hex()
{
	local v="$1";
	if [[ "$v" =~ ^[a-fA-F0-9]+$ ]]; then
		return 0;
	fi
	return 1;
}

define_variable_increment()
{
	local third_arg_idx=$((2 + deep-1));
	local last_arg_idx="${#code_line_elements[@]}";
	local symbol_id="";
	local symbol_data="";
	local symbol_value="";
	local instr_bytes="";
	for ((i=third_arg_idx; i<last_arg_idx; i++)); do
		symbol_id="${code_line_elements[$(( 2 + deep-1 ))]}";
		symbol_data=$(get_b64_symbol_value "${symbol_id}" "${SNIPPETS}")
		symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
		symbol_value=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d);
		instr_bytes="${instr_bytes}$(set_increment $dyn_data_offset $symbol_value)";
	done
	local instr_len="$(echo "${instr_bytes}" | base64 -d | wc -c)";
	local data_bytes="";
	local data_len="8";
	struct_parsed_snippet \
		"SYMBOL_TABLE" \
		"${symbol_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${dyn_data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"${CODE_LINE_B64}" \
		"1";
	return $?;
}

define_variable_arg()
{
	local arg_number="${sec_arg/@/}"
	# create a new dynamic symbol called ${symbol_name}
	local instr_bytes="$(get_arg $dyn_data_offset $arg_number)";
	local instr_len=$(echo -n "${instr_bytes}" | base64 -d | wc -c );
	# this address will receive the point to the arg variable set in rsp currently;
	# a better solution would be not have this space in binary but in memory.
	# but it is good enough for now. because we don't really have a dynamic memory now
	local data_bytes="";
	data_len="8"; # pointer size
	struct_parsed_snippet \
		"SYMBOL_TABLE" \
		"${symbol_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${dyn_data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"${CODE_LINE_B64}" \
		"1";
	return $?;
}

define_variable_read_from_file()
{
	local file_name="${code_line_elements[$(( 2 + deep-1 ))]}";
	local symbol_data=$(get_b64_symbol_value "${file_name}" "${SNIPPETS}")
	# sys_open will create a new file descriptor.
	local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	# TODO use a better place this is an insecure way, because on this page
	# we have all code, so we can rewrite it.
	local ptr_data_size=8;
	local stat_addr=$(( dyn_data_offset + ptr_data_size ));
	local stat_struct_size=144;
	if [ "${symbol_type}" != "${SYMBOL_TYPE_STATIC}" ]; then
		data_bytes="";
		data_bytes_len=0; # no data to append. just registers used.
		sym_dyn_data_size=$(get_sym_dyn_data_size "${input_symbol_name}" "${SNIPPETS}")
		data_addr_v="$(( dyn_data_offset ))";
		data_offset="${dyn_data_offset}";
	else
		data_offset="${static_data_offset}";
	fi;
	local filename_addr=$(get_symbol_addr "${file_name}" "$SNIPPETS")
	# Reading file involve some steps.
	# 1. Opening the file, if succeed, we have a file descriptor
	#    in success the rax will have the fd
	local open_code="$(system_call_open "${filename_addr}")";
	# 2. fstat that fd, so we have the information on data size, to allocate properly the memory.
	# TODO guarantee a valid writable memory location
	local fstat_code="$(sys_fstat "${stat_addr}")";
	# 	To do this we need to have some memory space to set the stat data struct.
	# 	TODO decide if we should mmap every time, or have a program buffer to use.
	# 3.a. in normal files, allocate memory with mmap using the fd.
	local mmap_code="";
	# 3.b. in case of virtual file like pipes or nodes(/proc/...) we can't map directly, but we still need to have a memory space to read the data in, so the fstat is still necessary. We should then use the sys_read to copy the data into memory.
	# 4. So we can access the data directly using memory addresses.
	local read_code="$(read_file "${symbol_type}" "${stat_addr}" "${data_offset}")"
	# it should return the bytecode, the size
	#fd="$(set_symbol_value "${symbol_value} fd" "${SYS_OPEN}")";
	# We should create a new dynamic symbol to have the file descriptor number
	#CODE="${CODE}$(sys_read $)"
	instr_bytes="${open_code}${fstat_code}${mmap_code}${read_code}"
	instr_len=$(echo -n "${instr_bytes}" | base64 -d | wc -c )
	data_bytes="";
	data_len="$(( stat_struct_size + ptr_data_size ))"; # Dynamic length, only at runtime we can know so give it the pointer size
	struct_parsed_snippet \
		"SYMBOL_TABLE" \
		"${symbol_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"${CODE_LINE_B64}" \
		"1" \
		"0" \
		"RAX"; #TODO: this is should set the register where the write call should look at data address. and it should be a variable, because this breaks cross arch(aarch does not have RAX).
	return $?;
}

define_variable_from_exec()
{
	local cmd="$(echo -n "${code_line_elements[$(( 2 + deep-1 ))]}")"
	# TODO for now positional args are good enough, but a better way is to have named args and env as an array or map each;
	local args=( );
	local static_map=( );
	for (( i=$((deep + 1)); i<$(( ${#code_line_elements[@]} + deep-1 )); i++ ));
	do {
		local arg_id="${code_line_elements[$i]}";
		local arg_snippet="$( echo "$SNIPPETS" | grep "SYMBOL_TABLE,${arg_id}," )";
		local arg_addr="$(echo "$arg_snippet" | cut -d, -f${SNIPPET_COLUMN_DATA_OFFSET} )";
		local arg_is_static=0;
		if is_static_data_snippet "${arg_snippet}"; then
			# if arg is static, the call is different because we pass the address to the string itself
			# instead of the address of the pointer to the string we have when it is dynamic
			# I've choose doing this way because we do less instructions as we don't need to allocate additional
			# bytes to create a pointer to the static string, we can just set the address to the register.
			arg_is_static=1;
		fi;
		args[$((i-deep))]="$arg_addr";
		static_map[$((i-deep))]=$arg_is_static;
	};
	done;
	local data_bytes="";
	local env=(); # memory address to the env
	local pipe_struct_size=8; # 2 int array; int 4 bytes each
	local pipe_buffer_size=$((16#100));# 256;
	local ptr_to_buffer_size=8; # reserve the first 8 bytes to a pointer to the buffer data (currently 8 bytes ahead), so the concat code will not break trying to resolve a pointer
	local pipe_buffer_addr=$(( dyn_data_offset + ptr_to_buffer_size ));
	local pipe_addr=$(( pipe_buffer_addr + pipe_buffer_size ))
	local args_addr="$(( pipe_addr + pipe_struct_size ))"; # the array address
	local args_size=$(( 8 * ${#args[@]} + 8 )) # 8 to cmd, 8 for each argument and 8 to null to close the array
	local env_addr=$(( args_addr + args_size ));
	local env_size=8; 
	env_size=0;
	env_addr=0; # no support for env, set NULL
	local argsparam="${args[@]}";
	local staticmapparam="${static_map[@]}";
	local data_len=$(( ptr_to_buffer_size + pipe_buffer_size + pipe_struct_size + args_size + env_size ));
	local exec_result="$(system_call_exec "${args_addr}" "${argsparam}" "${staticmapparam}" "${env_addr}" "${pipe_addr}" "${pipe_buffer_addr}" "${pipe_buffer_size}")";
	instr_bytes="$(echo "${exec_result}" | cut -d, -f1)";
	instr_len="$(echo "${exec_result}" | cut -d, -f2)";
	struct_parsed_snippet \
		"SYMBOL_TABLE" \
		"${symbol_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${dyn_data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"${CODE_LINE_B64}" \
		"1";
	return $?;
}

define_concat_variable(){
	local dyn_args=0;
	local static_value="";
	local instr_bytes="";
	local data_addr=""; # target concatenated data_addr
	for (( i=$((deep)); i<${#code_line_elements[@]}; i++ ));
	do
		local symbol_name=$(echo -n "${code_line_elements[$(( i - deep+1 ))]}");
		local symbol_data=$(get_b64_symbol_value "${symbol_name}" "${SNIPPETS}" )
		local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
		local symbol_value=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT});
		local symbol_addr="$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR})";
		local symbol_len="$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_SIZE})";
		local sym_dyn_data_size=$(get_sym_dyn_data_size "${symbol_name}" "${SNIPPETS}")
		if [ "${symbol_type}" == "${SYMBOL_TYPE_STATIC}" ]; then
			static_value="$( echo "${static_value}${symbol_value}" | base64 -d | base64 -w0 )";
			instr_bytes="${instr_bytes}$(concat_symbol_instr "${symbol_addr}" "${dyn_data_offset}" "${symbol_len}" "$i")";
		else
			dyn_args="$(( dyn_args + 1 ))";
			sym_dyn_data_size=$(get_sym_dyn_data_size "${symbol_name}" "${SNIPPETS}")
			instr_bytes="${instr_bytes}$(concat_symbol_instr "$(( symbol_addr ))" "${dyn_data_offset}" "-1" "$i")";
		fi;
	done;
	# if all arguments are static, we can merge them at build time
	local symbol_name=$(echo -n "${code_line_elements[$(( 0 + deep-1 ))]}" | cut -d: -f1);
	if [ "${dyn_args}" -eq 0 ]; then
	{
		local instr_bytes="";
		local instr_len=0;
		local data_bytes="${static_value}";
		local data_len=$(echo -n "$data_bytes" | base64 -d | wc -c);
		struct_parsed_snippet \
			"SYMBOL_TABLE" \
			"${symbol_name}" \
			"${instr_offset}" \
			"${instr_bytes}" \
			"${instr_len}" \
			"${static_data_offset}" \
			"${data_bytes}" \
			"${data_len}" \
			"${CODE_LINE_B64}" \
			"1";
		return $?
	}
	fi;
	# if at least one are dynamic we need to set instructions
	local instr_len=$(echo -n "$instr_bytes" | base64 -d | wc -c);
	local data_bytes="";
	local data_len=8;
	struct_parsed_snippet \
		"SYMBOL_TABLE" \
		"${symbol_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${dyn_data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"${CODE_LINE_B64}" \
		"1";
	return $?;
}

define_variable_from_test()
{
	#   defines a new symbol based on a boolean condition
	local field_a="${code_line_elements[$(( 2 + deep-1 ))]}";
	local field_data_a=$(get_b64_symbol_value "${field_a}" "${SNIPPETS}")
	local field_a_addr=$(echo "$field_data_a" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR})
	local field_type_a=$(echo "${field_data_a}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	local field_a_v=$(echo "${field_data_a}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d)
	local field_b="${code_line_elements[$(( 3 + deep-1 ))]}";
	local field_data_b=$(get_b64_symbol_value "${field_b}" "${SNIPPETS}");
	local field_b_addr=$(echo "$field_data_b" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR})
	local field_type_b=$(echo "${field_data_b}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
	local field_b_v=$(echo "${field_data_b}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d)
	local instr_bytes=$(compare "${field_a_v:=0}" "${field_b_v:=0}" "$field_type_a" "$field_type_b")
	local instr_len=$(echo "$instr_bytes" | base64 -d | wc -c);
	local data_bytes="";
	local data_len=0;
	struct_parsed_snippet \
		"SYMBOL_TABLE" \
		"${symbol_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${static_data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"${CODE_LINE_B64}" \
		"1";
	return $?;
}

define_array_variable(){
	local instr_bytes="";
	for (( i=$((deep + 1)); i<${#code_line_elements[@]}; i++ ));
	do
		local symbol_name=$(echo -n "${code_line_elements[$(( i - deep+1 ))]}");
		local symbol_data=$(get_b64_symbol_value "${symbol_name}" "${SNIPPETS}" )
		local symbol_addr="$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR})";
		local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
		local symbol_value=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} |base64 -d);
		if [ "${symbol_type}" == $SYMBOL_TYPE_PROCEDURE ]; then
			# TODO detect the jump size
			local jump_size=2; # instruction length of the jump over before the code
			symbol_addr=$(( symbol_addr + jump_size ));
		fi;
		instr_bytes="${instr_bytes}$(array_add "${dyn_data_offset}" "$((i-deep-1))" "${symbol_addr}" "$symbol_type" "$symbol_value")";
	done;
	local array_size=$(( ${#code_line_elements[@]} - (deep + 1) ));
	instr_bytes="${instr_bytes}$(array_end "${dyn_data_offset}" "$array_size")";
	local symbol_name=$(echo -n "${code_line_elements[$(( 0 + deep-1 ))]}" | cut -d: -f1);
	local instr_len=$(echo -n "$instr_bytes" | base64 -d | wc -c);
	local data_bytes="";
	local data_len=$(( array_size * 8 ));
	struct_parsed_snippet \
		"SYMBOL_TABLE" \
		"${symbol_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${dyn_data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"${CODE_LINE_B64}" \
		"1";
	return $?;
}

define_variable(){
	# All variables, constants, macros are symbols and should be managed by a symbol table
	# It should have name type, scope and memory address
	# The compiler should updated that items in the first code read
	#
	# Constants should replace the code value before process the code.
	# Constants should not keep in memory, instead should replace the value hardcoded in bytecode.
	# Variables should recover the target address and size at runtime.
	# A variable and constant are defined at the same way. The compiler should consider everything as constant.
	# Once the code changes the variable value, it will be converted to variable.
	# So if a variable is never changed, it will be always a constant hardcoded at the bytecode;
	local symbol_name="$( echo -n "${code_line_elements[$(( 0 + deep-1 ))]/:*/}" )"
	#local symbol_name="$(echo -n "${symbol_name/:*/}")";
	local sec_arg="$(echo -n "${code_line_elements[$(( 1 + deep-1 ))]}")"
	local symbol_data="$(echo "$SNIPPETS" | grep "SYMBOL_TABLE,${symbol_name}," | tail -1)";
	local is_new_symbol=0;
	if [ "${symbol_data}" == "" ]; then 
	{
		is_new_symbol="1";
	}
	fi;
	if [ "$sec_arg" == "?" ]; then # define a test
	{
		define_variable_from_test
		return $?
	}
	fi;
	if [[ "${sec_arg}" =~ \<=$ ]]; then # read from file into var
	{
		define_variable_read_from_file
		return $?
	}
	fi;
	if [ "$sec_arg" == "+" ]; then # increment a variable
	{
		define_variable_increment
		return $?
	}
	fi;
	if [[ "$sec_arg" =~ ^@[0-9]*$ ]]; then # capture the argument into variable
	{
		define_variable_arg
		return $?
	}
	fi
	if [[ "$sec_arg" =~ ^@[$]$ ]]; then # capture the argument count into variable
	{
		# create a new dynamic symbol called ${symbol_name}
		# That should point to the rbp register first 8 bytes (int)
		# argc_addr: memory address to put the argc 
		#   should i use the snippets data?
		argc_pos=$dyn_data_offset;
		instr_bytes="$(get_arg_count $argc_pos)"
		instr_len=$(echo -n "${instr_bytes}" | base64 -d | wc -c )
		data_bytes="";
		data_len="8"; # pointer size
		struct_parsed_snippet \
			"SYMBOL_TABLE" \
			"${symbol_name}" \
			"${instr_offset}" \
			"${instr_bytes}" \
			"${instr_len}" \
			"${dyn_data_offset}" \
			"${data_bytes}" \
			"${data_len}" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	}
	fi;
	if [ "$sec_arg" == "!" ]; then # exec and capture output into variable
	{
		# TODO: if the first array position is a function
		local array_symbol="${code_line_elements[$((2 + deep - 1))]}";
		if is_function $array_symbol; then
			define_variable_from_fn;
		else
			define_variable_from_exec;
		fi;
		return $?;
	}
	fi;
	if [ "$sec_arg" == "[]" ]; then # exec and capture output into variable
	{
		define_array_variable;
		return $?;
	}
	fi;
	if [ "${#code_line_elements[@]}" == "$(( 2 + deep - 1 ))" ]; then
	{
		# New symbol
		symbol_value="$( echo -n "${CODE_LINE/*:	/}" )";
		instr_bytes="";
		instr_len=0;
		data_bytes="$(set_symbol_value "${symbol_value}" "${SNIPPETS}")";
		data_len="$( echo -n "${data_bytes}" | base64 -d | wc -c)";
		if is_hard_coded_value "${data_bytes}" "${symbol_name}"; then
			data_len=0; # hard-coded values does not use data space
		fi;
		# if this is not the first static variable, we need to append 1 to the static_data_offset,
		# because it should be an \x00(null byte) between static data.
		struct_parsed_snippet \
			"SYMBOL_TABLE" \
			"${symbol_name}" \
			"${instr_offset}" \
			"${instr_bytes}" \
			"${instr_len}" \
			"${static_data_offset}" \
			"${data_bytes}" \
			"${data_len}" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	}
	fi;
	# concat all symbols in a new one
	define_concat_variable
	return $?;
}

parse_code_bloc_instr(){
	local symbol_name='_init_';
	local instr_bytes=$(init_bloc);
	local instr_len=$(echo $instr_bytes | base64 -d | wc -c);
	local data_bytes="";
	local data_len=0;
	struct_parsed_snippet \
		"INSTRUCTION" \
		"${symbol_name}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${dyn_data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"" \
		"0";
	instr_offset=$(( instr_offset + instr_len ));
	bloc_inner_code="$(
		echo "${code_bloc}" |
		awk 'NR>2 {print prev}; {prev=$0};' |
		base64 -w0
	)";
	local insideSnips="";
	echo "${bloc_inner_code}" |
		base64 -d | while read l; do
			local parsedLine=$(echo -n "$l" | parse_snippets "${ROUND}" "${PH_VADDR_V}" "${INSTR_TOTAL_SIZE}" "${static_data_size}" "$(echo -e "$SNIPPETS\n${insideSnips}")" "$deep")
			insideSnips=$(echo -en "${insideSnips}\n${parsedLine}")
			echo "${parsedLine}"
		done;
}

parse_code_bloc(){
	local instr_bytes="";
	SNIPPET_NAME="$(echo "${CODE_LINE}" |cut -d: -f1 | tr -d '\t')";
	code_bloc="$(echo "${CODE_LINE}"; read_code_bloc "${deep}")";
	bloc_outer_code_b64="$(echo -n "${code_bloc}" | base64 -w0 )";
	recursive_parse=$(parse_code_bloc_instr);
	instr_bytes=$(echo "$recursive_parse"  |
		cut -d, -f$SNIPPET_COLUMN_INSTR_BYTES
	);
	local innerlines="$(echo "$recursive_parse"  |
		cut -d, -f$SNIPPET_COLUMN_SOURCE_LINES_COUNT |
		awk '{s+=$1}END{print s}'
	)";
	local bloc_source_lines_count=$(( innerlines +2 ))
	local instr_size_sum="$( echo "${instr_bytes}" |
		base64 -d | wc -c |
		awk '{s+=$1}END{print s}';
	)";
	local jump_bytecode_len=0; # jump is a dynamic instr, it can change size based on how far is the target.
	# so we will try until it stop changing the instr size.
	local current_addr=$((PH_VADDR_V + INSTR_TOTAL_SIZE));
	local target_addr=$((current_addr + jump_bytecode_len + instr_size_sum));
	local jump_bytecode="";
	target_addr=$((current_addr + instr_size_sum));
	jump_bytecode=$(jump "$target_addr" "$current_addr");
	jump_bytecode_len=$(echo $jump_bytecode | base64 -d| wc -c);
	instr_offset=$(( instr_offset + jump_bytecode_len ));
	recursive_parse=$(parse_code_bloc_instr); # parse again with the correct instruction displacement
	instr_bytes=$(echo "$recursive_parse"  |
		cut -d, -f$SNIPPET_COLUMN_INSTR_BYTES
	);
	instr_offset=$(( instr_offset - jump_bytecode_len )); # revert the position because the jump have to be at snippet instr.
	instr_size_sum=$((instr_size_sum + jump_bytecode_len));
	instr_bytes="${jump_bytecode}${instr_bytes}";
	local data_bytes="$(echo "$recursive_parse"  |
		cut -d, -f$SNIPPET_COLUMN_DATA_BYTES )"
	local data_bytes_sum="$( echo "${data_bytes}" |
		base64 -d | wc -c |
		awk '{s+=$1}END{print s}'
	)";
	out="$(struct_parsed_snippet \
		"PROCEDURE_TABLE" \
		"${SNIPPET_NAME}" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_size_sum}" \
		"${static_data_offset}" \
		"${data_bytes}" \
		"${data_bytes_sum}" \
		"${bloc_outer_code_b64}" \
		"${bloc_source_lines_count}";
	)";
	echo "$out";
}

define_code_block(){
	# TODO add identation validation
	#
	# TODO prepend a jump move over the end of this block, so this code will be executed only if a explicit goto or call is requested. 
	new_bloc="$(parse_code_bloc)";
	local bloc_name=$(echo "$new_bloc" | cut -d, -f${SNIPPET_COLUMN_SUBNAME})
	if [ "$SNIPPETS" == "" ]; then
		SNIPPETS="$( echo "$new_bloc")";
	else
		SNIPPETS="$( echo -e "$SNIPPETS\n$new_bloc")";
	fi;
	echo "$new_bloc";
}

conditional_call(){
	local test_symbol_name="${code_line_elements[$(( 0 + deep-1 ))]}";
	local target="${code_line_elements[$(( 2 + deep-1 ))]}"
	local target_offset="$( echo "$SNIPPETS" | grep "PROCEDURE_TABLE,${target}," | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET} )";
	local arguments=(); # TODO implement args
	local arguments_map=();
	# TODO jump or call ?
	local instr_bytes="$(jump_if_equal "$(( target_offset + 2 - (deep-1) * 2 ))" "${instr_offset}" "${arguments}" "${arguments_map}" )"; # 2 is the jump instr expected to be at the snip first instr, each deep level have 2 bytes for the instr call
	local instr_len="$(echo "${instr_bytes}" | base64 -d | wc -c)";
	local data_bytes="";
	local data_len=0;
	struct_parsed_snippet \
		"SNIPPET_CALL" \
		"je" \
		"${instr_offset}" \
		"${instr_bytes}" \
		"${instr_len}" \
		"${static_data_offset}" \
		"${data_bytes}" \
		"${data_len}" \
		"${CODE_LINE_B64}" \
		"1";
}

get_instr_offset()
{
	local previous_snippet="$1";
	local previous_instr_offset=$(echo "${previous_snippet}" | cut -d, -f$SNIPPET_COLUMN_INSTR_OFFSET);
	previous_instr_offset="${previous_instr_offset:=$((PH_VADDR_V + EH_SIZE + PH_SIZE))}"
	local previous_instr_sum=$(echo "${previous_snippet}" | cut -d, -f$SNIPPET_COLUMN_INSTR_LEN);
	local instr_offset="$(( ${previous_instr_offset} + previous_instr_sum ))";
	echo -n "${instr_offset}";
}
# parse_snippet given a source code snippet echoes snippet struct to stdout
# allowing a pipeline to read a full instruction or bloc at time;
# it should return a code snippet
parse_snippet()
{
	local ROUND="$1";
	local PH_VADDR_V="$2";
	local INSTR_TOTAL_SIZE="$3";
	local static_data_size="$4"; # full static data length
	local CODE_LINE="$5";
	local SNIPPETS="$6";
	local deep="$7";

	# Bash imposes a threat here. The array parse syntax ( ${CODE_LINE} ) loses spaces.
	# to overcome that I need to write a hack
	local code_line_elements;# =( ${CODE_LINE} );
	# array hack: because ( ${CODE_LINE} ) will trim spaces.
	eval "code_line_elements=( $(echo "${CODE_LINE}" | tr '\t' '\n' | sed 's/^\(.*\)$/"\1"/g') )";
	local CODE_LINE_XXD="$( echo -n "${CODE_LINE}" | xxd --ps)";
	local CODE_LINE_B64=$( echo -n "${CODE_LINE}" | base64 -w0);
	local previous_snippet=$( echo "${SNIPPETS}" | tail -1 );
	local instr_offset=$(get_instr_offset "${previous_snippet}");
	local dyn_data_size=$(get_dynamic_data_size "$SNIPPETS");
	local zero_data_offset=$(( PH_VADDR_V + EH_SIZE + PH_SIZE + INSTR_TOTAL_SIZE ));
	local dynamic_data_offset=$(get_current_dynamic_data_offset "${SNIPPETS}" "${CODE_LINE_B64}")
	local static_data_displacement=$(get_current_static_data_displacement "${SNIPPETS}" "${CODE_LINE_B64}")
	local current_static_data_address=$((zero_data_offset + static_data_displacement))
	local static_data_offset=$current_static_data_address
	local dyn_data_offset="$(( zero_data_offset + static_data_size + dynamic_data_offset))";
	if [ "$CODE_LINE" == "" ]; then
	{
		struct_parsed_snippet \
			"EMPTY" \
			"" \
			"${instr_offset}" \
			"" \
			"0" \
			"${statc_data_offset}" \
			"" \
			"0" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	}
	fi;
	if [[ "${code_line_elements[$(( 0 + deep-1 ))]}" =~ ^[#] ]]; then # ignoring tabs, starts with pound symbol(#)
	{
		struct_parsed_snippet \
			"COMMENT" \
			"" \
			"${instr_offset}" \
			"" \
			"0" \
			"${static_data_offset}" \
			"" \
			"0" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	}
	fi;
	if [[ "${code_line_elements[$(( 1 + deep-1 ))]}" =~ [?][=]$ ]]; then # conditional call
		conditional_call
		return $?;
	fi;
	if [[ "${code_line_elements[$(( 0 + deep-1 ))]}" =~ :$ ]]; then
	{
		if [[ "${CODE_LINE_XXD}" =~ .*3a097b$ ]]; then # check if ends with ":\t{" ... so it's a code block function
		{
			define_code_block
			return $?;
		}
		fi;
		define_variable
		return $?
	}
	fi;
	if [[ "${code_line_elements[$(( 0 + deep-1 ))]}" == write ]]; then
	{
		local WRITE_OUTPUT_ELEM=1;
		local WRITE_DATA_ELEM=2;
		local input_symbol_name="${code_line_elements[$(( WRITE_DATA_ELEM + deep-1 ))]}";
		local out=${code_line_elements[$(( WRITE_OUTPUT_ELEM + deep-1 ))]};
		# expected: STDOUT, STDERR, FD...
		local data_output=$(get_b64_symbol_value "${out}" "${SNIPPETS}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d | tr -d '\0' );
		# I think we can remove the parse_data_bytes and force the symbol have the data always
		local symbol_data=$(get_b64_symbol_value "${input_symbol_name}" "${SNIPPETS}" )
		local symbol_type=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_TYPE});
		local symbol_value=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT});
		local symbol_addr="$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR})";
		local data_bytes=$(echo -n "${symbol_value}"| cut -d, -f1);
		local data_bytes_len="$(echo -n "${symbol_data}"| cut -d, -f2)";
		local data_addr_v=$(echo "${symbol_data}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR});
		if [ "${symbol_type}" != "${SYMBOL_TYPE_STATIC}" ]; then
		{
			data_bytes_len=0; # no data to append. just registers used.
			if [ "${symbol_type}" == "${SYMBOL_TYPE_PROCEDURE}" ]; then
			{
				data_bytes="";
				local procedure_addr=$(echo "$symbol_data" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_ADDR});
				data_addr_v="${procedure_addr}"; # point to the procedure address
			}
			fi;
		}
		fi;
		# TODO: detect if using dyn data addr and pass it 
		local input_symbol_return="$( echo "$SNIPPETS" | grep "SYMBOL_TABLE,${input_symbol_name}," | cut -d, -f${SNIPPET_COLUMN_RETURN} )";
		if [ "${input_symbol_return}" != "" ]; then
			data_addr_v="${input_symbol_return}";
		elif [ "${data_addr_v}" != "" ]; then
			data_addr_v="$(( data_addr_v ))";
		else
			data_addr_v="$( echo ${symbol_value} | base64 -d)"
		fi;
		local instr_bytes="$(system_call_write "${symbol_type}" "${data_output}" "$data_addr_v" "$data_bytes_len" "${instr_offset}")";
		data_bytes="";
		data_bytes_len=0;
		#if [ "${symbol_type}" == "${SYMBOL_TYPE_HARD_CODED}" ]; then
		#	data_bytes_len=8; # actually we need to calculate how many bytes we need to print using the hardcoded value
		#fi;
		local instr_size="$(echo -e "$instr_bytes" | base64 -d | wc -c)";
		struct_parsed_snippet \
			"INSTRUCTION" \
			"sys_write" \
			"${instr_offset}" \
			"${instr_bytes}" \
			"${instr_size}" \
			"${dyn_data_offset}" \
			"${data_bytes}" \
			"${data_bytes_len}" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	}
	fi;
	if [[ "${code_line_elements[$(( 0 + deep-1 ))]}" == ret ]]; then
	{
		ret_value="${code_line_elements[$(( 1 + deep-1 ))]}"
		bytecode_return="$(bytecode_ret "${ret_value}")"
		instr_bytes="$(echo $bytecode_return | cut -d, -f1)"
		instr_size="$(echo $bytecode_return | cut -d, -f2)"
		struct_parsed_snippet \
			"INSTRUCTION" \
			"sys_ret" \
			"${instr_offset}" \
			"${instr_bytes}" \
			"${instr_size}" \
			"${static_data_offset}" \
			"" \
			"0" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	}
	fi;
	if [[ "${code_line_elements[$(( 0 + deep-1 ))]}" == exit ]]; then
	{
		local exit_value=$(get_b64_symbol_value "${code_line_elements[$(( 1 + deep-1 ))]}" "${SNIPPETS}" | cut -d, -f${B64_SYMBOL_VALUE_RETURN_OUT} | base64 -d | tr -d '\00' )

		local instr_bytes="$(system_call_exit ${exit_value})";
		instr_len=$(echo "${instr_bytes}" | base64 -d | wc -c);
		struct_parsed_snippet \
			"INSTRUCTION" \
			"sys_exit" \
			"${instr_offset}" \
			"${instr_bytes}" \
			"${instr_len}" \
			"${static_data_offset}" \
			"" \
			"0" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	}
	fi;
	if [[ "${code_line_elements[$(( 0 + deep-1 ))]}" == goto ]]; then
	{
		target="${code_line_elements[$(( 1 + deep-1 ))]}"
		target_offset="$( echo "$SNIPPETS" | grep "PROCEDURE_TABLE,${target}," | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET} )";
		jmp_result="$(jump "$((target_offset + 2))" "${instr_offset}" )";
		jmp_bytes="$(echo "${jmp_result}" | cut -d, -f1)";
		jmp_len="$(echo "${jmp_result}" | cut -d, -f2)";
		struct_parsed_snippet \
			"SNIPPET_CALL" \
			"jmp" \
			"${instr_offset}" \
			"${jmp_bytes}" \
			"${jmp_len}" \
			"${static_data_offset}" \
			"" \
			"0" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	}
	fi;
	if echo "$SNIPPETS" | grep -q "${code_line_elements[$(( 0 + deep-1 ))]}"; then # function calling
	{
		target="${code_line_elements[$(( 0 + deep-1 ))]}"
		target_offset="$( echo "$SNIPPETS" | grep "PROCEDURE_TABLE,${target}," | cut -d, -f${SNIPPET_COLUMN_INSTR_OFFSET} )";
		local jmp_size=2; # all procedures have a jmp instruction at begining. it can be 2 or 5 bytes. 2 if the procedure body is smaller than 128 bytes;
		local target_instr_size="$( echo "$SNIPPETS" | grep "PROCEDURE_TABLE,${target}," | cut -d, -f${SNIPPET_COLUMN_INSTR_LEN} )";
		if [ "${target_instr_size:=0}" -gt 127 ]; then 
			jmp_size=5;
		fi;
		local call_bytes="$(call_procedure "$((target_offset + jmp_size))" "${instr_offset}" )";
		local call_len="$(echo "${call_bytes}" | base64 -d | wc -c)";
		struct_parsed_snippet \
			"SNIPPET_CALL" \
			"call" \
			"${instr_offset}" \
			"${call_bytes}" \
			"${call_len}" \
			"${static_data_offset}" \
			"" \
			"0" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	}
	fi;
	if [[ "${code_line_elements[$(( 0 + deep-1 ))]}" == ! ]]; then
	{
		# TODO for now positional args are good enough, but the correct is to have args and env as an array each;
		local args=( );
		local static_map=( );
		for (( i=$deep; i<$(( ${#code_line_elements[@]} + deep-1 )); i++ ));
		do {
			local arg_id="${code_line_elements[$i]}";
			local arg_snippet="$( echo "$SNIPPETS" | grep "SYMBOL_TABLE,${arg_id}," )";
			local arg_addr="$(echo "$arg_snippet" | cut -d, -f${SNIPPET_COLUMN_DATA_OFFSET} )";
			local arg_is_static=0;
			if is_static_data_snippet "${arg_snippet}"; then
				# if arg is static, the call is different because we pass the address to the string itself
				# instead of the address of the pointer to the string we have when it is dynamic
				# I've choose doing this way because we do less instructions as we don't need to allocate additional
				# bytes to create a pointer to the static string, we can just set the address to the register.
				arg_is_static=1;
			fi;
			args[$((i-1))]="$arg_addr";
			static_map[$((i-1))]=$arg_is_static;
		};
		done;
		local data_bytes="";
		local env=(); # memory address to the env
		local args_addr="$(( dyn_data_offset ))"; # the array address
		local args_size=$(( 8 * ${#args[@]} + 8 )) # 8 to cmd, 8 for each argument and 8 to null to close the array
		local env_addr=$(( args_addr + args_size ));
		local env_size=8; 
		env_size=0;
		env_addr=0; # no support for env, set NULL
		local data_len=$(( args_size + env_size )); # 8 to each array (args and env)
		local argsparam="${args[@]}";
		local staticmapparam="${static_map[@]}";
		local exec_result="$(system_call_exec "${args_addr}" "${argsparam}" "${staticmapparam}" "${env_addr}")";
		instr_bytes="$(echo "${exec_result}" | cut -d, -f1)";
		instr_len="$(echo "${exec_result}" | cut -d, -f2)";
		struct_parsed_snippet \
			"INSTRUCTION" \
			"sys_execve" \
			"${instr_offset}" \
			"${instr_bytes}" \
			"${instr_len}" \
			"${static_data_offset}" \
			"${data_bytes}" \
			"${data_len}" \
			"${CODE_LINE_B64}" \
			"1";
		return $?;
	}
	fi;
	if is_valid_hex "${CODE_LINE}"; then
	{
		local instr_bytes="$(echo ${CODE_LINE} | xxd --ps -r | base64 -w0)";
		instr_len="$(echo "${instr_bytes}" | base64 -d | wc -c)";
		local data_bytes="";
		local data_len="";
		struct_parsed_snippet \
			"INSTRUCTION" \
			"bytecode" \
			"${instr_offset}" \
			"${instr_bytes}" \
			"${instr_len}" \
			"${static_data_offset}" \
			"${data_bytes}" \
			"${data_len}" \
			"${CODE_LINE_B64}" \
			"1";
		return $?
	}
	fi;
	error "invalid code line instruction: [$CODE_LINE_B64][${code_line_elements[$(( 0 + deep-1 ))]}]";
	struct_parsed_snippet \
		"INVALID" \
		"" \
		"${instr_offset}" \
		"" \
		"0" \
		"${static_data_offset}" \
		"" \
		"0" \
		"${CODE_LINE_B64}" \
		"1";
	return $?;
}

# should return multiple struct_parsed_snippet output (one per line)
parse_snippets()
{
	local ROUND="$1";
	local PH_VADDR_V="$2";
	local INSTR_TOTAL_SIZE="$3";
	local static_data_size="$4"
	local SNIPPETS="$5"; # cummulative to allow cross reference between snippets
	local deep="${6-0}";
	local CODE_INPUT=$(cat);
	let deep++;
	local instr_offset="0"
	local static_data_offset=0;
	struct_parsed_snippet \
		"INSTRUCTION" \
		"_before_" \
		"${instr_offset}" \
		"" \
		"0" \
		"${static_data_offset}" \
		"" \
		"0" \
		"" \
		"0";
	IFS='';
	echo "${CODE_INPUT}" | while read CODE_LINE;
	do
		RESULT=$(parse_snippet "${ROUND}" "${PH_VADDR_V}" "${INSTR_TOTAL_SIZE}" "${static_data_size}" "${CODE_LINE}" "${SNIPPETS}" "${deep}");
		if [ "${#SNIPPETS}" -gt 0 ]; then
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

# detect_instruction_size_from_code should return the bytes used by the instructions code bloc.
# That includes NONE OF the data section (string table, the elf and program headers
detect_instruction_size_from_code()
{
	cat $1 | grep -E "^(INSTRUCTION|SNIPPET_CALL|SYMBOL_TABLE|PROCEDURE_TABLE)," |
	cut -d, -f${SNIPPET_COLUMN_INSTR_LEN} |
	awk '{s+=$1}END{print s}'
}

detect_static_data_size_from_code()
{
	local static_data_size=$(
		cat $1 | while read l;
		do
			if [ "${l}" == "" ]; then
				continue;
			fi;
			local snip_data_len=$(echo "${l}" | cut -d, -f$SNIPPET_COLUMN_DATA_LEN);
			if [ "${snip_data_len:=0}" -gt 0 ]; then
				if is_static_data_snippet "${l}"; then
					echo ${snip_data_len:=0};
					echo 1; # add 1 to the \x00 null byte between the static data
					c=$((c+1));
				fi;
			fi;
		done | awk '{s+=$1}END{print s}';
	)
	echo ${static_data_size:=0}
}

# Round exists because parse_snippets can only trust addresses in final round.
# We can use it to get control of address changes like to detect the args memory spot
ROUND_FIRST=1
ROUND_FINAL=2
write_elf()
{
	local ELF_FILE_OUTPUT="$1";
	# Virtual Memory Offset
	local PH_VADDR_V=$(./ph_vaddr_v)
	if [ "$PH_VADDR_V" == "" ]; then
		PH_VADDR_V=$(cat /proc/sys/vm/mmap_min_addr)
	fi;
	if [ "$PH_VADDR_V" == "" ]; then
		PH_VADDR_V=$(( 1 << 16 ));
	fi;
	local SH_COUNT=$(get_section_headers_count "");
	local INPUT_SOURCE_CODE="$(cat)";
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
	local snippets=$(echo "${INPUT_SOURCE_CODE}" | parse_snippets "${ROUND_FIRST}" "${PH_VADDR_V}" "${INSTR_TOTAL_SIZE-0}" "${static_data_size}");
	echo -n "$snippets" > $snippets_file;
	# now we have the all information parsed
	# but the addresses are just offsets
	# we need to redo to replace the addresses references
	debug ==== second parse round ====;
	local INSTR_TOTAL_SIZE=$(detect_instruction_size_from_code "${snippets_file}");
	local static_data_size=$(detect_static_data_size_from_code "${snippets_file}");
	# update snippets with new addr
	snippets=$(echo "${INPUT_SOURCE_CODE}" | parse_snippets "${ROUND_FINAL}" "${PH_VADDR_V}" "${INSTR_TOTAL_SIZE}" "${static_data_size}");
	echo -n "$snippets" > $snippets_file;
	local ELF_BODY="$(
		print_elf_body \
			"${PH_VADDR_V}" \
			"${SH_COUNT}" \
			"$snippets_file";
	)";
	local ELF_FILE_HEADER="$(
		print_elf_file_header \
			"${PH_VADDR_V}" \
			"${SH_COUNT}";
	)";
	echo -ne "${ELF_FILE_HEADER}${ELF_BODY}" |
		base64 -d > $ELF_FILE_OUTPUT;
}
