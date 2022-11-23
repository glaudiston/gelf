#!/bin/bash
# see man elf - /usr/include/elf.h has all information including enums
# https://www.airs.com/blog/archives/38
# http://www.sco.com/developers/gabi/latest/ch4.eheader.html
# https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-83432/index.html
#
# we use base64 everywhere because bash does not support \x0 on strings

. endianness.sh
ARCH=$(uname -m)
. system_call_linux_$ARCH.sh

function print_elf_header()
{
	local ELF_HEADER_SIZE="${1:-0}";
	local PH_VADDR_V="$2";
	local PH_SIZE="$3";
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

	EI_DATA="$(printEndianValue $(detect_endianness) ${SIZE_8BITS_1BYTE})" # get endianness from current bin
	EI_VERSION="\x01";	# ELF VERSION 1 (current)
	ELFOSABI_SYSV=0;
	ELFOSABI_HPUX=1;
	EI_OSABI="\x00";	# Operation System Applications Binary Interface (UNIX - System V-NONE)
	EI_ABIVERSION="\x00";
	EI_PAD="$(printEndianValue 0)"; # reserved non used pad bytes
	ET_EXEC=2;	# Executable file
	EI_ETYPE="$(printEndianValue $ET_EXEC $SIZE_16BITS_2BYTES)";		# DYN (Shared object file) code 3
	EI_MACHINE="$(printEndianValue $EM $SIZE_16BITS_2BYTES)";
	EI_MACHINE_VERSION="$(printEndianValue 1 $SIZE_32BITS_4BYTES)";		# 1 in little endian

	EI_ENTRY="$(printEndianValue $(( PH_VADDR_V + ELF_HEADER_SIZE + PH_SIZE )) $SIZE_64BITS_8BYTES)";	# VADDR relative program code entry point uint64_t
	EI_PHOFF="$(printEndianValue "${ELF_HEADER_SIZE}" $SIZE_64BITS_8BYTES)";# program header offset in bytes, starts immediatelly after header, so the offset is the header size
	EI_SHOFF="$( printEndianValue 0 $SIZE_64BITS_8BYTES)";			# section header offset in bytes
	EI_FLAGS="\x00\x00\x00\x00";	# uint32_t
	EI_EHSIZE="$(printEndianValue ${ELF_HEADER_SIZE} $SIZE_16BITS_2BYTES)";	# elf header size in bytes
	EI_PHENTSIZE="$(printEndianValue $(( 16#38 )) $SIZE_16BITS_2BYTES)";	# program header entry size (constant = sizeof(Elf64_Phdr))
	EI_PHNUM="$(printEndianValue 1 $SIZE_16BITS_2BYTES)"; 			# number of program header entries
	EI_SHENTSIZE="\x00\x00";	# section header size in bytes
	EI_SHNUM="\x00\x00"; 		# section header count
	EI_SHSTRNDX="\x00\x00"; 	# section header table index of entry of section name string table

	SECTION_ELF_HEADER="${ELFMAG}${EI_CLASS}${EI_DATA}${EI_VERSION}${EI_OSABI}${EI_PAD}"; # 16 bytes
	SECTION_ELF_HEADER="${SECTION_ELF_HEADER}${EI_ETYPE}${EI_MACHINE}${EI_MACHINE_VERSION}${EI_ENTRY}";
	SECTION_ELF_HEADER="${SECTION_ELF_HEADER}${EI_PHOFF}${EI_SHOFF}";
	SECTION_ELF_HEADER="${SECTION_ELF_HEADER}${EI_FLAGS}${EI_EHSIZE}${EI_PHENTSIZE}${EI_PHNUM}${EI_SHENTSIZE}${EI_SHNUM}${EI_SHSTRNDX}";

	# SECTION ELF HEADER END
	echo -en "${SECTION_ELF_HEADER}" | base64 -w0;
}

function print_elf_body()
{
	local ELF_HEADER_SIZE="$1";
	local ELF_SHELL_CODE="$2";
	local PH_VADDR_V="$3";
	local PH_SIZE=56; #x38
	PROGRAM_HEADERS=$(get_program_headers "$PH_VADDR_V" "$PH_SIZE");

	# SECTION PROGRAM HEADERS END
	SECTION_HEADERS=""; # test empty

	# code section start
	# to define the final code we need the header address,
	# but it depends on code size, because it is after the code.
	# so, first do a first run to get the code size
	local CODE_SIZE=$(get_elf_code_size "$ELF_SHELL_CODE");
	local CODE=$(get_elf_code_and_data "$PH_VADDR_V" "${ELF_HEADER_SIZE}" "${PH_SIZE}" "${CODE_SIZE}" "${ELF_SHELL_CODE}");
	SECTION_ELF_DATA="${PROGRAM_HEADERS}${SECTION_HEADERS}${CODE}";

	echo -en "${SECTION_ELF_DATA}";
}

function get_program_headers()
{
	local PH_VADDR_V="$1";
	local PH_SIZE="$2";
	# SECTION PROGRAM HEADERS START

	#SH_NAME="$(printEndianValue 1 $SIZE_32BITS_4BYTES)"; # Section name (String table index) uint32_t
	#SH_TYPE="$(printEndianValue 0 $SIZE_32BITS_4BYTES)"; # Section type
	#SH_FLAGS="$(printEndianValue 0 $SIZE_64BITS_8BYTES)"; # uint64_t

	#SECTION_HEADERS="${SH_NAME}"; # Elf64_Shdr

	# https://www.airs.com/blog/archives/45
	# this point the current segment offset is 0x40
	PH_TYPE="$(printEndianValue 1 $SIZE_32BITS_4BYTES)"	# Elf64_Word p_type 4;
	PH_FLAGS="$(printEndianValue 5 $SIZE_32BITS_4BYTES)"	# Elf64_Word p_flags 4;
	# offset, vaddr and p_align are stringly related.
	PH_OFFSET="$(printEndianValue 0 $SIZE_64BITS_8BYTES)"	# Elf64_Off p_offset 8;
	PH_VADDR="$(printEndianValue $PH_VADDR_V 8)"	# VADDR where to load program, must be after the current program size. Elf64_Addr p_vaddr 8;
	PH_PADDR="$(printEndianValue 0 $SIZE_64BITS_8BYTES)"	# Elf64_Addr p_paddr 8; Physical address are ignored for executables, libs and shared obj files.
	# PH_FILESZ and PH_MEMSZ should point to the first code position in elf
	# 16#78 == (ELF_HEADER_SIZE == x40 == 64) + (PH_SIZE == x38 == 56)
	PH_FILESZ="$(printEndianValue $(( ELF_HEADER_SIZE + PH_SIZE )) $SIZE_64BITS_8BYTES)"	# Elf64_Xword p_filesz 8;
	PH_MEMSZ="$(printEndianValue $(( ELF_HEADER_SIZE + PH_SIZE )) $SIZE_64BITS_8BYTES)"		# Elf64_Xword p_memsz 8;
	# p_align: Loadable process segments must have congruent values for p_vaddr and p_offset,
	#          modulo the page size.
	#          This member gives the value to which the segments are aligned in memory and in the file.
	#          Values 0 and 1 mean no alignment is required.
	#          Otherwise, p_align should be a positive, integral power of 2,
	#           and p_vaddr should equal p_offset, modulo p_align.
	#          See "Program Loading (Processor-Specific)".
	PH_ALIGN="$(printEndianValue 0 $SIZE_64BITS_8BYTES)"	# Elf64_Xword p_align 8;

	PROGRAM_HEADERS="${PH_TYPE}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_FLAGS}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_OFFSET}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_VADDR}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_PADDR}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_FILESZ}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_MEMSZ}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_ALIGN}"; # Elf64_Phdr[]

	#echo "PH_SIZE=${PH_SIZE}==$(echo -en "${PROGRAM_HEADERS}" | wc -c)" >&2 ## x38 == 56

	echo -en "$PROGRAM_HEADERS" | base64 -w0
}

function instruction_size() {
	INSTR="$1"
	if [ "${INSTR}" == "$(echo)" ];then
		echo 0;
		return;
	fi;
	if [ "${INSTR:0:6}" == "write " ]; then
		echo $system_call_write_len;
		return;
	fi;
	if [ "${INSTR:0:5}" == "exit " ]; then
		echo $system_call_exit_len;
		return;
	fi;
	echo "INVALID INSTRUCTION (1) [$INSTR]" >&2
}

function instruction_data()
{
	INSTR="$1"
	if [ "${INSTR}" == "$(echo)" ];then
		return;
	fi;
	if [ "${INSTR:0:6}" == "write " ]; then
		echo -n "${INSTR:6}";
		return;
	fi;
	if [ "${INSTR:0:5}" == "exit " ]; then
		return;
	fi;
	echo "INVALID INSTRUCTION (2) [$INSTR]" >&2
}

# instruction_code translate the code instruction to machine code
# on the current kernel and processor archtecture
# this returns a CSV base64 line with one line, that can have two fields
# the instruction in base64 and the data to append on the data_section
function instruction_code()
{
	DATA_SECTION="$1";
	INSTR="$2";
	if [ "${INSTR}" == "$(echo)" ];then
		return;
	fi;
	if [ "${INSTR:0:6}" == "write " ]; then
		data_text=$(instruction_data "$REPLY");
		data_section_size=$(echo "${DATA_SECTION}" | base64 -d | wc -c)
		data_size="$( echo -n "${data_text}" | base64 -d | wc -c)";
		data_addr_v="$(get_next_data_address "${PH_VADDR_V}" "${HEADER_SIZE}" "${PH_SIZE}" "${CODE_SIZE}" "${data_section_size}")";
		# echo "data_addr_v=[$data_addr_v]" >&2;
		# let's return the code instruction and the data to update on the section
		echo "$(system_call_write "$data_addr_v" "$data_size"),$(echo "$data_text")";
		return;
	fi;
	if [ "${INSTR:0:5}" == "exit " ]; then
		echo "$(system_call_exit ${INSTR:5}),"
		return;
	fi;
	echo "INVALID INSTRUCTION (3) [$INSTR]" >&2
}

# get_elf_code_size should return the bytes used by the instructions code block.
#  That includes NONE OF the data section (string table, the elf and program headers
function get_elf_code_size()
{
	CODE="$1"
	local sum=$(echo 0$(echo -e "$CODE" | while read; do
		echo -n "+$(instruction_size "${REPLY}")"
	done) | bc);
	# we can validate that value by getting the hex dump position(from where data section should start) - ph_size(56) - header size (64)
	echo -n $sum;
}

function append_data()
{
	local DATA_SECTION="$1";
	local TEXT="$2";
	echo "$DATA_SECTION$TEXT";
}

function get_data()
{
	CODE="$1"
	local data=$(echo -e "$CODE" | while read; do
		echo -n "$(instruction_data "${REPLY}")"
	done);
	# we can validate that value by getting the hex dump position(from where data section should start) - ph_size(56) - header size (64)
	echo -n "$data";
}

function get_instructions()
{
	DATA_SECTION="$1";
	CODE="$2";
	local RESP=$(echo -e "$CODE" | while read; do
		# echo "PARSING INSTRUCTION [$REPLY]" >&2
		RET=$(instruction_code "${DATA_SECTION}" "${REPLY}")
		DATA_SECTION="${DATA_SECTION}$(echo -n "$RET"| cut -d, -f2)"
		echo "${RET}";
	done);
	echo "$(echo -n "$RESP" | cut -d, -f1 | tr -d '\n'),$(echo -n "$RESP" | cut -d, -f2 | tr -d '\n')" ;
}

function get_elf_code_and_data()
{
	local PH_VADDR_V="$1"
	local HEADER_SIZE="$2";
	local PH_SIZE="$3";
	local CODE_SIZE="$4";
	local ELF_SHELL_CODE="$5";
	local DATA_SECTION="";

	local INSTR="$(get_instructions "${DATA_SECTION}" "${ELF_SHELL_CODE}")"
	CODE=$(echo "$INSTR" | cut -d, -f1);
	DATA_SECTION=$(echo "$INSTR" | cut -d, -f2);
	echo -n "${CODE}${DATA_SECTION}";
	return;
}

# get_next_data_address return the message addr, dynamic because every new code instruction changes it.
function get_next_data_address()
{
	# is the start address of the DATA_SECTION... composed of 00010000 + ELF_HEADER_SIZE + ELF_BODY_SIZE (without DATA_SECTION)"
	local PH_VADDR="$1"
	local ELF_HEADER_SIZE="$2"
	local PH_SIZE="$3"
	local CODE_SIZE="$4"
	local ELF_BODY_SIZE="$(( PH_SIZE + CODE_SIZE))"
	local DATA_SECTION_SIZE="$5";
	local DATA_ADDRESS_BEGIN_AT=$(( PH_VADDR + ELF_HEADER_SIZE + ELF_BODY_SIZE ))
	local NEXT_DATA_ADDRESS=$(( DATA_ADDRESS_BEGIN_AT + DATA_SECTION_SIZE ))
	echo -n "${NEXT_DATA_ADDRESS}";
}

function write_elf()
{
	local ELF_FILE="$1"
	local ELF_SHELL_CODE="$2"
	local ELF_HEADER="";
	# If we want to keep header size dynamic we can use:
	# local ELF_HEADER_SIZE="$( echo -ne "$(print_elf_header)" | wc -c )";
	# but for now 64 bytes is the value
	local ELF_HEADER_SIZE=64
	local PH_VADDR_V="$(( 1 << 16 ))" # 65536
	local PH_SIZE=$(( 16#38 )) #56
	ELF_HEADER="$(print_elf_header "${ELF_HEADER_SIZE}" "${PH_VADDR_V}" "${PH_SIZE}" )"; # now we have size
	local ELF_BODY="$(print_elf_body "${ELF_HEADER_SIZE}" "${ELF_SHELL_CODE}" "${PH_VADDR_V}" )";
	echo -ne "${ELF_HEADER}${ELF_BODY}" | base64 -d > $ELF_FILE
}
