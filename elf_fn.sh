#!/bin/bash
# see man elf - /usr/include/elf.h has all information including enums
# https://www.airs.com/blog/archives/38
# http://www.sco.com/developers/gabi/latest/ch4.eheader.html
# https://docs.oracle.com/cd/E19683-01/816-1386/chapter6-83432/index.html
#

export LC_ALL=C
. endianness.sh

SIZE_8BITS_1BYTE=1
SIZE_16BITS_2BYTES=2
SIZE_32BITS_4BYTES=4
SIZE_64BITS_8BYTES=8

function print_elf_header()
{
	local ELF_HEADER_SIZE="${1:-0}"
	# SECTION ELF HEADER START
	ELFMAG="\x7fELF" 	# ELF Index Magic 4 bytes, positions form 0 to 3
	EI_CLASS="\x00"		# Arch 2 bytes
	[ "$(uname -m)" == "x86" ] && EI_CLASS="\x01"
	[ "$(uname -m)" == "x86_64" ] && EI_CLASS="\x02"

	EI_DATA="$(printEndianValue $(detect_endianness) ${SIZE_8BITS_1BYTE})" # get endianness from current bin
	EI_VERSION="\x01"	# ELF VERSION 1 (current)
	ELFOSABI_SYSV=0
	ELFOSABI_HPUX=1
	EI_OSABI="\x00"		# Operation System Applications Binary Interface (UNIX - System V-NONE)
	EI_ABIVERSION="\x00"
	EI_PAD="$(printEndianValue 0)" # reserved non used pad bytes
	ET_EXEC=2 # Executable file
	EI_ETYPE="$(printEndianValue $ET_EXEC $SIZE_16BITS_2BYTES)";	# DYN (Shared object file) code 3
	EM_X86_64=62
	EI_MACHINE="$(printEndianValue $EM_X86_64 $SIZE_16BITS_2BYTES)";
	EI_MACHINE_VERSION="$(printEndianValue 1 $SIZE_32BITS_4BYTES)" # 1 in little endian
	# 16#010078 == VADDR(x010000) + HEADER_SIZE(x40) + PROGRAM_HEADERS_SIZE(x38)
	EI_ENTRY="$(printEndianValue $(( 16#010078)) $SIZE_64BITS_8BYTES)";	# TODO: VADDR relative program code entry point uint64_t
	EI_PHOFF="$(printEndianValue "${ELF_HEADER_SIZE}" $SIZE_64BITS_8BYTES)";	# program header offset in bytes, starts immediatelly after header, so the offset is the header size
	EI_SHOFF="$( printEndianValue 0 $SIZE_64BITS_8BYTES)";	# TODO: section header offset in bytes
	EI_FLAGS="\x00\x00\x00\x00";	# uint32_t
	EI_EHSIZE="$(printEndianValue ${ELF_HEADER_SIZE} $SIZE_16BITS_2BYTES)";	# elf header size in bytes
	EI_PHENTSIZE="$(printEndianValue $(( 16#38 )) $SIZE_16BITS_2BYTES)" # program header entry size (constant = sizeof(Elf64_Phdr))
	EI_PHNUM="$(printEndianValue 1 $SIZE_16BITS_2BYTES)"; 	# number of program header entries
	EI_SHENTSIZE="\x00\x00";	# TODO section header size in bytes
	EI_SHNUM="\x00\x00"; 	# TODO section header count
	EI_SHSTRNDX="\x00\x00"; # TODO section header table index of entry of section name string table

	SECTION_ELF_HEADER="${ELFMAG}${EI_CLASS}${EI_DATA}${EI_VERSION}${EI_OSABI}${EI_PAD}"; # 16 bytes
	SECTION_ELF_HEADER="${SECTION_ELF_HEADER}${EI_ETYPE}${EI_MACHINE}${EI_MACHINE_VERSION}${EI_ENTRY}";
	SECTION_ELF_HEADER="${SECTION_ELF_HEADER}${EI_PHOFF}${EI_SHOFF}"
	SECTION_ELF_HEADER="${SECTION_ELF_HEADER}${EI_FLAGS}${EI_EHSIZE}${EI_PHENTSIZE}${EI_PHNUM}${EI_SHENTSIZE}${EI_SHNUM}${EI_SHSTRNDX}";

	# SECTION ELF HEADER END
	echo -n "${SECTION_ELF_HEADER}"
}

function print_elf_body()
{
	local ELF_HEADER_SIZE="$1"
	local ELF_SHELL_CODE="$2"
	# SECTION PROGRAM HEADERS START

	SH_NAME="$(printEndianValue 1 $SIZE_32BITS_4BYTES)"; # Section name (String table index) uint32_t
	SH_TYPE="$(printEndianValue 0 $SIZE_32BITS_4BYTES)"; # Section type
	SH_FLAGS="$(printEndianValue 0 $SIZE_64BITS_8BYTES)"; # uint64_t

	SECTION_HEADERS="${SH_NAME}"; # Elf64_Shdr

	# https://www.airs.com/blog/archives/45
	# this point the current segment offset is 0x40
	PH_TYPE="$(printEndianValue 1 $SIZE_32BITS_4BYTES)"	# Elf64_Word p_type 4;
	PH_FLAGS="$(printEndianValue 5 $SIZE_32BITS_4BYTES)"	# Elf64_Word p_flags 4;
	# offset, vaddr and p_align are stringly related.
	PH_OFFSET="$(printEndianValue 0 $SIZE_64BITS_8BYTES)"	# Elf64_Off p_offset 8;
	PH_VADDR="$(printEndianValue $(( 2**10 * 64 )) 8)"	# VADDR where to load program, must be after the current program size. Elf64_Addr p_vaddr 8;
	PH_PADDR="$(printEndianValue 0 $SIZE_64BITS_8BYTES)"	# Elf64_Addr p_paddr 8; Physical address are ignored for executables, libs and shared obj files.
	# PH_FILESZ and PH_MEMSZ should point to the first code position in elf
	# 16#78 == ELF_HEADER_SIZE + PH_SIZE == 56
	PH_FILESZ="$(printEndianValue $(( 16#78 )) $SIZE_64BITS_8BYTES)"	# Elf64_Xword p_filesz 8;
	PH_MEMSZ="$(printEndianValue $(( 16#78 )) $SIZE_64BITS_8BYTES)"		# Elf64_Xword p_memsz 8;
	# p_align: Loadable process segments must have congruent values for p_vaddr and p_offset, modulo the page size. This member gives the value to which the segments are aligned in memory and in the file. Values 0 and 1 mean no alignment is required. Otherwise, p_align should be a positive, integral power of 2, and p_vaddr should equal p_offset, modulo p_align. See "Program Loading (Processor-Specific)".
	PH_ALIGN="$(printEndianValue $(( 16#1000 )) $SIZE_64BITS_8BYTES)"	# Elf64_Xword p_align 8;
	PROGRAM_HEADERS="${PH_TYPE}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_FLAGS}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_OFFSET}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_VADDR}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_PADDR}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_FILESZ}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_MEMSZ}";
	PROGRAM_HEADERS="${PROGRAM_HEADERS}${PH_ALIGN}"; # Elf64_Phdr[]

	# SECTION PROGRAM HEADERS END
	SECTION_HEADERS="" # test empty

	# code section start
	# to define the final code we need the header address,
	# but it depends on code size, because it is after the code.
	# so, first do a first run to get the code size
	local CODE_SIZE=$(get_elf_code_size "$ELF_SHELL_CODE")
	local CODE="$(get_elf_code_and_data "$PH_VADDR" "${ELF_HEADER_SIZE}" "${CODE_SIZE}" "${ELF_SHELL_CODE}")";
	SECTION_ELF_DATA="${PROGRAM_HEADERS}${SECTION_HEADERS}${CODE}";

	echo -n "${SECTION_ELF_DATA}";
}

function get_elf_code_size()
{
	# for now just getting the hex dump position(from where data section should start) - header size (64)
	echo $(( 16#9a - 64 ));
}

function append_data()
{
	local DATA_SECTION="$1";
	local TEXT="$2";
	echo "$DATA_SECTION$TEXT";
}

function get_data()
{
	local ELF_SHELL_CODE="$1";
	local TEXT="${ELF_SHELL_CODE}";
	if [ "${ELF_SHELL_CODE:0:6}" == "write " ]; then
		TEXT="${ELF_SHELL_CODE:6}"
	fi;
	echo "$TEXT"
}

function get_elf_code_and_data()
{
	local PH_VADDR="$1"
	local HEADER_SIZE="$2";
	local CODE_SIZE="$3";
	local ELF_SHELL_CODE="$4";
	local DATA_SECTION="";

	# for each instruction statement
	local TEXT="$(get_data "${ELF_SHELL_CODE}")";
	local DATA_LEN="${#TEXT}"
	# to write something we use a system_call_write passing the reference of the string on data section
	# so... we need to write the data section and get the reference to that string

	local DATA_ADDR="$(get_next_data_address "${PH_VADDR}" "${HEADER_SIZE}" "${CODE_SIZE}" "${DATA_SECTION}")";
	DATA_SECTION="$(append_data "${DATA_SECTION}" "$TEXT")"
	CODE="${CODE}$(system_call_write "${DATA_ADDR}" "$DATA_LEN" )"
	#CODE="${CODE}$(system_call_exec 192 )" #c0 == /bin/bash
	local EXIT_NO_ERROR=0;
	CODE="${CODE}$(system_call_exit $EXIT_NO_ERROR)";
	echo -n "${CODE}${DATA_SECTION}";
}

function get_next_data_address()
{
	# is the start address of the DATA_SECTION... composed of 00010000 + ELF_HEADER_SIZE + ELF_BODY_SIZE (without DATA_SECTION)"
	local PH_VADDR="$(( (2**10)*64 ))"
	local ELF_HEADER_SIZE="$2"
	local ELF_BODY_SIZE="$3"
	local DATA_ADDRESS_BEGIN_AT=$(( PH_VADDR + ELF_HEADER_SIZE + ELF_BODY_SIZE ))
	local DATA_SECTION_SIZE=0;
	local NEXT_DATA_ADDRESS=$(( DATA_ADDRESS_BEGIN_AT + DATA_SECTION_SIZE ))
	#the message addr, dynamic because every new code instruction changes it.
	local MSG_ADDR="$(printEndianValue $NEXT_DATA_ADDRESS 4)";
	echo -n "$MSG_ADDR"
}

. system_call_linux_x86-64.sh

function write_elf()
{
	local ELF_FILE="$1"
	local ELF_SHELL_CODE="$2"
	local ELF_HEADER="";
	# If we want to keep header size dynamic we can use:
	# local ELF_HEADER_SIZE="$( echo -ne "$(print_elf_header)" | wc -c )";
	# but for now 64 bytes is the value
	local ELF_HEADER_SIZE=64
	ELF_HEADER="$(print_elf_header "${ELF_HEADER_SIZE}")" # now we have size
	local ELF_BODY="$(print_elf_body "${ELF_HEADER_SIZE}" "${ELF_SHELL_CODE}")"
	echo -ne "${ELF_HEADER}${ELF_BODY}" > $ELF_FILE
}
