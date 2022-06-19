#!/bin/bash
# see man elf - /usr/include/elf.h has all information including enums
# https://www.airs.com/blog/archives/38
# http://www.sco.com/developers/gabi/latest/ch4.eheader.html
#
# System Interrupt call table for 64bit linux:
# http://www.cpu2.net/linuxabi.html
#
# x86 Instruction set
# https://en.wikipedia.org/wiki/X86_instruction_listings#Original_8086.2F8088_instructions
#
# Intel i64 and IA-32 Architectures
# https://software.intel.com/sites/default/files/managed/39/c5/325462-sdm-vol-1-2abcd-3abcd.pdf
# Linux syscall:
# https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/

export LC_ALL=C
. endianness.sh

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

	EI_DATA="\x$(dd if=/proc/self/exe bs=7 count=1 status=none | tail -c 1 | xxd --ps)" # get endianness from current bin
	EI_VERSION="\x01"	# ELF VERSION 1 (current)
	ELFOSABI_SYSV=0
	ELFOSABI_HPUX=1
	EI_OSABI="\x00"		# Operation System Applications Binary Interface (UNIX - System V-NONE)
	EI_ABIVERSION="\x00"
	EI_PAD="$(printBigEndian 0)" # reserved non used pad bytes
	ET_EXEC=2 # Executable file
	EI_ETYPE="$(printLittleEndian $ET_EXEC $SIZE_16BITS_2BYTES)";	# DYN (Shared object file) code 3
	EM_X86_64=62
	EI_MACHINE="$(printLittleEndian $EM_X86_64 $SIZE_16BITS_2BYTES)";
	EI_MACHINE_VERSION="$(printLittleEndian 1 $SIZE_32BITS_4BYTES)" # 1 in little endian
	printf "\nHD_SZ=[${ELF_HEADER_SIZE}]\n" >&2
	EI_ENTRY="\x78\x00\x01\x00\x00\x00\x00\x00";	# TODO: VADDR relative program code entry point uint64_t
	EI_PHOFF="$(printLittleEndian "${ELF_HEADER_SIZE}" $SIZE_64BITS_8BYTES)";	# program header offset in bytes, starts immediatelly after header, so the offset is the header size
	EI_SHOFF="\x00\x00\x00\x00\x00\x00\x00\x00";	# TODO: section header offset in bytes
	EI_FLAGS="\x00\x00\x00\x00";	# uint32_t
	EI_EHSIZE="$(printLittleEndian ${ELF_HEADER_SIZE} 2)";	# elf header size in bytes
	EI_PHENTSIZE="\x38\x00" # program header entry size (constant = sizeof(Elf64_Phdr))
	EI_PHNUM="\x01\x00"; 	# number of program header entries
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

	SH_NAME="$(printLittleEndian 1 4)"; # Section name (String table index) uint32_t
	SH_TYPE="$(printLittleEndian 0 4)"; # Section type
	SH_FLAGS="$(printLittleEndian 0 8)"; # uint64_t

	SECTION_HEADERS="${SH_NAME}"; # Elf64_Shdr

	# https://www.airs.com/blog/archives/45
	# this point the current segment offset is 0x40
	PH_TYPE="\x01\x00\x00\x00"	# Elf64_Word p_type 4;
	PH_FLAGS="\x05\x00\x00\x00"	# Elf64_Word p_flags 4;
	PH_OFFSET="\x00\x00\x00\x00\x00\x00\x00\x00"	# Elf64_Off p_offset 8;
	PH_VADDR="$(printLittleEndian $(( (2**10)*64 )) 8)"	# VADDR where to load program, must be after the current program size. Elf64_Addr p_vaddr 8;
	PH_PADDR="\x00\xb8\x3c\x00\x00\x00\x0f\x05"	# Elf64_Addr p_paddr 8;
	PH_FILESZ="\x78\x00\x00\x00\x00\x00\x00\x00"	# Elf64_Xword p_filesz 8;
	PH_MEMSZ="\x78\x00\x00\x00\x00\x00\x00\x00"	# Elf64_Xword p_memsz 8;
	PH_ALIGN="\x00\x10\x00\x00\x00\x00\x00\x00"	# Elf64_Xword p_align 8;
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
	local CODE="$(get_elf_code_and_data "${ELF_HEADER_SIZE}" "${CODE_SIZE}" "${ELF_SHELL_CODE}")";
	SECTION_ELF_DATA="${PROGRAM_HEADERS}${SECTION_HEADERS}${CODE}";

	echo -n "${SECTION_ELF_DATA}";
}

function get_elf_code_size()
{
	# for now just getting the hex dump position - header size (64)
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
	local HEADER_SIZE="$1";
	local CODE_SIZE="$2";
	local ELF_SHELL_CODE="$3";
	local DATA_SECTION="";

	# for each instruction statement
	local TEXT="$(get_data "${ELF_SHELL_CODE}")";
	local DATA_LEN="${#TEXT}"
	# to write something we use a system_call_write passing the reference of the string on data section
	# so... we need to write the data section and get the reference to that string

	local DATA_ADDR="$(get_next_data_address "$HEADER_SIZE" "${CODE_SIZE}" "$DATA_SECTION")";
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
	local ELF_MEM_DATA_START_AT=$(( 16#010000 ))
	local ELF_HEADER_SIZE="$1"
	local ELF_BODY_SIZE="$2"
	local DATA_ADDRESS_BEGIN_AT=$(( ELF_MEM_DATA_START_AT + ELF_HEADER_SIZE + ELF_BODY_SIZE ))
	local DATA_SECTION_SIZE=0;
	local NEXT_DATA_ADDRESS=$(( DATA_ADDRESS_BEGIN_AT + DATA_SECTION_SIZE ))
	#the message addr, dynamic because every new code instruction changes it.
	local MSG_ADDR="$(printLittleEndian $NEXT_DATA_ADDRESS 4)";
	echo -n "$MSG_ADDR"
}

. system_call_linux_x86-64.sh

function write_elf()
{
	local ELF_FILE="$1"
	local ELF_SHELL_CODE="$2"
	local ELF_HEADER="";
	local ELF_HEADER_SIZE="$( echo -ne "$(print_elf_header)" | wc -c )";
	ELF_HEADER="$(print_elf_header "${ELF_HEADER_SIZE}")" # now we have size
	local ELF_BODY="$(print_elf_body "${ELF_HEADER_SIZE}" "${ELF_SHELL_CODE}")"
	echo -ne "${ELF_HEADER}${ELF_BODY}" > $ELF_FILE
}
