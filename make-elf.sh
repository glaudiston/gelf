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

# given a value and a size(defalt 8), return the expected hex dumped bytes in little endianness
function printBigEndian(){
	local VALUE="$1"
	local VALUE="${VALUE:=0}"
	SIZE="$2"
	SIZE="${SIZE:=8}"
	printf "%0$((SIZE * 2))x\n" "${VALUE}" |
	       	sed 's/\(..\)/\\x\1/g'
}

# given a value and a optional size(default 8), return the expected hex dumped bytes in little endianness
function printLittleEndian(){
	local VALUE="$1"
	local SIZE="$2"
	printBigEndian "$VALUE" "$SIZE" |
		tr '\\' '\n' |
		tac |
		tr '\n' '\\' |
		sed 's/^\(.*\)\\\\$/\\\1/'
}

function print_elf_header()
{
	local ELF_BYTES="$1"
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
	EI_ETYPE="$(printLittleEndian $ET_EXEC 2)";	# DYN (Shared object file) code 3
	EM_X86_64=62
	EI_MACHINE="$(printLittleEndian $EM_X86_64 2)";
	EI_MACHINE_VERSION="$(printLittleEndian 1 4)" # 1 in little endian
	EI_ENTRY="\x54\x00\x00\x00\xbf\x2a\x00\x00";	# TODO: program code entry point uint64_t
	EI_PHOFF="\x40\x00\x00\x00\x00\x00\x00\x00";	# TODO: program header offset in bytes
	EI_SHOFF="\x00\x00\x00\x00\x00\x00\x00\x00";	# TODO: section header offset in bytes
	EI_FLAGS="\x00\x00\x00\x00";	# uint32_t
	EI_EHSIZE="\x40\x00";	# elf header size in bytes
	EI_PHENTSIZE="\x38\x00" # program header entry size (sizeof(Elf64_Phdr))
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
	# SECTION PROGRAM HEADERS START

	SH_NAME="\x01\x00\x00\x00"; # Section name (String table index) uint32_t
	SH_TYPE="\x00\x00\x00\x00"; # Section type
	SH_FLAGS="\x00\x00\x00\x00\x00\x00\x00\x00" # uint64_t

	SECTION_HEADERS="${SH_NAME}"; # Elf64_Shdr

	# https://www.airs.com/blog/archives/45
	PH_TYPE="\x01\x00\x00\x00"	# Elf64_Word p_type 4;
	PH_FLAGS="\x05\x00\x00\x00"	# Elf64_Word p_flags 4;
	PH_OFFSET="\x00\x00\x00\x00\x00\x00\x00\x00"	# Elf64_Off p_offset 8;
	PH_VADDR="\x00\x00\x00\x00\xbf\x2a\x00\x00"	# Elf64_Addr p_vaddr 8;
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
	MOV_EAX="\xb8"
	MOV_EDI="\xbf"
	SYSCALL="\x0f\x05"
	CODE="${CODE}${MOV_EAX}\x3c"
	CODE="${CODE}${SYSCALL}"
	CODE="\xb8\x3c\x00\x00\x00\xbf\x2a\x00\x00\x00\x0f\x05"
	SECTION_ELF_DATA="${PROGRAM_HEADERS}${SECTION_HEADERS}${CODE}";

	echo -n "${SECTION_ELF_DATA}"
}

function write_elf()
{
	local ELF_HEADER="$(print_elf_header "$1")"
	local ELF_BODY="$(print_elf_body)"
	echo -ne "${ELF_HEADER}${ELF_BODY}" > elf
}

write_elf
read ELF_BYTES < <( wc -c < elf )
write_elf "$ELF_BYTES"
