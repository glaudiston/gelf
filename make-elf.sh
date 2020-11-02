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

export LC_ALL=C
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
	EI_ENTRY="\x78\x00\x01\x00\x00\x00\x00\x00";	# TODO: VADDR relative program code entry point uint64_t
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
	elf_header_size="$1"
	# SECTION PROGRAM HEADERS START

	SH_NAME="$(printLittleEndian 1 4)"; # Section name (String table index) uint32_t
	SH_TYPE="$(printLittleEndian 0 4)"; # Section type
	SH_FLAGS="\x00\x00\x00\x00\x00\x00\x00\x00" # uint64_t

	SECTION_HEADERS="${SH_NAME}"; # Elf64_Shdr

	# https://www.airs.com/blog/archives/45
	# this point the current segment offset is 0x40
	PH_TYPE="\x01\x00\x00\x00"	# Elf64_Word p_type 4;
	PH_FLAGS="\x05\x00\x00\x00"	# Elf64_Word p_flags 4;
	PH_OFFSET="\x00\x00\x00\x00\x00\x00\x00\x00"	# Elf64_Off p_offset 8;
	PH_VADDR="\x00\x00\x01\x00\x00\x00\x00\x00"	# VADDR where to load program, must be after the current program size. Elf64_Addr p_vaddr 8;
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
	CODE="";
	TEXT="Hello world"
	CODE="${CODE}$(system_call_write "$TEXT")"
	CODE="${CODE}$(system_call_exit 42)"
	SECTION_ELF_DATA="${PROGRAM_HEADERS}${SECTION_HEADERS}${CODE}";
	P="${#SECTION_ELF_DATA}"
	VS=${#TEXT}
	T="$( echo -en "${SECTION_ELF_DATA/${TEXT}/$(printLittleEndian $(( 16#01009a )) 4)}" | wc -l )"
	SECTION_ELF_DATA="${SECTION_ELF_DATA/${TEXT}/$(printLittleEndian $(( 16#01009a )) 4)}$TEXT"

	echo -n "${SECTION_ELF_DATA}"
}
# See Table A-2. One-byte Opcode Map on Intel i64 documentation (page 2626)
MOV_RAX="\xb8"
MOV_RDX="\xba"
MOV_RSI="\xbe"
MOV_RDI="\xbf" #32 bit register (4 bytes)
SYSCALL="\x0f\x05"

function system_call_write()
{
	local string="$1";
	local CODE=""
	STDOUT=1
	CODE="${CODE}${MOV_RAX}$(printLittleEndian 1 4)"
	CODE="${CODE}${MOV_RDI}$(printLittleEndian $STDOUT 4)"
	CODE="${CODE}${MOV_RSI}${string}"
	#CODE="${CODE}${MOV_RSI}\x9a\x00\x01\x00"
	CODE="${CODE}${MOV_RDX}$(printLittleEndian ${#string} 4)"
	CODE="${CODE}${SYSCALL}"
	echo "${CODE}"
}

function system_call_exit()
{
	local exit_code="$1"
	local CODE="";
	local EXIT="$(printLittleEndian 60 4)";
	CODE="${CODE}${MOV_RDI}$(printLittleEndian ${exit_code:=0} 4)"
	CODE="${CODE}${MOV_RAX}${EXIT}"
	CODE="${CODE}${SYSCALL}"
	echo -n "${CODE}"
}

function write_elf()
{
	local ELF_HEADER="$(print_elf_header "$1")"
	local ELF_BODY="$(print_elf_body "$(echo -en "${ELF_HEADER}" | wc -c)")"
	echo -ne "${ELF_HEADER}${ELF_BODY}" > elf
}

write_elf
read ELF_BYTES < <( wc -c < elf )
write_elf "$ELF_BYTES"
