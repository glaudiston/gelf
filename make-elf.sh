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

# SECTION ELF HEADER START
EI_MAG3="\x7fELF" 	# ELF Index Magic 4 bytes, positions form 0 to 3
EI_CLASS="\x00"		# Arch 2 bytes
[ "$(uname -m)" == "x86" ] && EI_CLASS="\x01"
[ "$(uname -m)" == "x86_64" ] && EI_CLASS="\x02"

EI_DATA="$(dd if=/bin/touch bs=7 count=1 status=none | tail -c 1)" # get endianness from touch binary
EI_VERSION="\x01"	# ELF VERSION 1 (current)
EI_OSABI="\x00"		# Operation System Applications Binary Interface (UNIX - System V)
EI_ABIVERSION="\x00"
EI_PAD="\x00\x00\x00\x00\x00\x00\x00\x00" # reserved non used pad bytes
EI_ETYPE="\x02\x00";	# DYN (Shared object file) code 3 in little endian
EI_MACHINE="\x3e\x00";	# EM_X86_64 in little endian
EI_MACHINE_VERSION="\x01\x00\x00\x00" # 1 in little endian
EI_ENTRY="\x78\x00\x00\x00\x00\x00\x00\x00";	# TODO: program code entry point uint64_t
EI_PHOFF="\x40\x00\x00\x00\x00\x00\x00\x00";	# TODO: program header size
EI_SHOFF="\x00\x00\x00\x00\x00\x00\x00\x00";	# TODO: section header offset in bytes
EI_FLAGS="\x00\x00\x00\x00";	# uint32_t
EI_EHSIZE="\x40\x00";	# elf header size in bytes
EI_PHENTSIZE="\x38\x00" # program header entry size (sizeof(Elf64_Phdr))
EI_PHNUM="\x01\x00"; 	# number of program header entries
EI_SHENTSIZE="\x00\x00";	# TODO section header size in bytes
EI_SHNUM="\x00\x00"; 	# TODO section header count
EI_SHSTRNDX="\x00\x00"; # TODO section header table index of entry of section name string table

SECTION_ELF_HEADER="${EI_MAG3}${EI_CLASS}${EI_DATA}${EI_VERSION}${EI_OSABI}${EI_PAD}"; # 16 bytes
SECTION_ELF_HEADER="${SECTION_ELF_HEADER}${EI_ETYPE}${EI_MACHINE}${EI_MACHINE_VERSION}${EI_ENTRY}";
SECTION_ELF_HEADER="${SECTION_ELF_HEADER}${EI_PHOFF}${EI_SHOFF}"
SECTION_ELF_HEADER="${SECTION_ELF_HEADER}${EI_FLAGS}${EI_EHSIZE}${EI_PHENTSIZE}${EI_PHNUM}${EI_SHENTSIZE}${EI_SHNUM}${EI_SHSTRNDX}";

# SECTION ELF HEADER END

# SECTION PROGRAM HEADERS START

SH_NAME="\x01\x00\x00\x00"; # Section name (String table index) uint32_t
SH_TYPE="\x00\x00\x00\x00"; # Section type
SH_FLAGS="\x00\x00\x00\x00\x00\x00\x00\x00" # uint64_t

SECTION_HEADERS="${SH_NAME}"; # Elf64_Shdr

# https://www.airs.com/blog/archives/45
PH_TYPE="\x01\x00\x00\x00"	# Elf64_Word p_type 4;
PH_FLAGS="\x05\x00\x00\x00"	# Elf64_Word p_flags 4;
PH_OFFSET="\x00\x00\x00\x00\x00\x00\x00\x00"	# Elf64_Off p_offset 8;
PH_VADDR="\x00\x00\x40\x00\x00\x00\x00\x00"	# Elf64_Addr p_vaddr 8;
PH_PADDR="\x00\x00\x40\x00\x00\x00\x00\x00"	# Elf64_Addr p_paddr 8;
PH_FILESZ="\x38\x00\x00\x00\x00\x00\x00\x00"	# Elf64_Xword p_filesz 8;
PH_MEMSZ="\x38\x00\x00\x00\x00\x00\x00\x00"	# Elf64_Xword p_memsz 8;
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

echo -ne "${SECTION_ELF_HEADER}${SECTION_ELF_DATA}" > elf
