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
	EI_ETYPE="$(printLittleEndian $ET_EXEC 2)";	# DYN (Shared object file) code 3
	EM_X86_64=62
	EI_MACHINE="$(printLittleEndian $EM_X86_64 2)";
	EI_MACHINE_VERSION="$(printLittleEndian 1 4)" # 1 in little endian
	printf "${ELF_HEADER_SIZE}" >&2
	EI_ENTRY="\x78\x00\x01\x00\x00\x00\x00\x00";	# TODO: VADDR relative program code entry point uint64_t
	EI_PHOFF="$(printLittleEndian "${ELF_HEADER_SIZE}" 8)";	# program header offset in bytes, starts immediatelly after header, so the offset is the header size
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
	local elf_header_size="$1"
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
	local CODE="";
	local TEXT="${ELF_SHELL_CODE}";
	if [ "${ELF_SHELL_CODE:0:5}" == "echo " ]; then
		TEXT="${ELF_SHELL_CODE:5}"
	fi;
	CODE="${CODE}$(system_call_write "$TEXT")"
	CODE="${CODE}$(system_call_exec 192 )" #c0 == /bin/bash
	CODE="${CODE}$(system_call_exit 42)"
	SECTION_ELF_DATA="${PROGRAM_HEADERS}${SECTION_HEADERS}${CODE}";
	P="${#SECTION_ELF_DATA}"
	VS=${#TEXT}
	T="$( echo -en "${SECTION_ELF_DATA//${TEXT}/$(printLittleEndian $(( 16#01009a )) 4)}" | wc -l )"
	SECTION_ELF_DATA="${SECTION_ELF_DATA/${TEXT}/$(printLittleEndian $(( 16#0100b5 )) 4)}"
	DATA="${TEXT}/bin/sh\x00"
	SECTION_ELF_DATA="${SECTION_ELF_DATA}$DATA"

	echo -n "${SECTION_ELF_DATA}"
}

# See Table A-2. One-byte Opcode Map on Intel i64 documentation (page 2626)
# See Table B-13.  General Purpose Instruction Formats and Encodings for Non-64-Bit Modes (Contd.) (page 2658)
MOV_RAX="\xb8"
MOV_RDX="\xba"
MOV_RSI="\xbe"
MOV_RDI="\xbf" #32 bit register (4 bytes)

# LEA - Load Effective Address (page 1146)
SYSCALL="\x0f\x05"

function system_call_read()
{
	local string="$1";
	local len="${2}";
	local CODE="";
	STDIN=0;
	CODE="${CODE}${MOV_RAX}$(printLittleEndian 0 4)";
	CODE="${CODE}${MOV_RDI}$(printLittleEndian $STDIN 4)";
	CODE="${CODE}${MOV_RSI}${string}";
	CODE="${CODE}${MOV_RDX}$(printLittleEndian ${len} 4)";
	CODE="${CODE}${SYSCALL}";
	echo "${CODE}";
}

function system_call_write()
{
	local string="$1";
	local CODE=""
	STDOUT=1
	CODE="${CODE}${MOV_RAX}$(printLittleEndian 1 4)"
	CODE="${CODE}${MOV_RDI}$(printLittleEndian $STDOUT 4)"
	CODE="${CODE}${MOV_RSI}${string}"
	CODE="${CODE}${MOV_RDX}$(printLittleEndian ${#string} 4)"
	CODE="${CODE}${SYSCALL}"
	echo "${CODE}"
}

function system_call_exit()
{
	local exit_code="$1"
	local BIN_CODE="";
	local EXIT="$(printLittleEndian 60 4)";
	BIN_CODE="${BIN_CODE}${MOV_RDI}$(printLittleEndian ${exit_code:=0} 4)"
	BIN_CODE="${BIN_CODE}${MOV_RAX}${EXIT}"
	BIN_CODE="${BIN_CODE}${SYSCALL}"
	echo -n "${BIN_CODE}"
}

function system_call_exec()
{
	local PTR_FILE="$1"
	local CODE=""
	#								mem       elf     str
	# 401000:       48 bf 00 20 40 00 00    movabs $0x402000,%rdi #        == 2000 == /bin/sh
	# 401007:       00 00 00
	#CODE="${CODE}${MOV_RDI}$(printLittleEndian ${PTR_FILE:=0} 4)"
	CODE="${CODE}\x48\xbf\xc0\x00\x01\x00\x00\x00\x00\x00"

	# LEA_RSP_RSI="\x48\x8d\x74\x24\x08";
	# 40100a:       48 8d 74 24 08          lea    0x8(%rsp),%rsi
	# CODE="${CODE}${LEA_RSP_RSI}"
	CODE="${CODE}${MOV_RSI}$(printLittleEndian ${PTR_ARGS:=0} 4)"

	# 40100f:       ba 00 00 00 00          mov    $0x0,%edx
	CODE="${CODE}${MOV_RDX}$(printLittleEndian ${PTR_ENV:=0} 4)" # const char *const envp[]

	# 401014:       b8 3b 00 00 00          mov    $0x3b,%eax
	CODE="${CODE}${MOV_RAX}$(printLittleEndian 59 4)" # sys_execve (3b)

	# 401019:       0f 05                   syscall
	CODE="${CODE}${SYSCALL}"
	echo "${CODE}"
}

function write_elf()
{
	local ELF_FILE="$1"
	local ELF_SHELL_CODE="$2"
	local ELF_HEADER="";
	# local ELF_HEADER_SIZE="$( echo -ne "$(print_elf_header)" | wc -c )";
	local ELF_HEADER_SIZE=64
	ELF_HEADER="$(print_elf_header "${ELF_HEADER_SIZE}")" # now we have size
	local ELF_BODY="$(print_elf_body "${ELF_HEADER_SIZE}" "${ELF_SHELL_CODE}")"
	echo -ne "${ELF_HEADER}${ELF_BODY}" > $ELF_FILE
}
