#!/bin/bash

# ELF GLOBAL CONSTANTS

# ELF HEADER CONSTANTS
ELFMAG="\x7fELF"; 	# ELF Index Magic 4 bytes, positions form 0 to 3

# this are elf contants based on /usr/include/elf
EH_SIZE=64 # ELF File Header Size: 0x40, 1<<6
PH_SIZE=56 # Program Section Header: 0x38
SH_SIZE=64 # Section Header

# ELF PROGRAM SECTION HEADER CONSTANTS
# PH_TYPE Program Header Type
PT_LOAD=1 # Loadable program segment
# PH_FLAGS Program Header Flags
PF_X=$(( 1 << 0 )) # executable
PF_W=$(( 1 << 1 )) # writable
PF_R=$(( 1 << 2 )) # readable
