#!/bin/bash
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

detect_endndianess()
{
	LC_ALL=C
	{ for i in {0..5}; do read -n1 -rd $'\0'; done; # read and skip the first 6 bytes
		read -n1 -rd $'\0'; printf %i "'$REPLY"; # print the 6th byte (endianness)
	}  </proc/self/exe;
}
