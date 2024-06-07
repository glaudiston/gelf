#!/bin/bash
# given a value and a size(defalt 8), return the expected hex dumped bytes in little endianness

false && . ./utils.sh; # just for reference, we already sourced at main

export LC_ALL=C
function printBigEndian(){
	local VALUE="$1"
	local VALUE="${VALUE:=0}"
	SIZE="$2"
	SIZE="${SIZE:=8}"
	local l=$((SIZE * 2));
	printf "%0${l}x\n" "${VALUE}" |
		sed 's/.*\(.\{'$l'\}\)$/\1/g;s/\(..\)/\\x\1/g;' # truncates and escape
}

# given a value and a optional size(default 8), return the expected hex dumped bytes in little endianness
function printLittleEndian(){
	local VALUE="$1"
	local SIZE="$2"
	if [ "$SIZE" == "" ]; then
		error empty size, using default 64 bits
	fi;
	printBigEndian "$VALUE" "$SIZE" |
		tr '\\' '\n' |
		tac |
		tr '\n' '\\' |
		sed 's/^\(.*\)\\\\$/\\\1/'
}

function printEndianValue(){
	if ! is_valid_number "$1"; then 
		error "INVALID NUMBER \"$1\""
		backtrace
		return
	fi
	integerValue="$1";
	size_in_bytes="${2}";
	isLittle="1";
	if [ ${integerValue} -lt 0 ]; then
		negativeBitValue=$(( 1 << size_in_bytes * 8 - 1 )) 
		integerValue=$(( negativeBitValue * 2 + integerValue ))
	fi;

	if [ "$isLittle" == 1 ]; then
		printLittleEndian "$integerValue" "$size_in_bytes";
	else
		printBigEndian "$integerValue" "$size_in_bytes";
	fi;
}

function detect_endianness()
{
	LC_ALL=C
	{ for i in {0..5}; do read -n1 -rd $'\0'; done; # read and skip the first 6 bytes
		read -n1 -rd $'\0'; printf %i "'$REPLY"; # print the 6th byte (endianness)
	}  </proc/self/exe;
}
