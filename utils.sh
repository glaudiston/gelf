#!/bin/bash

is_valid_number()
{
	[ "$1" -eq "$1" ] 2>/dev/null;
	return $?
}

encode_array_to_b64_csv() {
	local IFS=$'\t'
	local array=($@)
	out=$(
	for item in "${array[@]}";
	do
		 echo -n "$item" | base64 -w0
		 echo -n ","
	done;
	);
	echo "${out%,}"
}

decode_b64_csv_to_array() {
	local IFS=$'\t'
	local a=();
	local i=0;
	for item in $(echo -n "$@" | tr , '\t');
	do
		a[$i]=$(echo -n "$item" | base64 -d);
		#debug "$i=[${a[$i]}]"
		let i++; 
	done;
	echo -n "${a[@]}";
}

function b64_to_hex_dump()
{
	base64 -d | xxd --ps | sed "s/\(..\)/\\\\x\1/g" | tr -d '\n'
}

