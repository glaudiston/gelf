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

px()	{ echo -en "$(printEndianValue "$1" "$2")" | xd | tr -d '\n'; }
xd()	{ xxd --ps; }
xdr()	{ xxd --ps -r; }
b64xd()	{ base64 -d | xd; }
xcnt()	{ xdr | wc -c; }	# count binary bytes in a hex dump
xd2esc(){ sed "s/\(..\)/\\\\x\1/g"; }
xd2b64(){ xdr | base64 -w0; }
b64_2esc(){ base64 -d | xxd --ps | xd2esc | tr -d '\n'; }
b64cnt(){ base64 -d | wc -c; }
