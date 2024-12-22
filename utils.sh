#!/bin/bash

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

is_valid_number()
{
	[ "$1" -eq "$1" ] 2>/dev/null;
}
is_nbit_uint(){
	local bits="$1";
	local v="$2";
	is_valid_number "$v" && [ $(( (v >= 0 && (v < (1 << bits)) ) )) -eq 1 ];
}
is_nbit_sint(){
	local bits="$1";
	local v="$2";
	is_valid_number "$v" && [ $(( (v >= - ( 1 << (bits -1) )) && (v < ( 1 << (bits -1) ) ) )) -eq 1 ];
}
is_8bit_uint(){
	is_nbit_uint 8 "$1";
}
is_8bit_sint(){
	is_nbit_sint 8 "$1";
}
is_16bit_uint(){
	is_nbit_uint 16 "$1";
}
is_16bit_sint(){
	is_nbit_sint 16 "$1";
}
is_32bit_uint(){
	is_nbit_uint 32 "$1";
}
is_32bit_sint(){
	is_nbit_sint 32 "$1";
}
is_64bit_uint(){
	is_nbit_uint 64 "$1";
}
is_64bit_sint(){
	is_nbit_sint 64 "$1";
}
is_addr_ptr(){
    [[ "$1" =~ ^\(.*\)$ ]];
}
