#!/bin/bash
if ! declare -F is_valid_number >/dev/null; then
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
fi;
