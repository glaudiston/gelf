#!/bin/bash

#number_bits receives a arbitrary numeric string and echoes the number of bits to represent that number
#- if the number is not a valid numeric it fails return 1
#- if the number is negative it returns the number of bits +1 (sign bit). be aware that this probably is not the same of the memory size because the negative number sign bit is the first bit in any data type and this function only add 1 bit.
#- otherwise returns the number of bits necessary to represent the given number
number_bits(){
	local input="$1";
	# sanitize the input string;
	input="${input#"${input%%[!0 ]*}"}"; # remove spaces and zeros
	if ! is_valid_number "$input"; then
		echo "[ERROR] not a valid number: $input" >&2
		return 1;
	fi;
	local i=0;
	# it fits in the bash numeric 64bit var ?
	if [[ "${#input}" -lt 19 ]]; then
		local is_neg=$(( input < 0 ));
		[[ $is_neg == 1 ]] && (( input *= -1 ));
		for (( i=0; i<64; i++ )); do
			(( input >> i != 0 )) || break
		done;
		[[ $is_neg == 1 ]] && (( i++ ));
		echo $i;
		return;
	fi;

	# big int implementation (slow but supports numbers over 64bits):
	local is_neg=0;
	[[ "${input:0:1}" == "-" ]] && is_neg=1;
	local NUM="${input#-}"
	local BINARY="";
	while [[ "$NUM" != "" ]]; do
		local result="";
		local remainder=0;
		# Perform division by 2 on the string using shift right
		for (( i=0; i<${#NUM}; i++ )); do
			digit=${NUM:i:1};
			val=$(( remainder * 10 + digit ))
			result="${result}$(( val >> 1 ))"
			remainder=$((val & 1))
		done
		NUM="${result#"${result%%[!0]*}"}"; # remove any 0 prefix
		# Prepend remainder to binary string
		BINARY="${remainder}${BINARY}"
	done

	# The length of the binary string is the number of bits
	BITS=${#BINARY}
	[[ $is_neg == 1 ]] && (( BITS++ ))

	echo "$BITS"
	# echo "Binary: $BINARY" # Optional: verify result
}

is_valid_number()
{
	# limitation: any number bigger that 64bit will be valid but bash can not represent it
	[[ "$1" =~ ^[+-]?[0-9]+$ ]]
}
is_nbit_uint(){
	local bits="$1";
	local v="$2";
	is_valid_number "$v" && (( v >= 0 && v <= (1<<bits-1)-1 ));
}
is_nbit_sint(){
	local bits="$1";
	local v="$2";
	if [[ "$bits" == 64 ]]; then
		is_valid_number "$v"; # any valid number means 64 bit because all valid numbers in bash is represented int 64bit
		return;
	fi;
	is_valid_number "$v" && (( v > -(1<<(bits-1) ) && (v < ( 1 << (bits -1) ) +1 ) ));
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
#float "10/3" 6
#3.333333
float(){
	local LANG="" expr=$1 prec=$2; printf "%.*f\n" $prec "$((10**prec * $expr ))e-$prec";
}

is_float(){ local LANG=""; [[ "$1" =~ ^[-+\ ]*[0-9]*[.][0-9]*$ ]]; }

float_precision(){
	local LANG=""
	local n=$1
	[[ $# == 2 ]] && local -n _float_precision_var=$2
	is_float "$n" || return;
	local fracpart="${n#*.}"
	[[ $# == 1 ]] && printf %i "${#fracpart}";
	[[ $# == 2 ]] && printf -v _float_precision_var %i "${#fracpart}";
}

# "3.14" becomes 3140 (i.e. 3.140 × 1000)
float_to_int() {
	local n="$1"
	local prec=$2;
	if [[ "$prec" == "" ]]; then
		float_precision "$n" prec || return;
	fi;
	is_float "$n" || return;
	local intpart="${n%%.*}"
	local fracpart="${n#*.}"
	# pad/truncate fractional part to $prec digits
	[[ $prec -eq 0 ]] && printf %i $intpart && return;
	printf -v fracpart "%i%0.*i" "$fracpart" "$prec" 0
	fracpart="${fracpart:0:prec}"
	echo "$((10#$intpart * (10 ** prec) + 10#$fracpart))"
}

# 3140 back to "3.140"
int_to_float() {
  local n=$1
  local prec=$2;
  local sign=""
  (( n < 0 )) && sign="-" && n=$(( -n ))
  printf "%s%d.%0.${prec}d" "$sign" $(( n / (10 ** prec) )) $(( n % (10 ** prec) ))
}

float_exp(){
	local elems=()
	# parse the expression
	# run all numbers
	# if float detect the biggest precision
	# multiply all numbers by the 10 ** precision and convert them to int
	# preform the operation
	# convert the result to float with the detected precision
	:
}

#a=$(float_to_int "3.14")   # 3140
#b=$(float_to_int "2.5")    # 2500
#
## Now do integer math
#sum=$(( a + b ))           # 5640
#echo "$(int_to_float $sum)"  # 5.640
