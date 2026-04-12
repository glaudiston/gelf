
function push(){
	local reg="$1";
	local b2=$(( 16#50 + reg ));
	if is_64bit_extended_register "$reg"; then
		local b1="$((16#41))";
		px "$b1" $SIZE_8BITS_1BYTE;
	fi;
	px "$b2" $SIZE_8BITS_1BYTE;
}

function pop(){
	local reg="$1";
	local b2=$(( 16#58 + reg ));
	if [[ "$reg" =~ R([8-9]|1[0-5]) ]]; then
		b1="$((16#41))";
		printf "%02x%02x" "${b1}" "${b2}";
	else
		printf "%02x" "${b2}";
	fi;
}

function push_imm()
{
	local value="$1";
	if is_8bit_uint "$value"; then
		printf "6a";
		px "$value" $SIZE_8BITS_1BYTE;
		return;
	fi;
	# 16bit only valid for 16 bit mode
	#if is_16bit_uint "$value"; then
	#	printf "68";
	#	px "$value" $SIZE_16BITS_2BYTE;
	#	return;
	#fi;
	if is_32bit_uint "$value"; then
		printf "68";
		px "$value" $SIZE_32BITS_4BYTES;
		return;
	fi;
	error "invalid value to push [${value}]"
}

function push_stack()
{
	# PUSHA/PUSHAD – Push All General Registers 0110 0000

	local PUSH="\x68";
	local ADDR_V="$(printEndianValue )";
	echo -n "${PUSH}${ADDR_V}";
}

function pop_stack()
{
	# POPA/POPAD – Pop All General Registers 0110 0001
	:
}

