# get the most significant bit index from r1 value and put the result in r2
bsr(){
	local r1="$1";
	local r2="$2";
	local code="";
	local modrm="$MODRM_MOD_NO_EFFECTIVE_ADDRESS";
	if [ "$r1" == "(rax)" ]; then
		modrm="$MODRM_MOD_DISPLACEMENT_REG_POINTER";
	fi
	local rc=$(( modrm + ( ${r1,,} << 3 ) + ( ${r2,,} ) ));
	BSR="$(prefix $r1 $r2)0FBD$(px ${rc} $SIZE_8BITS_1BYTE)";
	code="${code}${BSR}";
	echo -n "$code";
}
