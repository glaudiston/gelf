mov(){
	local v1="$1";
	local v2="$2";
	local code="";
	local prefix=$(prefix "$v1" "$v2");
	code="${code}${prefix}";
	local modrm="";
	if [[ "$v1" =~ ^\(.*\)$ ]]; then	# resolve pointer address value
	{
		local v1_r=$( echo $v1 | tr -d '()' );
		local mov_resolve_address="8b";
		code="${code}${mov_resolve_address}";
		if is_register "$v1_r"; then
			local mod_reg=$(( v2 << 3 )); # 000 0
			if is_register "$v2"; then
				modrm="$(px "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + mod_reg + v1_r ))" $SIZE_8BITS_1BYTE)";
			fi;
			printf "${code}${modrm}";
			debug "asm: mov $@; # $code";
			return;
		fi;
		if is_32bit_uint "$v1_r" && is_64bit_register "$v2"; then
		{
			local opcode="${mov_resolve_address}";
			local use_sib=$(( 1 << 2 ));
			local mod=$((MODRM_MOD_DISPLACEMENT_REG_POINTER << 6));
			local r=$((v2 << 3));
			local m=$(( use_sib ));
			local modrm_v=$(( mod | r | m ));
			local modrm="$(px $modrm_v $SIZE_8BITS_1BYTE)";
			local scale="0";
			local index="$((2#011 << 3))";
			local base="$(( 2#001 ))";
			local sib="$(( scale | index | base ))";
			local displacement=$(px $v1_r $SIZE_32BITS_4BYTES);
			local instr="${prefix}${opcode}${modrm}${sib}${displacement}";
			printf "${instr}";
			debug "asm: mov $@; # $code";
			return;
		}
		fi;
		code="${code}${modrm}";
	}
	fi;
	if ! is_register $v1 && is_valid_number "$v1"; then
	{
		if is_8bit_uint "$v1" && ! is_register "$v2" && is_8bit_register "$v2"; then
			code="${code}$(px $(( 16#B0 + v2 )) $SIZE_8BITS_1BYTE)"
			code="${code}$(px "$v1" $SIZE_8BITS_1BYTE)";
			printf "${code}";
			debug "asm: mov $@; # $code"
			return;
		fi;
		if ! is_register "$v2" && is_32bit_uint "$v1" && is_32bit_uint "$v2"; then
		{
			# move immediate value to displacement;
			local opcode="c7";
			local modrm="04";
			local scale=0;
			local index=$((4<<3));
			local base=5;
			local sib_v="$(( scale | index | base ))";
			debug "sib_v=$sib_v";
			local sib="$(px $sib_v $SIZE_8BITS_1BYTE)"; # 25
			local displacement="$(px "$v2" $SIZE_32BITS_4BYTES)";
			local immediate="$(px "$v1" $SIZE_32BITS_4BYTES)";
			local code="${opcode}${modrm}${sib}${displacement}${immediate}";
			printf $code
			debug "asm: mov $@; # [$code]";
			return;
		}
		fi;
		local mov_v4_reg="c7";
		local mod_reg=0;
		modrm="$(px "$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + mod_reg + v2 ))" $SIZE_8BITS_1BYTE)";
		code="${code}${mov_v4_reg}${modrm}$(px "$v1" $SIZE_32BITS_4BYTES)";
		printf $code
		debug "asm: mov $@; # $code"
		return
	}
	fi;
	if is_64bit_register "$v1"; then
	{
		code="${code}89";
		local mod_reg=$(( v1 << 3 ));
		if is_addr_ptr "$v2"; then	# resolve pointer address value
		{
			local v2_r=$( echo $v2 | tr -d '()' );
			if is_register "$v2_r"; then
				local mod_reg=$(( v1 << 3 )); # 000 0
				if is_register "$v1"; then
					modrm="$(px "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + mod_reg + v2_r ))" $SIZE_8BITS_1BYTE)";
				fi;
				if [ "$v2_r" == "rsp" ]; then # rsp is a special case where the next byte is sib;
					sib=$(px $(( MODRM_MOD_DISPLACEMENT_REG_POINTER + ( v2_r << 3 ) )) $SIZE_8BITS_1BYTE);
					modrm="$modrm$sib";
				fi;
			fi;
			code="${code}${modrm}";
			debug "asm: mov $@; # $code";
			echo -n "$code";
			return;
		}
		fi;
		if is_register "$v2"; then
			modrm="$(px "$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + mod_reg + v2 ))" $SIZE_8BITS_1BYTE)";
			code="${code}${modrm}";
			local rv="$(echo -en "${code}")";
			echo -n $rv;
			debug "mov $@; # $rv";
			return;
		elif is_valid_number "$v2"; then
			# if 32 bits addr
			# MOV %rsp ADDR: 48892425 78100000 ? not tested
			# 48: rex_64bit
			# 89: MOV instruction
			# 24: 00100100 MOD/R
			# 25: 00100101 SIB
			# 78100000: little endian 32bit addr
			# the rsp(100) is set to require an additional field the SIB is this additional field
			local sib=$rsp;
			MOD_RM="$( px $(( MODRM_MOD_DISPLACEMENT_REG_POINTER + mod_reg + sib )) ${SIZE_8BITS_1BYTE} )";
			SIB=$(px $(( 2#00100101 )) ${SIZE_8BITS_1BYTE});
			local v="$(px "$v2" $SIZE_32BITS_4BYTES)";
			code="${code}${INSTR_MOV}${MOD_RM}${SIB}${v}";
		else
			error not implemented
		fi;
		code="${code}${modrm}";
	}
	fi;
	if is_8bit_register "$v1"; then
	{
		if is_8bit_register "$v2"; then
			mov_8bit="88";
			rex="40";
			code="${rex}${mov_8bit}";
			code="${code}$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + $(( v1 << 3 )) + v2 )) $SIZE_8BITS_1BYTE)";
			echo -n "${code}";
			debug "asm: mov $@; # $code"
			return;
		fi;
		if is_valid_number "$v2"; then
		{
			local mov_8bit="88";
			# See Intel Instruction Format manual
			# Table 2-3. 32-Bit Addressing Forms with the SIB Byte (intel ref)
			# https://www.intel.com/content/dam/www/public/us/en/documents/manuals/64-ia-32-architectures-software-developer-instruction-set-reference-manual-325383.pdf
			local sib_index_none=4;	# 4 == none (no register because ebp is not allowed)
			local sib_base_none=5;	# 5 == means a disp32 with no base if the MOD is 00B. Otherwise, [*] means disp8 or disp32 + [EBP]. This provides the following address modes
						# MOD bits Effective Address
						# 00 [scaled index] + disp32
						# 01 [scaled index] + disp8 + [EBP]
						# 10 [scaled index] + disp32 + [EBP]
			local scale=$(( 0 << 6 ));
			local index=$(( sib_index_none << 3 ));
			local base=$(( sib_base_none << 0 ));
			local sib=$(px $(( scale | index | base )) $SIZE_8BITS_1BYTE);
			local prefix="";
			local opcode="${mov_8bit}";
			local use_sib=4;
			local modrm=$(px $(( MODRM_MOD_DISPLACEMENT_REG_POINTER + $(( v1 << 3 )) + use_sib )) $SIZE_8BITS_1BYTE);
			local displ32="$(px $v2 $SIZE_32BITS_4BYTES)";
			local instr="${prefix}${opcode}${modrm}${sib}${displ32}";
			echo -n "${instr}";
			debug "asm: mov $@; # $code"
			return;
		}
		fi;
	}
	fi;
	debug mov $@: out [$code];
	echo -n $code;
}

movs(){
	local r_in="$1";
	r_in="${rsi:=rsi}";
	local r_out="${2}"
	local prefix="$(prefix "$r_in" "$r_out")";
	prefix="f3"; # REP
	local opcode="a4";
	local modrm="";
	local sib="";
	local displacement="";
	local immediate="";

	if is_addr $2; then
		mov $2 rdi;
	fi;
	printf "${prefix}${opcode}${modrm}${sib}${displacement}${immediate}";
}

