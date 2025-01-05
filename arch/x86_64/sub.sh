# SUB
#    28H: SUB with two 8-bit operands.
#    29H: SUB with 32-bit operands (or 64bit registers, depends on ModR/M.
#    2AH: SUB with 8-bit or 16-bit operands.
#    2BH: SUB with 16-bit or 64-bit operands.
#    80H /n: SUB with immediate data and 8-bit operands.
#    81H /n: SUB with immediate data and 16-bit or 32-bit operands.
#    83H /n: SUB with immediate data and sign-extended 8-bit or 32-bit operands.
SUB_R="\x29";
SUB_64bit="\x2B";
SUB_IMM32="\x81";
SUB_IMMSE8="\x83" # This depends on ModR/M OpCode
#SUB_rsp_SHORT="$(prefix v1 rsp | xd2esc)\x83\xec"; # Subtract 1 byte(two complement) value from rsp
SUB_ADDR4_rax_rax="482b04d5";
SUB_rdx_rsi="$(prefix rdx rsi | xd2esc)${SUB_R}${ModRM}";
SUB_rsi_rdx="$(prefix rsi rdx | xd2esc)\x29\xf2";
sub(){
	local v1="$1";
	local v2="$2";
	local p="$(prefix "$v1" "$v2")";
	if is_8bit_register "$v1"; then
    	local opcode1="28";
	    if is_8bit_register "$v2"; then
    		opcode2="$(px $((MODRM_MOD_NO_EFFECTIVE_ADDRESS + (v1 << 3) + v2 )) $SIZE_8BITS_1BYTE)";
    		c="${p}${opcode1}${opcode2}";
    		debug "asm: sub $@; # $c";
    		echo -n "$c";
            return;
        fi;
        if is_valid_number "$v2"; then
            local opcode2="34"
            local sib="25"
            local v4=$(px $v2 $SIZE_32BITS_1BYTE)
       		c="${p}${opcode1}${opcode2}${sib}${v4}";
       		debug "asm: sub $@; # $c";
       		echo -n "$c";
            return;
        fi;
	fi;
	if is_valid_number "$v1" && is_8bit_sint "$v1"; then
	{
		#4883E801          sub rax,byte +0x1
		#48832801          sub qword [rax],byte +0x1
		if is_register "$v2"; then
			opcode1="83";
			opcode2=$(px $(( 16#e8 + v2 )) $SIZE_8BITS_1BYTE);
			c="${p}${opcode1}${opcode2}$(px $v1 $SIZE_8BITS_1BYTE)";
			debug "asm: sub $@; # $c";
			echo -n $c;
			return;
		fi;
	}
	fi;
	if is_64bit_register "$v1"; then
	{
		if is_64bit_register "$v2"; then
		{
			opcode=29;
			modrm="$(px $(( ${MODRM_MOD_NO_EFFECTIVE_ADDRESS} + (v1 << 3) + v2 )) 1)";
			c="${p}${opcode}${modrm}";
			debug "asm: sub $@; # $c";
			echo -n "$c";
			return;
		}
		fi;
	}
	fi;
	error not implemented sub $@
}

