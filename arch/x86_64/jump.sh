JNE="0f85"; # The second byte "85" is the opcode for the JNE(Jump if Not Equal) same of JNZ(Jump if Not Zero) instruction. The following four bytes "06 00 00 00" represent the signed 32-bit offset from the current instruction to the target label.
JZ="\x0f\x84";
JNC_BYTE="\x73"; # jae, jnb and jnc are all the same condition code CF = 0.
JZ_BYTE="74"; # follow by a signed byte from FF (-126) to 7f (127)
JNZ_BYTE="75";
JNA_BYTE="\x76";
JA_BYTE="\x77"; # CF = 0, ZF = 0
JS_BYTE="\x77";
JNG_V1="7E";JLE_V1="$JNG_V1";
JG_V1="7F";
JL_V4="\x0f\x8c";
JGE_V4="\x0f\x8d"; # Jump if greater than or igual to zero flags: SF = OF
JG="0F8F"; # Jump if Greater than zero; flags: SF = OF, ZF = 0
#jbe, jna	CF = 1 or ZF = 1
#jb, jc, jnae	CF = 1
#jle, jng	SF != OF or ZF = 1
#jl, jnge	SF != OF

#js	SF = 1
#jns	SF = 0
#
#jo	OF = 1
#jno	OF = 0
#
#jp, jpe (e = even)	PF = 1
#jnp, jpo (o = odd)	PF = 0


#jcxz, jecxz	cx = 0 (16b mode)
#jcxz, jecxz	ecx = 0 (32b mode)

#http://unixwiz.net/techtips/x86-jumps.html
#Instruction 	Description 			signed-ness 	Flags 	short jump 	near jump
#									opcodes		opcodes
#JO		Jump if overflow 			  	OF = 1		70	0F 80
#JNO 		Jump if not overflow 	  			OF = 0	 		71 	0F 81
#JS 		Jump if sign 	  				SF = 1 			78 	0F 88
#JNS 		Jump if not sign 		  		SF = 0 			79 	0F 89
#JE		Jump if equal/
#JZ		Jump if zero					ZF = 1 			74 	0F 84
#JNE
#JNZ	 	Jump if not equal/
#		Jump if not zero 			  	ZF = 0 			75 	0F 85
#JB		Jump if below
#JNAE		Jump if not above or equal
#JC		Jump if carry 	unsigned 			CF = 1 			72 	0F 82
#JNB		Jump if not below/
#JAE		Jump if above or equal/
#JNC 		Jump if not carry		unsigned 	CF = 0 			73 	0F 83
#JBE		Jump if below or equal
#JNA 		Jump if not above		unsigned 	CF = 1 or ZF = 1 	76 	0F 86
#JA		Jump if above
#JNBE 		Jump if not below or equal 	unsigned 	CF = 0 and ZF = 0 	77 	0F 87
#JL 		Jump if less
#JNGE		Jump if not greater or equal 	signed 		SF <> OF 		7C 	0F 8C
#JGE 		Jump if greater or equal
#JNL		Jump if not less 		signed 		SF = OF 		7D 	0F 8D
#JLE	 	Jump if less or equal
#JNG		Jump if not greater 		signed 		ZF = 1 or SF <> OF 	7E 	0F 8E
#JG 		Jump if greater
#JNLE		Jump if not less or equal 	signed 		ZF = 0 and SF = OF 	7F 	0F 8F
#JP		Jump if parity
#JPE 		Jump if parity even 	  			PF = 1 			7A 	0F 8A
#JNP 		Jump if not parity
#JPO		Jump if parity odd 	  			PF = 0 			7B 	0F 8B
#JCXZ		Jump if %CX register is 0
#JECXZ		Jump if %ECX register is 0 	  		%CX = 0 %ECX = 0 	E3
jz(){
	local v="$1";
	printf ${JZ_BYTE};
	printf $(px "$v" $SIZE_8BITS_1BYTE);
}
je(){
	jz $@
}
jnz(){
	local v="$1";
	printf ${JNZ_BYTE};
	printf $(px $v $SIZE_8BITS_1BYTE);
}
jne(){
	jnz $@;
}
jl(){
	local v="$1";
	local opcode="7c";
	echo -n "${opcode}$(px "$v" 1)";
}
jnl(){
	local v="$1";
	local opcode="7d";
	echo -n $opcode$(px "$v" 1 );
}
jg(){
	local v="$1";
	local code=""
	code="${code}${JG_V1}";
	code="${code}$(px "$v" 1)";
	echo -n "${code}";
}

# JMP
# We have some types of jump
# Relative jumps (short and near):
JMP_V1="eb"; # followed by a 8-bit signed char (-128 to 127) to move relative to BIP.
JMP_V4="e9"; # followed by a 32-bit signed integer(-2147483648 to 2147483647).
# Jump to the full virtual address
JMP_rax="\xff";
JMP_rdi="\xe0";
jmp(){
	# JMP_V4="\xe9"; # followed by a 32-bit signed integer(-2147483648 to 2147483647).
	local v1=$1;
	if is_8bit_sint "$v1"; then
	{
		local code="eb";
		code="${code}$(px "${v1}" $SIZE_8BITS_1BYTE)";
		echo -en "${code}";
		debug "asm: jmp .$v1; # $code"
		return;
	}
	fi;
	if is_32bit_sint "$v1"; then
	{
		local code="e9";
		code="${code}$(px "${v1}" $SIZE_32BITS_4BYTES)";
		echo -en "${code}";
		debug "asm: jmp .$v1; # $code"
		return;
	}
	fi;
	debug "asm: jmp .$v1; #  not supported $code: jmp $@"
}

jump_if_equal(){
	local code="";
	local target_offset="$1";
	local current_offset="$2";
	local jump_instr_size=6; # 2 bytes for jz and 4 bytes for addr
	CODE_TO_JUMP="$(printEndianValue "$(( target_offset - current_offset - jump_instr_size ))" ${SIZE_32BITS_4BYTES})";
	code="${code}${JZ}${CODE_TO_JUMP}"; # The second byte is the opcode for the JE instruction. The following four bytes represent the signed 32-bit offset from the current instruction to the target label.
	echo -en "${code}" | base64 -w0;
}

# jump should receive the target address and the current BIP.
#   It will select the correct approach for each context based on the JMP alternatives
function jump()
{
	local TARGET_ADDR="$1";
	local CURRENT_ADDR="$2";
	local relative=$(( TARGET_ADDR - CURRENT_ADDR ))
	# debug "jump: TARGET_ADDR:[$(printf %x $TARGET_ADDR)], CURRENT_ADDR:[$( printf %x ${TARGET_ADDR})]"
	local OPCODE_SIZE=1;
	local DISPLACEMENT_BITS=32; # 4 bytes
	local JUMP_NEAR_SIZE=$(( OPCODE_SIZE + DISPLACEMENT_BITS / 8 )); # 5 bytes
	jump_relative $relative
}

# Jump short is the fastest and cheaper way to run some code,
# but it has two limitations:
#  * Address distance should fit one byte;
#  * it has no stack control, so be careful
# returns:
#  base 64 encoded bytecode and exit code comma separated;
#  the exit code can be:
#    -1 error: the target address is outside the range scope ( 1 << 8  == -128 to 127 )
#    0 nothing to do (the current address is the same as the target address)
#    2 the jump short instruction byte count
function bytecode_jump_short()
{
	local relative=$1;
	local code="";
	if [ ! "$(( (relative >= -128) && (relative <= 127) ))" -eq 1 ]; then
		debug "displacement too big to jump short: $relative";
		return;
	fi;
	# debug jump short relative $relative
	local RADDR_V="$(px "$relative" $SIZE_8BITS_1BYTE )";
	# debug jump short to RADDR_V=[$( echo -n "$RADDR_V" | xxd)]
	code="${code}${JMP_V1}${RADDR_V}";
	echo -n "${code}";
	return
}

jump_relative(){
	local relative=$1;
	local short_jump_response=$(bytecode_jump_short "${relative}")
	if [ "$(echo -n "${short_jump_response}" | xcnt)" -gt 0 ];then
		echo -n "${short_jump_response}";
		return;
	fi;
	#bytecode_jump_near
	if [ "$(( (relative >= - ( 1 << 31 )) && (relative <= ( 1 << 31 ) -1) ))" -eq 1 ]; then
		# jump near
		local RADDR_V="$(px "${relative}" $SIZE_32BITS_4BYTES)";
		# debug "jump near relative ( $relative, $RADDR_V )";
		CODE="${CODE}${JMP_V4}${RADDR_V}";
		echo -en "${CODE}";
		return;
	fi;

	error "JMP not implemented for that relative or absolute value: $relative"
	# TODO, another way to move to a location is set the RIP directly
	# something like
	# mov eax, $address
	# mov [rsp], eax
	# mov eip, [rsp]
	return;
}
