#!/bin/bash
. $(dirname $(realpath $BASH_SOURCE))/../../types.sh;
. $(dirname $(realpath $BASH_SOURCE))/../../encoding.sh;
. $(dirname $(realpath $BASH_SOURCE))/../../number.sh;
. $(dirname $(realpath $BASH_SOURCE))/registers.sh;
# Intel manual ref for modr/m:
# Table 2-2. 32-Bit Addressing Forms with the ModR/M Byte
MODRM_MOD_DISPLACEMENT_REG_POINTER=$(( 0 << 6 ));	# If mod is 00, no displacement follows the ModR/M byte, and the operand is IN a register (like a pointer). The operation will use the address in a register. This is used with SIB for 64bit displacements
MODRM_MOD_DISPLACEMENT_8=$((   1 << 6 ));	# If mod is 01, pointer of [reg+displacement of 8 bits] follows the ModR/M byte.
MODRM_MOD_DISPLACEMENT_32=$((  2 << 6 ));	# If mod is 10, pointer of [reg+displacement of 32 bits] follows the ModR/M byte.
MODRM_MOD_NO_EFFECTIVE_ADDRESS=$(( 3 << 6 ));	# If mod is 11, the operand is a register, and there is no SIB and no displacement. The operation will use the register itself. It can have immediate memory or value, but not an effective address, sib or displacement.
# Here's a table with the 3-bit ModR/M values and their corresponding descriptions, including the value 101 for MOV rax, imm:
# 3-bit	Description
# 000	Register (Direct)
# 001	Register (Indirect w/Disp8)
# 010	Register (Indirect w/Disp32)
# 011	Memory (SIB w/Disp32)
# 100	Register (Direct)
# 101	Immediate to register
# 110	Memory (Direct w/Disp32)
# 111	Register (Direct)

MODRM_OPCODE_ADD=$(( 0 << 3 )) # 000
MODRM_OPCODE_OR=$((  1 << 3 )) # 001
MODRM_OPCODE_ADC=$(( 2 << 3 )) # 010
MODRM_OPCODE_SBB=$(( 3 << 3 )) # 011
MODRM_OPCODE_AND=$(( 4 << 3 )) # 100
MODRM_OPCODE_SUB=$(( 5 << 3 )) # 101
MODRM_OPCODE_XOR=$(( 6 << 3 )) # 110
MODRM_OPCODE_CMP=$(( 7 << 3 )) # 111

MODRM_REG_rax=$(( rax << 3 )); # 000 0
MODRM_REG_rcx=$(( rcx << 3 )); # 001 1
MODRM_REG_rdx=$(( rdx << 3 )); # 010 2
MODRM_REG_rbx=$(( rbx << 3 )); # 011 3
MODRM_REG_rsp=$(( rsp << 3 )); # 100 4
MODRM_REG_rbp=$(( rbp << 3 )); # 101 5
MODRM_REG_rsi=$(( rsi << 3 )); # 110 6
MODRM_REG_rdi=$(( rdi << 3 )); # 111 7
MODRM_REG_r8=$((  r8  << 3 )); # 000 0
MODRM_REG_r9=$((  r9  << 3 )); # 001 1
MODRM_REG_r10=$(( r10 << 3 )); # 010 2
MODRM_REG_r11=$(( r11 << 3 )); # 011 3
MODRM_REG_r12=$(( r12 << 3 )); # 100 4
MODRM_REG_r13=$(( r13 << 3 )); # 101 5
MODRM_REG_r14=$(( r14 << 3 )); # 110 6
MODRM_REG_r15=$(( r15 << 3 )); # 111 7

modrm(){
	local v1="$1";
	local v2="$2";
	if [[ "$v1" =~ ^\(.*\)$ ]]; then	# resolve pointer address value
	{
		local v1_r=$( echo $v1 | tr -d '()' );
		local mod_reg=$(( v2 << 3 )); # 000 0
		if is_register "$v1_r"; then
			if is_register "$v2"; then
				local modrm_v=$(( MODRM_MOD_DISPLACEMENT_REG_POINTER | mod_reg | v1_r ));
				px "$modrm_v" $SIZE_8BITS_1BYTE;
				return;
			fi;
		fi;
		if is_valid_number "$v1_r"; then
			if is_register "$v2"; then
				local use_sib=4;
				local modrm_v=$(( MODRM_MOD_DISPLACEMENT_REG_POINTER | mod_reg | use_sib));
				px "$modrm_v" $SIZE_8BITS_1BYTE;
				return;
			fi;
		fi
		error not implemented;
	}
	fi;
	if is_valid_number "$v1"; then
	{
		local mod_reg=0;
		modrm="$(px "$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + mod_reg + v2 ))" $SIZE_8BITS_1BYTE)";
		printf $modrm;
		return;
	}
	fi;
	if is_64bit_register "$v1"; then
	{
		local mod_reg=$(( v1 << 3 ));
		if [[ "$v2" =~ ^\(.*\)$ ]]; then	# resolve pointer address value
		{
			local v2_r=$( echo $v2 | tr -d '()' );
			if is_register "$v2_r"; then
				local mod_reg=$(( v1 << 3 )); # 000 0
				if is_register "$v1"; then
					modrm="$(px "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + mod_reg + v2_r ))" $SIZE_8BITS_1BYTE)";
				fi;
			fi;
			printf "${modrm}";
			return;
		}
		fi;
		if is_register "$v2"; then
			modrm="$(px "$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + mod_reg + v2 ))" $SIZE_8BITS_1BYTE)";
			printf "$modrm";
			return;
		elif is_valid_number "$v2"; then
			# the rsp(100) is set to require an additional field the SIB is this additional field
			local use_sib=4;
			printf "$(px $(( MODRM_MOD_DISPLACEMENT_REG_POINTER + mod_reg + use_sib )) ${SIZE_8BITS_1BYTE} )";
			return;
		fi;
		error not implemented
	}
	fi;
	if is_8bit_register "$v1"; then
	{
		if is_8bit_register "$v2"; then
			local modrm="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + $(( v1 << 3 )) + v2 )) $SIZE_8BITS_1BYTE)";
			printf $modrm;
			return;
		fi;
		if is_valid_number "$v2"; then
		{
			local use_sib=4;
			local modrm_v=$(( MODRM_MOD_DISPLACEMENT_REG_POINTER | $(( v1 << 3 )) | use_sib ))
			local modrm=$(px ${modrm_v} $SIZE_8BITS_1BYTE);
			printf $modrm;
			return;
		}
		fi;
	}
	fi;
	error not implemented;
}
