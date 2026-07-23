#!/bin/bash
. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash <<-EOF
	../../types.sh
	../../encoding.sh
	../../number.sh
	./registers.sh
	./memory.sh
EOF
# Intel manual ref for modr/m:
# Table 2-2. 32-Bit Addressing Forms with the ModR/M Byte
declare -xg MODRM_MOD_DISPLACEMENT_REG_POINTER=$(( 0 << 6 ));	# If mod is 00, no displacement follows the ModR/M byte, and the operand is IN a register (like a pointer). The operation will use the address in a register. This is used with SIB for 64bit displacements
declare -xg MODRM_MOD_DISPLACEMENT_8=$((   1 << 6 ));	# If mod is 01, pointer of [reg+displacement of 8 bits] follows the ModR/M byte. This means after the mod_rm, we have an additional byte (8bit) to extend it. It is normally used when using rbp registers like in "mov rax (rbp)".
declare -xg MODRM_MOD_DISPLACEMENT_32=$((  2 << 6 ));	# If mod is 10, pointer of [reg+displacement of 32 bits] follows the ModR/M byte.
declare -xg MODRM_MOD_NO_EFFECTIVE_ADDRESS=$(( 3 << 6 ));	# If mod is 11, the operand is a register, and there is no SIB and no displacement. The operation will use the register itself. It can have immediate memory or value, but not an effective address, sib or displacement.
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

declare -xg MODRM_SIB=$((4 << 3)); # 100

modrm(){
	local v1="$1";
	local v2="$2";
	if is_ptr "$v1"; then
	{
		local v1_r=$( ptr "$v1" );
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
				local modrm_v=$(( MODRM_MOD_DISPLACEMENT_REG_POINTER | mod_reg | MODRM_SIB));
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
		modrm="$(px "$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS | mod_reg | v2 ))" $SIZE_8BITS_1BYTE)";
		printf "%s" "$modrm";
		return;
	}
	fi;
	if is_64bit_register "$v1"; then
	{
		local mod_reg=$(( v1 << 3 ));
		if is_ptr "$v2"; then	# resolve pointer address value
		{
			local v2_r="$(ptr "$v2")";
			if is_register "$v2_r"; then
				local mod_reg=$(( v1 << 3 )); # 000 0
				if is_register "$v1"; then
					modrm="$(px "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER | mod_reg | v2_r ))" "$SIZE_8BITS_1BYTE")";
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
			printf "$(px $(( MODRM_MOD_DISPLACEMENT_REG_POINTER | MODRM_SIB | mod_reg)) ${SIZE_8BITS_1BYTE} )";
			return;
		fi;
		error not implemented
	}
	fi;
	if is_8bit_register "$v1"; then
	{
		if is_8bit_register "$v2"; then
			local modrm="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS | v1 << 3 | v2 )) $SIZE_8BITS_1BYTE)";
			printf $modrm;
			return;
		fi;
		if is_valid_number "$v2"; then
		{
			local modrm_v=$(( MODRM_MOD_DISPLACEMENT_REG_POINTER | MODRM_SIB | $(( v1 << 3 )) ))
			local modrm=$(px ${modrm_v} $SIZE_8BITS_1BYTE);
			printf $modrm;
			return;
		}
		fi;
	}
	fi;
	error not implemented;
}
