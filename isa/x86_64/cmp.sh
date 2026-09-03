#!/bin/bash
set -euo pipefail

. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";

import_bash <<-EOF
	./registers.sh
	./prefix.sh
	./mod_rm.sh
	./../../logger/bash/logger.sh
	./../../encoding.sh
	./../../number.sh
	./multiple_operation.sh
EOF
# CMP
cmp(){
	local v1="$1";
	local v2="$2";
	local opcode="";
	local mod_rm="";
	local code="";
	code="${code}$(prefix "$v1" "$v2")";
	debug "cmp $*..."
	if is_8bit_register "$v1"; then
	{
		opcode="38";
		if is_8bit_register "$v2"; then
		{
			#mod_rm="$(px "$((MODRM_MOD_NO_EFFECTIVE_ADDRESS + (v2 << 3) + v1 ))" "$SIZE_8BITS_1BYTE")";
			mod_rm=$(modrm "$v1" "$v2");
			code="${code}${opcode}${mod_rm}";
			echo -en "$code";
			debug "asm: cmp $*; # $code";
			return;
		}
		fi;
		if is_valid_number "$v2"; then
		{
			if is_8bit_sint "$v2"; then
			{
				imm8="$(px "$v2" "$SIZE_8BITS_1BYTE")"; # immediate value with 8 bits
				if [ "$v1" = "al" ]; then
				{
					code="${code}3c$(px "${imm8}" "$SIZE_8BITS_1BYTE")"; # only valid to %al: cmp %al, imm8;
					echo -en "$code";
					debug "asm: cmp $*; # $code";
					return;
				}
				fi;
				# byte registers without REX:
				# CMP r/m8, imm8 	Compare imm8 with r/m8
				# 80 /7 ib
				# \xb0 %al/r8b, lb ... \xb7
				#
				#  80F800            cmp al,0x0
				#  80F900            cmp cl,0x0
				#  80FA00            cmp dl,0x0
				#  80FB00            cmp bl,0x0
				#  80FC00            cmp ah,0x0
				#  80FD00            cmp ch,0x0
				#  80FE00            cmp dh,0x0
				#  80FF00            cmp bh,0x0
				#
				# byte registers with REX:
				# they are: AL, BL, CL, DL, DIL, SIL, BPL, SPL, R8B - R15B;
				# but we will not use the ones we can reach without the REX byte;
				# so we expect to use only for DIL, SIL, BPL, SPL, R8B - R15B;
				# 248:00000000  4880F800          o64 cmp al,0x0
				#  4880F800          o64 cmp al,0x0
				#  4880F900          o64 cmp cl,0x0
				#  4880FA00          o64 cmp dl,0x0
				#  4880FB00          o64 cmp bl,0x0
				#  4880FC00          o64 cmp spl,0x0
				#  4880FD00          o64 cmp bpl,0x0
				#  4880FE00          o64 cmp sil,0x0
				#  4880FF00          o64 cmp dil,0x0
				#
				opcode="$( px "$(( 16#f8 + v1 ))" "$SIZE_8BITS_1BYTE")";
				code="${code}80${opcode}${imm8}";
				debug "asm: cmp $*; # $code";
				echo -en "$code";
				return;
			}
			fi;
			error not implemented or allowed?
		}
		fi;
	}
	fi;
	if is_64bit_register "$v1"; then
	{
		if is_valid_number "$v2"; then
		{
			if is_8bit_sint "$v2"; then
			{
				# | REX.W + 83 /7 ib | CMP r/m64, imm8 | MI | Valid | N.E. | Compare imm8 with r/m64. |
				# /7 means modrm.reg = 7; this is why we use MODRM_OPCODE_CMP
				code="$(multiple_operation cmp "$v1" "$v2")"
				printf %s "$code";
				debug "asm: cmp $*; # $code"
				return;
			}
			fi;
			if [ "$v1" == "rax" ]; then
				prefix="$(prefix "$v1" "$v2")"
				opcode=3d
				imm32="$(px "$v2" "$SIZE_32BITS_4BYTES")"
				code="${prefix}${opcode}${imm32}";
				printf %s "${code}";
				debug "asm: cmp $*; # $code";
				return;
			fi
			multiple_operation cmp "$v1" "$v2";
			return;
		}
		fi;
		if is_64bit_register "$v2"; then
			local b1="39";
			local b2;
			#b2="$(px "$((MODRM_MOD_NO_EFFECTIVE_ADDRESS + (v2 << 3) + v1 ))" "$SIZE_8BITS_1BYTE")";
			b2=$(modrm "$v2" "$v1");
			local rv="${code}${b1}${b2}";
			debug "asm: cmp $*; # $rv";
			echo -n "$rv";
			return;
		fi;
	}
	fi;
	error not implemented
}

