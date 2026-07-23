#!/bin/bash
set -euo pipefail
. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash <<-EOF
	./../../types.sh
	./../../logger/bash/logger.sh
	./../../endianness.sh
	./../../encoding.sh
	./../../utils.sh
	./registers.sh
	./prefix.sh
	./multi_syntax.sh
	./mod_rm.sh
	./bytecode.sh
EOF

MOV="$(( MODRM_MOD_DISPLACEMENT_32 ))";	# \x80 Move using memory as source (32-bit)
MOVR="$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS ))";	# \xc0 move between registers
IMM="$(( 2#00111000 ))";

# mov intel syntax
mov(){
	local v1="$1";
	local v2="$2";
	if is_register_ptr "$v1" && is_64bit_register "$v2"; then
	{
		local prefix;
		prefix="$(rex "$1" "$2")";
		local opcode=89;
		local v1_r=$(echo "$v1" | tr -d '[]')
		local mod=$(( v1_r == rbp ));
		local modrm=$(px $(( MODRM_MOD_DISPLACEMENT_REG_POINTER | (mod << 6)| ($v2 << 3) | $v1_r )) $SIZE_8BITS_1BYTE);
		local sib=$({
		[ $(( v1_r )) == $(( rsp )) ] && {
			local scale=0;
			local base=$((v1_r));
			local index=$((v1_r));
			px "$(( (scale<<5) | (base<<3) | index ))" $SIZE_8BITS_1BYTE;
		}
		[ $(( v1_r )) == $(( rbp )) ] && printf 00;
		});
		local code="${prefix}${opcode}${modrm}${sib}";
		printf "%s" "$code";
		debug "asm: mov " "$@" "; # $code";
		return;
	}
	fi;
	if is_register "$v1"; then
	{
		if is_register_ptr "$v2"; then
		{
			local prefix;
			local opcode;
			local modrm;
			local displacement_8bit="";
			local sib="";
			prefix=$(prefix "$v1" "$v2");
			local v2_r;
			v2_r=$( echo $v2 | tr -d '[]' );
			local mov_resolve_address="8b";
			opcode="${mov_resolve_address}";
			local mod_reg=$(( v1 << 3 )); # 000 0
			if is_register "$v1"; then
				modrm="$(px "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER + mod_reg + v2_r ))" "$SIZE_8BITS_1BYTE")";
			fi;
			if [[ $((v2_r)) == "$rsp" ]]; then # special case for rsp
				local scale="0"; # 1x
				local index="$((2#100 << 3))"; # no index for sib
				local base="$(( v2_r ))"; # the register, in this case rsp
				sib="$(px $(( scale | index | base )) "$SIZE_8BITS_1BYTE")";
			fi;
			if [[ $((v2_r)) == "$rbp" ]]; then # special case rbp
				displacement_8bit="00";
				modrm="$(px "$(( MODRM_MOD_DISPLACEMENT_8 + mod_reg + v2_r ))" "$SIZE_8BITS_1BYTE")";
			fi;
			local code="${prefix}${opcode}${modrm}${displacement_8bit}${sib}"
			printf "%s" "${code}";
			debug "asm: mov " "$@" "; # $code";
			return;
		}
		fi;
		if is_register "$v2"; then
			local prefix opcode modrm;
			prefix="$(prefix "$v1" "$v2")";
			opcode="89";
			modrm="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS | (v2 << 3) | v1 )) "$SIZE_8BITS_1BYTE")";
			local code="${prefix}${opcode}${modrm}";
			printf "%s" "$code"
			debug "asm: mov " "$@" "; # $code";
			return;
		fi;
		if is_addr_ptr "$v2"; then
		{
			if is_64bit_register "$v1" && is_32bit_uint "$v2_r"; then
			{
				local opcode="${mov_resolve_address}";
				local use_sib=$(( 1 << 2 ));
				local mod=$((MODRM_MOD_DISPLACEMENT_REG_POINTER << 6));
				local r=$((v2 << 3));
				local m=$(( use_sib ));
				local modrm_v=$(( mod | r | m ));
				local modrm;
				modrm="$(px "$modrm_v" "$SIZE_8BITS_1BYTE")";
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
			printf "${prefix}${opcode}${modrm}${sib}${imm32}";
			return
		}
		fi;
		if is_64bit_uint "$v2"; then
		{
			local prefix="";
			is_64bit_extended_register $v1 && prefix="41";
			local opcode=$( printf %02x $(( 16#b8 + v1)) )
			local modrm=""
			local sib=""
			local imm32=$(px "$v2" "$SIZE_32BITS_4BYTES")
			printf "${prefix}${opcode}${modrm}${sib}${imm32}"
			return;
		}
		fi;
		if is_32bit_sint "$v2"; then
		{
			local prefix;
			prefix=$(prefix "$v1" "$v2");
			local opcode=c7
			local modrm="";
			local sib=$rsp;
			local mod_reg=0;
			modrm="$(px "$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + mod_reg + v1 ))" "$SIZE_8BITS_1BYTE")";
			local sib=""
			local imm32=$(px "$v2" "$SIZE_32BITS_4BYTES")
			printf "${prefix}${opcode}${modrm}${sib}${imm32}"
			return;
		}
		fi;
		if is_64bit_sint "$v2"; then
		{
			local prefix="";
			prefix=$(prefix "$v1" "$v2");
			local opcode=$( printf %02x $(( 16#b8 + v1)) )
			local modrm=""
			local sib=""
			local imm32=$(px "$v2" "$SIZE_64BITS_8BYTES")
			local code="${prefix}${opcode}${modrm}${sib}${imm32}"
			printf "%s" "$code";
			debug "asm: mov " "$@" "; # $code";
			return;
		}
		fi;
	}
	fi;
	if is_addr_ptr "$v1"; then
	{
		local prefix opcode modrm displacement_8bit sib imm32;
		prefix=$(prefix "$v1" "$v2");
		opcode=89;
		modrm=$(px "$(( MODRM_MOD_DISPLACEMENT_REG_POINTER | (v2 << 3) | 2#100 ))" "$SIZE_8BITS_1BYTE");
		sib=25;
		local v1_r;
		v1_r=$( echo "$v1" | tr -d '[]' );
		imm32="$(px "$v1_r" "$SIZE_32BITS_4BYTES")"
		local code="${prefix}${opcode}${modrm}${sib}${imm32}"
		printf "%s" "$code";
		debug "asm: mov " "$@" "; # $code";
		return;
	}
	fi;
	error "not implemented: mov $@"
}

movs(){
	local r_in="$1";
	r_in="${rsi:=rsi}";
	local r_out="${2}"
	local prefix;
	prefix="$(prefix "$r_in" "$r_out")";
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

MOV_AL_ADDR4="\x88\x04\x25";
# LEA - Load Effective Address (page 1146)
#LEAQ_RIP_rbx="$(prefix rip rbx | xd2esc)\x8d\x1d\x00\x00\x00\x00";
LEA_rax_rax_4="\x8d\x04\x80";
LEA_V4_rdx="$(prefix v4 rdx | xd2esc)\x8d\x14\x25";
LEA_V4_rax="$(prefix v4 rax | xd2esc)\x8d\x04\x25";
LEA_V4_rcx="$(prefix v4 rcx | xd2esc)\x8d\x0c\x25";
MOV_ADDR4_rdx="$(prefix addr4 rdx | xd2esc)\x8b\x14\x25"; # followed by 4 bytes le;
MOV_ADDR4_rax="$(prefix addr4 rax | xd2esc)\x8b\x04\x25";
MOV_ADDR4_rsi="$(prefix addr4 rsi | xd2esc)\x8b\x34\x25";
MOV_ADDR4_rdi="$(prefix addr4 rdi | xd2esc)\x8b\x3c\x25";
MOV_V4_rax="$(prefix v4 rax | xd2esc)\xc7\xc0";
MOV_V4_rcx="$(prefix v4 rcx | xd2esc)\xc7\xc1";
MOV_V4_rdx="$(prefix v4 rdx | xd2esc)\xc7\xc2"; # MOV value and resolve address, so the content of memory address is set at the register
MOV_V4_rsi="$(prefix v4 rsi | xd2esc)\xc7\xc6";
MOV_V4_rdi="$(prefix v4 rdi | xd2esc)\xc7\xc7";
MOV_V8_rax="$(prefix v8 rax | xd2esc)$( printEndianValue $(( MOV + IMM + rax )) ${SIZE_8BITS_1BYTE} )"; # 48 b8
MOV_V8_rdx="$(prefix v8 rdx | xd2esc)$( printEndianValue $(( MOV + IMM + rdx )) ${SIZE_8BITS_1BYTE} )"; # 48 ba
MOV_V8_rsi="$(prefix v8 rsi | xd2esc)$( printEndianValue $(( MOV + IMM + rsi )) ${SIZE_8BITS_1BYTE} )"; # 48 be
#debug MOV_rsi=$MOV_rsi
MOV_V8_rdi="$(prefix v8 rdi | xd2esc)$( printEndianValue $(( MOV + IMM + rdi )) ${SIZE_8BITS_1BYTE} )"; # 48 bf; #if not prepended with rex(x48) expect 32 bit register (edi: 4 bytes)
MOV_CL_ADDR4_rdi="888F";
MOV_R="\x89";
MOVSB="\xa4"; # move 64bits(8 bytes) from %rsi addr to %rdi addr
#MOVSQ="$(prefix | xd2esc)\xa5"; # move 64bits(8 bytes) from %rsi addr to %rdi addr
REP="\xf3"; # repeat until rcx
#MOVSBL_V4rsp_EAX="\x0F\xBE\x44\x24";
#MOV_rsi_rcx="\x48\x89\xF1";
#MOVSBL_V4rsi_ECX="\x0F\xBE\x4E$(printEndianValue 63 $SIZE_8BITS_1BYTE)";
#MOVZX_DL_rdx="\x48\x0F\xB6\xD2";
#LEA_rdx_rdx="\x48\x8B\x12";
#MOVZX_SIL_rsi="\x48\x0F\xB6\xF6";
#MOVZX_SIL_rdi="\x48\x0F\xB6\xFE";
MOVZX_DL_rdi="480fb6fa";
SBB_0_EDX="83da00";
MOVSBL_V4_rdx_EDX="0FBE1415";
