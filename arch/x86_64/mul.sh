#!/bin/bash
. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash <<-EOF
	./prefix.sh
	./mod_rm.sh
EOF
# signed integer multiply
imul(){
	local prefix opcode modrm sib displacement imm;
	local multiplicand="$1";
	local multiplier="$2";
	if is_valid_number "$multiplier"; then
	{
		local p="$(prefix "$multiplicand" "$multiplier" 1)";
		local b1="0f";
		local b2="af";
		local b3="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + (multiplier << 3) + multiplicand)) $SIZE_8BITS_1BYTE)";
		c="$p$b1$b2$b3";
		echo -n "$c";
		debug "imul $@; # $c"
		return;
	}
	fi;
	if is_register "$multiplicand"; then
		if is_valid_number "$multiplier"; then
		{
			if is_32bit_sint "$multiplier"; then
				local code;
				local prefix opcode modrm imm32;
				prefix="$p";
				opcode=69; # hex value
				modrm="$(px "$(( MODRM_MOD_NO_EFFECTIVE_ADDRESS | multiplier))" "$SIZE_8BITS_1BYTE")"
				imm32="$(px "$multiplicand" "$SIZE_32BITS_4BYTES")"
				code="${prefix}${opcode}${modrm}${imm32}"
				printf %s "$code"
				debug "imul $*; # $code";
				return;
			fi;
			# 486BF60A	# imul $multiplier0,%rsi ; imul rsi,rsi,byte +0xa
			#
			local b1="6b";
			# f0 + target reg + reg mul
			local b2="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + (multiplier<<3) + multiplier)) $SIZE_8BITS_1BYTE)";
			local b3="$(px "$multiplicand" $SIZE_8BITS_1BYTE)";
			c="$p$b1$b2$b3";
			echo -n "$c";
			debug "imul $@; # $c"
			return;
		}
		fi;
		if is_register "$multiplier"; then
		{
			prefix="$(prefix "$multiplier" "$multiplicand" "1" )"; # we are using complex opcode
			opcode="0faf";
			modrm="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + (multiplicand << 3) + multiplier )) $SIZE_8BITS_1BYTE)";
			printf "${prefix}${opcode}${modrm}"
			return;
		}
		fi;
	fi;
	# 480fafc2	imul %rdx,%rax
	error not implemented: imul $@
}
