#!/bin/bash
if ! declare -F mul_loaded >/dev/null; then mul_loaded(){ :; };
. $(dirname $(realpath $BASH_SOURCE))/prefix.sh;
. $(dirname $(realpath $BASH_SOURCE))/mod_rm.sh;
. $(dirname $(realpath $BASH_SOURCE))/../../logger.sh;
# signed integer multiply
imul(){
	# IMUL_rdx_rax="$(prefix rdx rax | xd2esc)\x0f\xaf\xc2";
	local multiplier="$1";
	local multiplicand="$2";
	local p="$(prefix "$multiplicand" "$multiplier")";
	if is_valid_number "$multiplier"; then
		# 480fafc2	imul %rdx,%rax
		local b1="0f";
		local b2="af";
		local b3="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + (multiplier << 3) + multiplicand)) $SIZE_8BITS_1BYTE)";
		c="$p$b1$b2$b3";
		echo -n "$c";
		debug "imul $@; # $c"
		return;
	fi;
	if is_register "$multiplier"; then
		if is_valid_number "$multiplicand"; then
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
		fi;
		if is_register "$multiplicand"; then
			local prefix="$p";
			local opcode="0faf";
			local modrm="$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + (multiplier << 3) + multiplicand )) $SIZE_8BITS_1BYTE)";
			printf "${prefix}${opcode}${modrm}"
			return;
		fi;
	fi;
	error not implemented: imul $@
}
fi;
