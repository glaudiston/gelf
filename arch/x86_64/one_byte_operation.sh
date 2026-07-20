#!/bin/bash
import_bash <<-EOF
	./../../encoding.sh
	./../../types.sh
	./mod_rm.sh
	./prefix.sh
EOF

one_byte_operation(){
	local op="$1";
	local v1="$3";
	local v2="$2";
	local p=$(prefix "$v2" "$v1");
	local c="";
	c="$c$p";
	c="$c$op";
	if is_64bit_register "$v1" && is_64bit_register "$v2"; then
		local modrm=$(px $(( MODRM_MOD_NO_EFFECTIVE_ADDRESS + ( v1 << 3 ) + v2 )) $SIZE_8BITS_1BYTE);
		c="$c${modrm}";
	fi;
	printf "${c}";
	debug "asm: $@; # $c";
}
