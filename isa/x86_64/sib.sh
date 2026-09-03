#!/usr/bin/env bash

. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash <<-EOF
	./../../types.sh
	./../../endianness.sh
	./registers.sh
EOF

sib(){
	local scale base index;
	local a a_v;
	a="$1"
	local variant;
	variant="${2:-0}";
	[[ "$variant" == 1 ]] && return;
	resolve_ptr a_v "$a";
	if (( a_v == rbp )); then
		printf 00;
		return;
	fi;
	if (( a_v != rsp )); then
		return;
	fi;
	scale=0;
	base=$rsp;
	index=$rsp;
	px "$(( (scale<<5) | (base<<3) | index ))" "${SIZE_8BITS_1BYTE}"
}
