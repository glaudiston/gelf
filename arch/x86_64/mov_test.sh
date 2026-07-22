#!/bin/bash
set -euo pipefail

. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash ./test_asm.sh;

set_r2()
{
	local v1=$1;
	local v2=${r_64[$2]};
	test_op_reg_reg mov "$v1" "$v2";
	test_mov_ptrreg_reg "$v1" "$v2";
	test_mov_reg_ptrreg "$v1" "$v2";
}

set_r1()
{
	local v1="${r_64[$1]}";
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" "set_r2 $v1";
	test_op_reg_u8 mov "$v1";
	test_op_reg_u32 mov "$v1";
}

run(){
	import_bash <<-EOF
		./registers.sh
		./mov.sh
		./test_asm.sh
		./../../fsh/fsh.sh
	EOF
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" set_r1;
}

test_mov_u8_ptrreg()
{
	local c="mov '$1' '($2)'";
	local got=$($c 2>/dev/null);
	local r=$( echo $got | xxd --ps -r | ndisasm -b 64 -);
	local v=$(echo $r| tr "," " " | tr -s " " | tr " " "\t");
	local expected=$(asm_hex<<<"mov $1, (%$2)");
	if [ "${got,,}" != "${expected,,}" ]; then
		err "$c" "$expected" "$r";
	else
		ok "$c" "${got}";
	fi;
}
test_mov_reg_ptrreg()
{
	local c="mov $1 ($2)";
	local got;
	got=$($c 2>/dev/null);
	local r;
	r=$(echo "$got" | xxd --ps -r | ndisasm -b 64 -);
	local v;
	v=$(echo "$r" | tr "," " " | tr -s " " | tr " " "\t");
	local code;
	code=$(cut -f2<<<"$v");
	local expected;
	expected=$(nasm_hex<<<"mov $1, [$2]");
	if [ "${got,,}" != "${expected,,}" ]; then
		err "$c" "$expected" "$got"
	else
		ok "$c" "${got}";
	fi;
}
test_mov_ptrreg_reg()
{
	local c="mov ($1) $2";
	local got;
	got=$($c 2>/dev/null);
	local r;
	r=$(echo "$got" | xxd --ps -r | ndisasm -b 64 -);
	local v;
	v=$(echo "$r" | tr "," " " | tr -s " " | tr " " "\t");
	local code;
	code=$(cut -f2<<<"$v");
	local expected;
	expected=$(asm_hex<<<"mov %$2, (%$1)");
	if [ "${got,,}" != "${expected,,}" ]; then
		err "$c" "$expected" "$got"
	else
		ok "$c" "${got}";
	fi;
}
run

