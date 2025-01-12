#!/bin/bash
run(){
	local SOURCE_DIR="$(dirname $(realpath $BASH_SOURCE))";
	. $SOURCE_DIR/registers.sh;
	. $SOURCE_DIR/mov.sh;
	. $SOURCE_DIR/test_asm.sh;
	. $SOURCE_DIR/../../fsh/fsh.sh;
	. $SOURCE_DIR/../../fsh/fsh.sh;
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" set_r1;
}

test_mov_u8_ptrreg()
{
	local c="mov '$1' '($2)'";
	local result=$($c 2>/dev/null);
	local r=$( echo $result | xxd --ps -r | ndisasm -b 64 -);
	local v=$(echo $r| tr "," " " | tr -s " " | tr " " "\t");
	local expected=$(asm_hex<<<"mov $1, (%$2)");
	if [ "${result,,}" != "${expected,,}" ]; then
		echo "ERROR: given [$c] got [$r] but expected [$expected]";
	fi;
}
test_mov_reg_u8()
{
	local c="mov $1 $2";
	local result=$($c 2>/dev/null);
	local r=$( echo $result | xxd --ps -r | ndisasm -b 64 -);
	local v=$(echo $r| tr "," " " | tr -s " " | tr " " "\t");
	local expected=$(asm_hex<<<"mov \$$2, %$1");
	if [ "${result,,}" != "${expected,,}" ]; then
		echo "test_mov_reg_u8 ERROR: given [$c] got [$result] but expected [$expected]";
	fi;
}
test_mov_reg_u32()
{
	local c="mov $1 $(( (2 ** 32 ) + $2 ))";
	local got=$($c 2>/dev/null);
	local r=$( echo $got | xxd --ps -r | ndisasm -b 64 -);
	local v=$(echo $r| tr "," " " | tr -s " " | tr " " "\t");
	local expected=$(asm_hex<<<"mov \$$2, %$1");
	if [ "${got,,}" != "${expected,,}" ]; then
		echo "test_mov_reg_u32 ERROR: given [$c] got [$got] but expected [${expected,,}]";
	fi;
}
test_mov_reg_ptrreg()
{
	local c="mov '$1' '($2)'";
	local r=$($c 2>/dev/null| xxd --ps -r | ndisasm -b 64 -);
	local v=$(echo $r| tr "," " " | tr -s " " | tr " " "\t");
	local code=$(cut -f2<<<$v);
	local op=$(cut -f3<<<$v);
	local tgt=$(cut -f4<<<$v);
	local src=$(cut -f5<<<$v);
	if [ "$c" != "$op $tgt $src" ]; then
		expected=$(asm_hex<<<"$op (%$2), %$1");
		echo "ERROR: given [$c] got [$code] but expected [$op $tgt $src][$expected]";
	fi;
}
test_mov_ptrreg_reg()
{
	local c="mov ($1) $2";
	local got=$($c 2>/dev/null);
	local r=$(echo $got | xxd --ps -r | ndisasm -b 64 -);
	local v=$(echo $r| tr "," " " | tr -s " " | tr " " "\t");
	local code=$(cut -f2<<<$v);
	local expected=$(asm_hex<<<"mov %$2, (%$1)");
	if [ "${got,,}" != "${expected,,}" ]; then
		echo "ERROR: given [$c] got [$got] but expected [$expected]";
	fi;
}

test_mov_reg_reg()
{
	local c="mov $1 $2";
	local got=$($c 2>/dev/null)
	local r=$(echo $got| xxd --ps -r | ndisasm -b 64 -);
	local v=$(echo $r| tr "," " " | tr -s " " | tr " " "\t");
	local code=$(cut -f2<<<$v);
	local op=$(cut -f3<<<$v);
	local tgt=$(cut -f4<<<$v);
	local src=$(cut -f5<<<$v);
	local expected=$(asm_hex<<<"$op %$src, %$tgt");
	if [ "${got,,}" != "${expected,,}" ]; then
		echo "ERROR: given [$c] got [$got] but expected[$expected]";
	fi;
}

set_r2()
{
	local v1=$1;
	local v2=${r_64[$2]};
	test_mov_reg_reg $v1 $v2;
	test_mov_ptrreg_reg $v1 $v2;
	#test_mov_reg_ptrreg $v1 $v2;
}

set_r1()
{
	local v1=${r_64[$1]};
	iterate $1 "[ \$1 -lt ${#r_64[@]} ]" "set_r2 $v1";
	test_mov_reg_u8 $v1 $(( RANDOM % 256 ));
	test_mov_reg_u32 $v1 $(( RANDOM % (2 ** 32) ));
}

run
