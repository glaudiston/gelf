#!/bin/bash

. $(dirname $(realpath $BASH_SOURCE))/../../fsh/fsh.sh

nasm_hex()
{
	n=/dev/shm/n-${RANDOM}${RANDOM};
	cat > $n.asm; nasm -f elf64 -l $n.lst $n.asm;
	cat $n.lst | tr -s " " | cut -d" " -f4;
	rm -fr $n.lst $n.asm;
}

asm_hex()
{
	as -al -o /dev/null |
		grep -v GAS |
		sed 's/^   1 .... \([^ ]*\).*/\1/g' |
		tr -d '\n';
}

test_op_reg_reg(){
	local got="$($@ 2>/dev/null)";
	local expected="$(nasm_hex<<<"$1 $2, $3")";
	if [ "${got,,}" != "${expected,,}" ]; then
		echo "ERROR: given [$@] expected [${expected,,}] but got [${got,,}]";
	fi;
}

test_op_reg_u8(){
	local u8=$(( RANDOM % ( 2 ** 8 ) - (2 ** 7) ));
	local got="$($@ $u8 2>/dev/null)";
	local expected="$(nasm_hex<<<"$1 $2, $u8")";
	if [ "${got,,}" != "${expected,,}" ]; then
		echo "ERROR: given [$@ $u8] expected [${expected,,}] but got [${got,,}]";
	fi;
}
