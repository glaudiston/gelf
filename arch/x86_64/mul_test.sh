#!/bin/bash

. $(dirname $(realpath $BASH_SOURCE))/mul.sh
. $(dirname $(realpath $BASH_SOURCE))/test_asm.sh

set_multiplicand(){
	local multiplier=$1;
	local multiplicand=${r_64[$2]};
	test_op_reg_reg imul $multiplier $multiplicand;
}
set_multiplier(){
	local v=${r_64[$1]};
	iterate $1 "[ \$1 -lt ${#r_64[@]} ]" "set_multiplicand $v";
	test_op_reg_u8 imul $v
}
run(){
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" set_multiplier;
}
run
