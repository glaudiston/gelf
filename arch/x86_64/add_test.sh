#!/bin/bash

test_add_reg_reg(){
	test_op_reg_reg add $@;
}

set_addend(){
	local augend=$1;
	local addend=${r_64[$2]};
	test_add_reg_reg $augend $addend;
}

set_augend(){
	local v=${r_64[$1]};
	iterate $1 "[ \$1 -lt ${#r_64[@]} ]" "set_addend $v";
	test_op_reg_u8 add $v;
}

run(){
	local SCRIPT_DIR=$(dirname $(realpath $BASH_SOURCE));
	. $SCRIPT_DIR/test_asm.sh
	. $SCRIPT_DIR/add.sh
	. $SCRIPT_DIR/../../fsh/fsh.sh
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" set_augend;
}
run
