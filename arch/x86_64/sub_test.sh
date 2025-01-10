#!/bin/bash

test_sub_reg_reg(){
	test_op_reg_reg sub $@;
}

set_subtrahend(){
	local minuend=$1;
	local subtrahend=${r_64[$2]};
	test_sub_reg_reg $minuend $subtrahend;
}

set_minuend(){
	local v=${r_64[$1]};
	iterate $1 "[ \$1 -lt ${#r_64[@]} ]" "set_subtrahend $v";
}

run(){
	local SCRIPT_DIR=$(dirname $(realpath $BASH_SOURCE));
	. $SCRIPT_DIR/test_asm.sh
	. $SCRIPT_DIR/sub.sh
	. $SCRIPT_DIR/../../fsh/fsh.sh
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" set_minuend;
}
run
