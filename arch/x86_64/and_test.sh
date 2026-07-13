#!/bin/bash
#. $(dirname $(realpath $BASH_SOURCE))/../../pragma_once.sh || return 0
. $(dirname $(realpath $BASH_SOURCE))/test_asm.sh;

test_and(){
	test_op_reg_reg and "$@";
}

set_op_a(){
	local op_a=$1;
	local op_b=${r_64[$2]};
	test_and $op_a $op_b;
}

set_op_b(){
	local v=${r_64[$1]};
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" "set_op_a $v";
}

run(){
	local SCRIPT_DIR=$(dirname $(realpath $BASH_SOURCE));
	. $SCRIPT_DIR/test_asm.sh
	. $SCRIPT_DIR/and.sh
	. $SCRIPT_DIR/registers.sh
	. $SCRIPT_DIR/../../fsh/fsh.sh
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" set_op_b;
}
run
