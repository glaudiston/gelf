#!/bin/bash
. $(dirname $(realpath $BASH_SOURCE))/../../pragma_once.sh || return 0;
. $(dirname $(realpath $BASH_SOURCE))/test_asm.sh;

test_or(){
	test_op_reg_reg or "$@";
}

set_op_a(){
	local op_a=$1;
	local op_b=${r_64[$2]};
	test_or $op_a $op_b;
}

set_op_b(){
	local v=${r_64[$1]};
	iterate $1 "[ \$1 -lt ${#r_64[@]} ]" "set_op_a $v";
	test_op_reg_u8 or $v;
}

run(){
	echo sd $@
	local SCRIPT_DIR=$(dirname $(realpath $BASH_SOURCE));
	. $SCRIPT_DIR/../../fsh/fsh.sh
	. $SCRIPT_DIR/or.sh
	. $SCRIPT_DIR/test_asm.sh
	. $SCRIPT_DIR/registers.sh
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" set_op_b;
}
run
