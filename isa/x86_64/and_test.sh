#!/bin/bash
. "$(dirname "$(realpath "${BASH_SOURCE[@]}")")/../../pragma_once/bash/import_bash.sh";
import_bash ./test_asm.sh;

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
	test_op_reg_s8 and $v;
	test_op_reg_s32 and $v;
}

run(){
	import_bash <<-EOF
		./test_asm.sh
		./and.sh
		./registers.sh
		./../../fsh/fsh.sh
	EOF
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" set_op_b;
}
run
