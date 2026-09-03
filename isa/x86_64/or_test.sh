#!/bin/bash

. "$(dirname "$(realpath "${BASH_SOURCE[@]}")")/../../pragma_once/bash/import_bash.sh";
import_bash ./test_asm.sh;

test_or(){
	test_op_reg_reg or "$@";
}

set_op_a(){
	local op_a=$1;
	local op_b=${r_64[$2]};
	test_or "$op_a" "$op_b";
}

set_op_b(){
	local v=${r_64[$1]};
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" "set_op_a $v";
	test_op_reg_s8 or "$v";
	test_op_reg_s32 or "$v";
}

run(){
	import_bash <<-EOF
		./../../fsh/fsh.sh
		./or.sh
		./test_asm.sh
		./registers.sh
	EOF
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" set_op_b;
}
run
