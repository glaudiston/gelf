#!/bin/bash

set_subtrahend(){
	local minuend=$1;
	local subtrahend=${r_64[$2]};
	test_op_reg_reg sub "$minuend" "$subtrahend";
}

set_minuend(){
	local v=${r_64[$1]};
	iterate "$1" "[ \$1 -lt ${#r_64[@]} ]" "set_subtrahend $v";
	test_op_reg_s8 sub "$v";
	test_op_reg_s32 sub "$v";
}

run(){
	. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
	import_bash ./test_asm.sh;
	import_bash <<-EOF
		./registers.sh
		./test_asm.sh
		./sub.sh
		../../fsh/fsh.sh
	EOF
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" set_minuend;
}
run
