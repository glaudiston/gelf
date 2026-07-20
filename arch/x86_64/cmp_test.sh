#!/bin/bash
set -euo pipefail

. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash ./test_asm.sh;

test_cmp_reg_reg(){
	test_op_reg_reg cmp $@;
}

set_operand2(){
	local operand1=$1;
	local operand2=${r_64[$2]};
	test_cmp_reg_reg $operand1 $operand2;
}

set_operand1(){
	local v=${r_64[$1]};
	iterate $1 "[ \$1 -lt ${#r_64[@]} ]" "set_operand2 $v";
	test_op_reg_u8 cmp $v;
}

run(){
	import_bash <<-EOF
		./test_asm.sh
		./cmp.sh
		./registers.sh
		../../fsh/fsh.sh
	EOF
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" set_operand1;
}
run

