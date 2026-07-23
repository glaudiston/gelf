#!/bin/bash

. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash ./test_asm.sh;

set_addend(){
	local augend=$1;
	local addend=${r_64[$2]};
	test_op_reg_reg add $augend $addend;
}

set_augend(){
	local v=${r_64[$1]};
	iterate $1 "[ \$1 -lt ${#r_64[@]} ]" "set_addend $v";
	test_op_reg_u8 add $v;
}

run(){
	import_bash <<-EOF
		./test_asm.sh
		./add.sh
		../../fsh/fsh.sh
	EOF
	import_bash ./registers.sh
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" set_augend;
}
run
