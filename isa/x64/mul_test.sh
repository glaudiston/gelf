#!/bin/bash

. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash <<-EOF
	mul.sh
	test_asm.sh
EOF

set_multiplier(){
	local multiplicand=$1;
	local multiplier="${r_64[$2]}";
	test_op_reg_reg imul "$multiplicand" "$multiplier";
}
set_multiplicand(){
	local v=${r_64[$1]};
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" "set_multiplier $v";
	test_op_reg_s8 imul "$v"
	test_op_reg_s32 imul "$v"
}
run(){
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" set_multiplicand;
}
run
