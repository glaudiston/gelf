#!/bin/bash
set -euo pipefail

. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash ./test_asm.sh;

set_r2()
{
	local v1=$1;
	local v2=${r_64[$2]};
	test_op_reg_reg mov "$v1" "$v2";
	test_op_ptrreg_reg mov "$v1" "$v2";
	test_op_reg_ptrreg mov "$v1" "$v2";
}

set_r1()
{
	local v1="${r_64[$1]}";
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" "set_r2 $v1";
	test_op_reg_u8 mov "$v1";
	test_op_ptrs32_reg mov "$v1";
	test_op_reg_u32 mov "$v1";
}

run(){
	import_bash <<-EOF
		./registers.sh
		./mov.sh
		./test_asm.sh
		./../../fsh/fsh.sh
	EOF
	iterate 0 "[ \$1 -lt ${#r_64[@]} ]" set_r1;
}

run

