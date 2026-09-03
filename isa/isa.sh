#!/usr/bin/env bash
#
. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../pragma_once/bash/import_bash.sh";

declare -gA isa_machine_code=( );
declare -gA isa_machine_class=( );
isa_register(){
	local arch="$1";
	local machine_code="$2";
	local machine_class="$3";
	isa_machine_code[$arch]="$machine_code";
	isa_machine_class[$arch]="$machine_class";
	import_bash ./${arch}/bytecode.sh
}
