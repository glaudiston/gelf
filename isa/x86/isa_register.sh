#!/usr/bin/env bash
#
. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";

import_bash ../isa.sh
X86_ISA_ARCH=x86;
X86_ISA_MACHINE_CODE=$(( 16#03 ));
X86_ISA_MACHINE_CLASS=$(( 16#01 ));
isa_register "${X86_ISA_ARCH}" "${X86_ISA_MACHINE_CODE}" "${X86_ISA_MACHINE_CLASS}";

