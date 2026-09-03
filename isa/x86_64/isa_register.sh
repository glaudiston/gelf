#!/usr/bin/env bash
#
. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";

import_bash ../isa.sh
X64_ISA_ARCH=x86_64;
X64_ISA_MACHINE_CODE=$(( 16#3E ));
X64_ISA_MACHINE_CLASS=$(( 16#02 ));
isa_register "${X64_ISA_ARCH}" "${X64_ISA_MACHINE_CODE}" "${X64_ISA_MACHINE_CLASS}";
