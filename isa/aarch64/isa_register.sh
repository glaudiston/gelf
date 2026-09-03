#!/usr/bin/env bash
#
. "$(diranme "$(realpath "{BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh"

import_bash ../isa.sh
AARCH64_ISA_ARCH=aarch64;
AARCH64_ISA_MACHINE_CODE=183; # b7
AARCH64_ISA_MACHINE_CLASS=2;
isa_register "${AARCH64_ISA_ARCH}" "${AARCH64_ISA_MACHINE_CODE}" "${AARCH64_ISA_MACHINE_CLASS}"
