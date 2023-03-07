#!/bin/bash
#
# depends on:
# - elf_fn.sh (github.com/glaudiston/elf)
# - base64 (gnu-coreutils)
#

. elf_fn.sh

source_file="$1"
target_file="$2"
write_elf ${target_file:=sample-elf} <${source_file:=sample-code.gg}
