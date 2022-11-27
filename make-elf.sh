#!/bin/bash
#
# depends on:
# - elf_fn.sh (github.com/glaudiston/elf)
# - base64 (gnu-coreutils)
#

. elf_fn.sh

write_elf elf <<EOF
main: {
	write $(arg "Hello $USER")
	write $(arg " By Glaudiston")
}
main
exit 0
EOF
