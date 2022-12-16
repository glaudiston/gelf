#!/bin/bash
#
# depends on:
# - elf_fn.sh (github.com/glaudiston/elf)
# - base64 (gnu-coreutils)
#

. elf_fn.sh

write_elf elf <<EOF
main: {
	write $(arg " This is from inside a code block")
}
write $(arg "Hi $USER")
write $(arg " By Glaudiston")
main
exit 2
EOF
