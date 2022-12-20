#!/bin/bash
#
# depends on:
# - elf_fn.sh (github.com/glaudiston/elf)
# - base64 (gnu-coreutils)
#

. elf_fn.sh

write_elf elf <<EOF
# function just for testing purposes
func: {
	write $(arg "sample code at func")
	exit 3
}
# func main is not really needed
main: {
	write $(arg "first line in main")
	write $(arg "second line on main... x00.shstrtab\x00is from inside a code block")
	exit 2
}
write $(arg "Hi $USER\n")
write $(arg " By Glaudiston")
main
exit 1
EOF
