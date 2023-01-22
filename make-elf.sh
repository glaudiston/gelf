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
	write $(arg "first code at func\n")
	ret
}

# func main is not really needed
main: {
	write $(arg "first line in main\n")
	func
	write $(arg "second line on main\n")
	ret
}
write $(arg "Program start.\n")
write $(arg "Hi $USER\n")
write $(arg "before calling main\n")
main
write $(arg "after calling main\n")
	write $(arg " By Glaudiston\n")
exit 1
EOF
