#!/bin/bash

. elf_fn.sh

function run_shell()
{
	ELF_FILE="/dev/shm/elf"
	read -p "elf-shell < " ELF_SHELL_CODE
	[ "$?" == "1" ] && exit 0; # stdin closed
	if [ -e "${ELF_SHELL_CODE/ */}" ]; then
		echo "#!${ELF_SHELL_CODE}" >$ELF_FILE;
		return;
	else
		write_elf "$ELF_FILE" "$ELF_SHELL_CODE";
	fi;
	chmod +x $ELF_FILE;
	$ELF_FILE;
}

while true; do run_shell; done;
