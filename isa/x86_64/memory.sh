#!/bin/bash
set -eou pipefail
# system calls memory related:
# sys_brk	12
# 	It reports or increase the end address byte of useful data memory.
# 	If you try to use memory after that value the program will break.
# 	We can use it to extend the space we have to allocate dynamic pointers after the code in memory over the initial 4096 bytes.
# sys_mmap	9
# 	reserve a new memory page space
set -euo pipefail
. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash ./mmap.sh

is_addr(){
	is_32bit_sint "$1";
}

# ptr return the resolved ptr value by removing the brackets of the input
ptr(){
	[[ "${1,,}" =~ ^\[(.*)\]$ ]] && _ptr_v="${BASH_REMATCH[1]}"
	echo "$_ptr_v"
}

# resolve_ptr receives a var and a ptr, setting the resolved value into the var. If the ptr is not valid, return ptr;
# e.g.: 
#  resolve_ptr my_var [rax] # my_var=rax
#  resolve_ptr my_var rcx # my_var=rcx
#  resolve_ptr my_var [12345] # my_var=12345
#  resolve_ptr my_var 12345 # my_var=12345
resolve_ptr(){
	local -n _ptr_v=$1;
	_ptr_v=$2;
	[[ "${_ptr_v,,}" =~ ^\[(.*)\]$ ]] && _ptr_v="${BASH_REMATCH[1]}"
}

is_addr_ptr() {
	if ! [[ "$1" =~ ^\[.*\]$ ]]; then
		return 1; # no
	fi;
	# resolve pointer address value
	local v;
	resolve_ptr v "$1";
	is_32bit_sint "$v";
}

sys_mprotect()
{
	mov 10 rax;
	mov "$1" rdi; # start address
	mov "$2" rsi; # length size
	mov "$3" rdx; # protection flags
}

