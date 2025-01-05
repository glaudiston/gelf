# system calls memory related:
# sys_brk	12
# 	It reports or increase the end address byte of useful data memory.
# 	If you try to use memory after that value the program will break.
# 	We can use it to extend the space we have to allocate dynamic pointers after the code in memory over the initial 4096 bytes.
# sys_mmap	9
# 	reserve a new memory page space
. arch/x86_64/mmap.sh

is_addr(){
	is_32bit_uint $1;
}

is_addr_ptr() {
	if ! [[ "$1" =~ ^\(.*\)$ ]]; then
		return 1 # no
	fi;
	# resolve pointer address value
	local v=$( echo $1 | tr -d '()' );
	is_32bit_uint $v;
}
sys_mprotect()
{
	mov 10 rax;
	mov $1 rdi; # start address
	mov $2 rsi; # length size
	mov $3 rdx; # protection flags
}
