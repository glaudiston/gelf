PAGESIZE=$(( 4 * 1024 )); # 4KiB
# map a memory region
#|rax|syscall___________________|rdi______________|rsi________________|rdx________________|r10________________|r8_______________|r9________|
#| 9 |sys_mmap                 |unsigned long   |unsigned long len |int prot          |int flags         |int fd          |long off |
# Returns:
#  rax Memory Address
#  r8 FD
#  r9 Size
function sys_mmap()
{
	debug "sys_mmap $@";
	local size="$1"; # this is the bytecode to detect and update rsi with the size
	local fd="$2";
	local ptr="$3";
	# ; Map the memory region
	xor rdi rdi; # let kernel choose
	# TODO nem mapping files use fstat to detect the size and implement a logic to align it to page memory
	# When using mmap, the size parameter specified in rsi should be aligned to the page size.
	# This is because the kernel allocates memory in units of pages,
	# and trying to mmap a region that is not page-aligned could result in undefined behavior.
	# To ensure that the size is aligned(I don't know a system call that returns the system page size
	# but the default linux uses 4K. libc provides a function getpagesize() to determine
	# the page size at runtime) and then round up the size parameter
	# to the nearest multiple of the page size.
	#    mov rsi, size  ; length
	#
	# recover size
	# mov ${mmap_size} rsi;
	#if pagesize > size {
	#	pagesize
	#} else {
	#	(1+(requested size / pagesize)) * pagesize
	#}
	mov ${size:=$PAGESIZE} rsi;

	# Protection flag
	# Value	Constant	Description
	# 0	PROT_NONE	No access
	# 1	PROT_READ	Read access
	# 2	PROT_WRITE	Write access
	# 4	PROT_EXEC	Execute access
	#    mov rdx, 3     ; prot (PROT_READ(1) | PROT_WRITE(2) | PROT_EXEC(4))
	PROT_NONE=0;
	PROT_READ=1;
	PROT_WRITE=2;
	PROT_EXEC=4;
	mov $(( PROT_READ + PROT_WRITE )) rdx;
	# man mmap for valid flags
	#    mov r10, 2    ; flags
	MAP_SHARED=1;
	MAP_PRIVATE=2;
	MAP_SHARED_VALIDATE=3;
	MAP_ANONYMOUS=$((2#00100000));
	mov $MAP_PRIVATE r10;
	# The file descriptor is expected to be at r8,
	# but for virtual files it will fail with a -19 at rax.
	#
	if [ "$fd" == "rax" ]; then
		mov rax r8;
	elif [ "$fd" != "" ]; then
		mov $fd r8;
	else
		# no file descriptor, so allocate a new empty block (/dev/zero)
		mov $(( MAP_PRIVATE + MAP_ANONYMOUS )) r10;
		mov -1 r8;
	fi;
	#xor r8 r8;
	#    mov r9, 0     ; offset
	xor r9 r9
	#    mov rax, 9    ; mmap system call number
	mov $SYS_MMAP rax;
	syscall;
	mov rax $ptr;
	if [ "$fd" == "" ]; then
		return;
	fi;
	# then we need to read the data to that location
	mov r8 rdi;
	system_call_read "" "rsi"; # TODO not sure the best choice here. We should do it better
	mov rax r9;
	# By default the sys_read will move the memory address from rax to rsi.
	mov rsi rax; # restore rax to return the memory address
}

