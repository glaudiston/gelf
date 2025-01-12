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
	[ "$size" != "rsi" ] && mov rsi ${size:=$PAGESIZE};

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
	mov rdx $(( PROT_READ + PROT_WRITE ));
	# man mmap for valid flags
	#    mov r10, 2    ; flags
	MAP_SHARED=1;
	MAP_PRIVATE=2;
	MAP_SHARED_VALIDATE=3;
	MAP_ANONYMOUS=$((2#00100000));
	# The file descriptor is expected to be at r8,
	# but for virtual files it will fail with a -19 at rax.
	#
	if is_64bit_register "$fd"; then
		mov r10 $MAP_PRIVATE;
		[ r8 != $fd ] && mov r8 $fd;
	elif [ "$fd" != "" ]; then
		mov r10 $MAP_PRIVATE;
		mov r8 $fd;
	else
		# no file descriptor, so allocate a new empty block (/dev/zero)
		mov r10 $(( MAP_PRIVATE + MAP_ANONYMOUS ));
		mov r8 -1;
	fi;
	#xor r8 r8;
	#    mov r9, 0     ; offset
	xor r9 r9
	#    mov rax, 9    ; mmap system call number
	mov rax $SYS_MMAP;
	syscall;
	cmp rax 0
	local retry_anon="$({
		mov rax $SYS_MMAP;
		mov r10 $(( MAP_PRIVATE + MAP_ANONYMOUS ));
		syscall;
		cmp rax 0;
		local read_code=$({
			# then we need to read the data to that location
			push rax;
			mov rdi r8;
			system_call_read "" "rsi";
			# now we need to store the rax to the st_size
			local ptr_size=8;
			mov $(( ptr + ptr_size + st_size )) rax; # update the stat size with the read byte count;
			pop rax;
		});
		jng $(xcnt<<<$read_code);
		printf $read_code
	})";
	jnl $(xcnt<<<$retry_anon);
	printf $retry_anon;
	mov $ptr rax;
}

