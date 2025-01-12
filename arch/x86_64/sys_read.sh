function system_call_read()
{
	local fd=$1;
	local len="$2";
	local data_addr="$3";
	# by default expect the rdi already have the fd
	if [ "$fd" != "" ]; then
		mov rdi $fd;
	fi
	if is_64bit_register "$len"; then
		[ $len != rdx ] && mov rdx $len;
	else
		mov rdx $len;
	fi;
	if [ "$DATA_ADDR" == "" ]; then
		#use rax
		mov rsi rax;
	else
		mov rsi $data_addr;
	fi;
	mov rax $SYS_READ;
	syscall;
}


