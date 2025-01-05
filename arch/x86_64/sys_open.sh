#!/bin/bash
. $(dirname $(realpath $BASH_SOURCE))/mov.sh
. $(dirname $(realpath $BASH_SOURCE))/syscall.sh
function sys_open()
{
	local filename="$1"
	# mov rax, 2 ; System call for open()
	mov rax $SYS_OPEN;
	# mov rdi, filename ; File name
	mov rdi ${filename};
	xor rsi rsi;
	#mov rsi, 'r' ; Open mode
	#mov rsi $(( 16#72 )); # mode=r (x72)
	#mov rsi 0;
	# xor rdx, rdx; #  File permissions (ignored when opening)
	syscall;
}
