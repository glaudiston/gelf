
sys_geteuid(){
	local addr="$1";
	mov rax $SYS_GETEUID;
	syscall;
	mov "$addr" rax;
}
