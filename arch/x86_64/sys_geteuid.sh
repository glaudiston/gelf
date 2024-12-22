
sys_geteuid(){
	local addr="$1";
	mov $SYS_GETEUID rax;
	syscall;
	mov rax "$addr";
}
