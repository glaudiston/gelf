# operation system calls
is_system_function(){
	local YES=0;
	local NO=1;
	local symbol_name="$1";
	if [[ "$symbol_name" =~ ^(sys_write|sys_exit|sys_geteuid)$ ]]; then
		return $YES
	fi;
	return $NO
}
