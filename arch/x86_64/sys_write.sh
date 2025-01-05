function system_call_write()
{
	local type="$1";
	local OUT="$2";
	local DATA_ADDR_V="$3";
	local DATA_LEN="$4";
	local CURRENT_RIP="$5";

	debug "system_call_write: type is $1; out is $OUT; DATA_ADDR_V is [$DATA_ADDR_V]; data_len($DATA_LEN)"
	if [ "${type}" == "${SYMBOL_TYPE_STATIC}" ]; then
		system_call_write_addr "${OUT}" "${DATA_ADDR_V}" "${DATA_LEN}";
	elif [ "${type}" == "${SYMBOL_TYPE_HARD_CODED}" ]; then
	{
		push_imm "${DATA_ADDR_V}";
		mov rax $SYS_WRITE;
		mov rdi $OUT;
		mov rsi rsp;
		mov rdx 8;
		syscall;
		pop rax;
	}
	elif [ "${type}" == "${SYMBOL_TYPE_DYNAMIC}" ]; then
	{
		system_call_write_dyn_addr "${OUT}" "${DATA_ADDR_V}" "${DATA_LEN}";
	}
	elif [ "${type}" == "${SYMBOL_TYPE_DYNAMIC_ARGUMENT}" ]; then
	{
		system_call_write_dyn_addr "${OUT}" "${DATA_ADDR_V}" "${DATA_LEN}" "${type}";
	}
	elif [ "$type" == "${SYMBOL_TYPE_PROCEDURE}" ]; then
	{
		call_procedure ${DATA_ADDR_V} ${CURRENT_RIP} | b64xd;
		mov rax $SYS_WRITE;
		mov rdx r9;
		mov rdi $OUT;
		syscall;
	}
	else
		error "a Not Implemented path type[$type], DATA_ADDR_V=[$DATA_ADDR_V]"
	fi;
	return
}

# given a dynamic address, write it to OUT;
# if len=0, autodetect by null char;
function system_call_write_dyn_addr()
{
	local outfd="$1";
	local data_addr_v="$2";
	local data_len="$3";
	# otherwise we expect all instruction already be in the data_addr_v as base64
	if is_64bit_register $data_addr_v; then
		[ rsi != $data_addr_v ] && mov rsi $data_addr_v;
	elif [ "${type}" != "${SYMBOL_TYPE_DYNAMIC_ARGUMENT}" ]; then
		mov rsi "($data_addr_v)";
	else
		mov rsi $data_addr_v;
	fi
	if [ "${data_len}" == "0" ]; then
		detect_string_length rsi rdx rax;
	else
		if [ "${type}" == "${SYMBOL_TYPE_DYNAMIC}" ]; then
			local ptr_size=8;
			mov rdx "($(( data_addr_v + ptr_size + st_size )))"
		else
			mov rdx $data_len;
		fi;
	fi;
	mov rdi $outfd;
	mov rax $SYS_WRITE;
	syscall;
}

# given a data address as argument, write it to stdout
function system_call_write_addr()
{
	local out="$1";
	local data_addr_v="$2";
	local data_len="$3";
	mov rax $SYS_WRITE;
	mov rdi "$out";
	mov rsi "${data_addr_v}";
	mov rdx "${data_len}";
	syscall;
}

