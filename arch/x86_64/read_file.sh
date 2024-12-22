# We have real files and virtual files.

# Steps reading the file
# - open the file
#    When reading a file we need to open the file, getting a file descritor
# - Stat to detect the filesize
#    To read we need to know the size. Some files as virtual fs in /proc and pipes don't
#    allows stat to get the full file size, so for those the best way is to read 4k blocks
#    for others is better to detect the size with stat then do a single read or mmap.
# - read the contents
#    mmap will create a new memory page but read need to have a writable memory section
#    mmap will fail on streams like pipes or /proc virtual filesystems
function read_file()
{
	local TYPE="$1"
	local stat_addr="$2";
	local targetMemory="$3";
	local DATA_LEN="$4";
	if [ "$stat_addr" != "" ]; then
		DATA_LEN="$(get_read_size "${stat_addr}")";
	fi;
	debug DATA_LEN="$DATA_LEN"
	local CODE="";
	# DATA_LEN should be the size(in bytes) we want to write out.
	# We need to stat the file to get the real value
	# Memory address of the stat structure
	# debug read_file
	if [ "${TYPE}" == "${SYMBOL_TYPE_STATIC}" -o "${TYPE}" == "${SYMBOL_TYPE_HARD_CODED}" ]; then
	{
		# do we have a buffer to read into? should we use it in a mmap?
		# now we create a buffer with mmap using this fd in rax.
		CODE="${CODE}$(sys_mmap "${DATA_LEN}")";
		CODE="${CODE}$(mov rax "$targetMemory")";
		# TODO test sys_mmap return at rax, and if fails(<0) then mmap without the fd
		# TODO once mmap set, if the source file is read only we can just close it.
		# then the fd should be at eax and r8
		#
		# TODO:
		# collect $rax (memory location returned from mmap)
		# use it as argument to write out.
		echo -en "${CODE}" | xd2b64;
		return;
	}
	elif [ "${TYPE}" == ${SYMBOL_TYPE_DYNAMIC} ]; then
	{
		if [ "$(echo -n "${DATA_ADDR_V}" | base64 -d | cut -d, -f1 | base64 -w0)" == "$( echo -n ${ARCH_CONST_ARGUMENT_ADDRESS} | base64 -w0)" ]; then
		{
			# now we create a buffer with mmap using this fd in rax.
			CODE="${CODE}$(sys_mmap | xd2esc)";
			# collect $rax (memory location returned from mmap)
			# use it as argument to write out.
			CODE="$(mov rax "$targetMemory" | xd2esc)";
			CODE="${CODE}${MOV_rax_rsi}";
			CODE="${CODE}${MOV_V8_rax}$(printEndianValue $SYS_WRITE $SIZE_64BITS_8BYTES)";
			STDOUT=1;
			CODE="${CODE}${MOV_V8_rdi}$(printEndianValue $STDOUT $SIZE_64BITS_8BYTES)";
			CODE="${CODE}${MOV_V8_rdx}$(printEndianValue "${DATA_LEN}" $SIZE_64BITS_8BYTES)";
			CODE="${CODE}${SYSCALL}";
			echo -en "${CODE}" | base64 -w0;
		}
		else
		{
			# otherwise we expect all instruction already be in the data_addr_v as base64
			# so just throw it back
			echo -n "$DATA_ADDR_V";
		}
		fi;
		return;
	}
	fi
	error "b Not Implemented path type[$TYPE], DATA_ADDR_V=[$DATA_ADDR_V]";
	return;
}
