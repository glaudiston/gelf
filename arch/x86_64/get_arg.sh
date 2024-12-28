# changes rsi, rcx
function detect_argsize()
{
	argn=$1;
	r_in=rsi;
	r_out=rcx;
	# figure out the data size dynamically.
	# To do it we can get the next address - the current address
	# the arg2 - arg1 address - 1(NULL) should be the data size
	# The last argument need to check the size by using 16 bytes, not 8.
	#   because 8 bytes lead to the NULL, 16 leads to the first env var.
	#
	# to find the arg size, use rcx as rsi
	# increment rcx by 8
	local non_hardcoded=$({
		local PTR_SIZE=8
		local ARGUMENT_DISPLACEMENT=$PTR_SIZE;
		mov $r_in $r_out;
		add $ARGUMENT_DISPLACEMENT $r_out;
		# mov to the real address (not pointer to address)
		mov "($r_out)" $r_out; # resolve pointer to address
		# and subtract rcx - rsi (resulting in the result(str len) at rcx)
		str_null_size_detection=$({
			# if rcx is zero, then we the input is the last argument and we are unable to detect size using method;
			# so fallback to string size detection
			mov "($r_in)" $r_in; # resolve pointer to address
			# now we have a problem:
			#  We do know how to detect a string length. but we don't know if this is a string.
			#  a string is a ptr to bytes, a int is just the bytes.
			#
			# we can use the stack frame counter as first item on rsp,
			# so we know that the first stack frame is all string,
			# but other requires an type array.
			detect_string_length $r_in $r_out
		});
		fast_str_size_detection=$({
			mov "($r_in)" $r_in; # resolve pointer to address
			sub $r_in $r_out;
		#	dec $r_out; # because it counts the null byte
			jump $(xcnt<<<$str_null_size_detection);
		});
		fast_str_size_detection_size=$(xcnt<<<$fast_str_size_detection);
		cmp $r_out $SYMBOL_TYPE_HARD_CODED;
		hardcoded_size_detection=$({
			mov 8 $r_out;
		})
		jnz $(xcnt<<<$hardcoded_size_detection);
		printf $hardcoded_size_detection;
		cmp rsp $r_out; # no argument; ptr == NULL
		jl $(xcnt<<<$fast_str_size_detection); #
		debug jz=[$(jz $fast_str_size_detection_size)]
		printf $fast_str_size_detection; # this only works when we have a next value; that is why we jump over if zero.
		printf "$str_null_size_detection";
	});
	local hard_coded=$({
		mov $r_in $r_out;
		mov "($r_out)" $r_out; # resolve pointer to address
		cmp $r_out 0;
		mov 8 $r_out;
		je $(xcnt<<<$non_hardcoded)
	});
	cmp r15 0; # r15 is zero only on root stack frame layer, so we don't have types on args
	jz $(xcnt<<<$hard_coded);
	printf $hard_coded;
	printf $non_hardcoded;
}

# get_arg should abstract two scenarios
# 1. when the program starts we have the stack like
#    { stack level(rbp), argc, program, args... };
# 2. when a function is called we have the stack like
#    { return address, return value addr, stack level(rbp), argc, function address, args... }
#
# stack level is zero at start frame and increase by 1 each frame deep 
# reflecting the number of stack frames to the root stack frame
#
# rbp should be set to stack level at the current frame;
#
# When program starts, we know everithing is a string, we can manage to parse argument as string.
#   we can even use substracting the next arg addr to detect the argument size (except last argument).
# but when a function is called, the argument can be anything. and this makes things complicated.
#
function get_arg()
{
	local argn="$1";
	local addr_ptr="$2";
	local args_typed=$({
		# this should be used only on call functions
		# so we use typed data and we have the return addr ptr on rsp
		add rsp r15; # r15 is argc
		mov r15 rsi;
		sub rsp r15;
		add $(( 8 * (1 + argn * 2) )) rsi; # "1 +" the first 8 bytes are the argc *2 because each argument has the type prefix byte
	});
	local args_root=$({
		# in process root level we don't have typed args and rsp points to argc
		mov rsp rsi;
		add $(( 8 * (1 + argn) )) rsi; # +1 because the first arg is the argc
		jump $(xcnt<<<${args_typed});
	});
	cmp r15 0; # this means we are not root level and rsp is the return value
	jnz $(xcnt<<<${args_root});
	printf $args_root;
	printf $args_typed;
	detect_argsize $argn;
	# now rcx has the string size
	cmp r15 0;
	skip_type=$({
		add 8 rsi;
	});
	jz $(xcnt<<<$skip_type);
	printf $skip_type;
	movs rsi $addr_ptr rcx;
	#detect_string_length rsi rdx; # rdx has the string size
	# if multiple of 8; set it to addr_ptr and we are done;
	# modulus8(int, int):
	#        mov    edx, edi
	#        sar     edx, 31
	#        shr     edx, 29
	#        lea     eax, [rdi+rdx]
	#        and     eax, 7
	#        sub     eax, edx
	#        ret
	# if not multiple of 8; we need to pad zeros to align 64 bits;
	# 	otherwise we will have issues with bsr and other number functions on registers
	# TODO: move string to memory:
	# 	because we need to zero higher bits in byte, avoiding further issues with bsr
	# TODO: set me address to the target address
	# MOV rsi addr_ptr
}
