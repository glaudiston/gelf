#!/bin/bash
. $(dirname $(realpath $BASH_SOURCE))/add.sh
#
#
# When we start a process the memory is someyhing like:
# +-----------------+
# |      stack      |
# |-----------------|
# | environments... |
# | NULL            |
# | arguments...    |
# | arg count       | <-- RSP
# +-----------------+
#
# Each stack entry is a 8 byte pointer;
#
# Each argument is a pointer to a location where the argument string starts 
# but in linux, the argument size are not aligned in 8 bytes:
# +----------+----------------------+
# | mem pos  | 123456 7812345678... |
# |----------|----------------------|
# | byte val | arg 1\0arg 2\0       |
# |          | ^    ^ ^             |
# |          | A    B C             |
# +----------+----------------------+
# A = start of first argument;
# B = end of first argument;
# C = start of second argument;
# D = end of second argument;
#
# in this example, in the stack will be something like
# +-----------------+--------+----------+
# |      stack      | var    | value    |
# |-----------------|--------|----------|
# | environments... |        |          |
# | NULL            |        |          |
# | RSP+16          | arg[1] | ptr to 6 |
# | RSP+8           | arg[0] | ptr to 1 |
# | RSP             | argc   |     2    |
# +-----------------+--------+----------+
#
# The problem with this is that given all registers are fixed size in 8 bytes,
# if we copy "ptr to 1" into any register, say RSI, RSI will have the value
# "arg 1\0ar", instead of "arg 1\0\0\0" and this will break the compare logic.
#
# to my acknoledge, that means we can not just copy it to registers and compare,
# we need to make a logic to copy them to another place aligned to 8 bytes,
# so the string end has filled with NULL until the 8 bytes alignment. 
# and only then we can copy each 8 bytes block to registers and compare it.
#
# Seems to me that there is no way to compare n bytes in memory;
# So we need to copy the memory to register before using it in test or cmp instruction.
# so only way I know to test/compare strings in x86 is by comparing 2 registers.
#
# this premise is the reason why I have to alocate a memory address to copy 
# the argument bytes into.
#
# Other possible approaches can include:
# - explore SIMD instructions (e.g., AVX, SSE)
# - Use a loop with `lodsb` to compare bytes one at a time.
# - Use `repe cmpsb` for block comparisons of strings in memory.

ARCH_CONST_ARGUMENT_ADDRESS="_ARG_ADDR_ARG_ADDR_";
# changes rsi, rcx
detect_argsize()
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
	local PTR_SIZE=8
	local proc_arg=$({
		local ARGUMENT_DISPLACEMENT=$PTR_SIZE;
		mov $r_out $r_in;
		add $r_out $ARGUMENT_DISPLACEMENT $r_out;
		# mov to the real address (not pointer to address)
		mov $r_out "($r_out)"; # resolve pointer to address
		# and subtract rcx - rsi (resulting in the result(str len) at rcx)
		str_null_size_detection=$({
			# if rcx is zero, then we the input is the last argument and we are unable to detect size using method;
			# so fallback to string size detection
			mov $r_in "($r_in)"; # resolve pointer to address
			# now we have a problem:
			#  We do know how to detect a string length. but we don't know if this is a string.
			#  a string is a ptr to bytes, a int is just the bytes.
			#
			# we can use the stack frame counter as first item on rsp,
			# so we know that the first stack frame is all string,
			# but other requires an type array.
			detect_string_length $r_in $r_out;
		});
		fast_str_size_detection=$({
			mov $r_in "($r_in)"; # resolve pointer to address
			sub $r_out $r_in;
		#	dec $r_out; # because it counts the null byte
			jump $(xcnt<<<$str_null_size_detection);
		});
		fast_str_size_detection_size=$(xcnt<<<$fast_str_size_detection);
		cmp $r_out 0; # no argument; ptr == NULL
		jz $(xcnt<<<$fast_str_size_detection); #
		printf $fast_str_size_detection; # this only works when we have a next value; that is why we jump over if zero.
		printf "$str_null_size_detection";
	});
	local func_arg=$({
		mov $r_in rsp;
		add $r_in $(( 16 + (argn * 16) )); # retval_ptr + argc + ( type + argn_ptr )
		# at this point r_in == arg_type;
		mov $r_in "($r_in)";
		cmp $r_in $SYMBOL_TYPE_HARD_CODED;
		#cmp $r_out $SYMBOL_TYPE_HARD_CODED;
		hardcoded_size_detection=$({
			mov $r_out 8; # 8 bytes ( integer )
		})
		jnz $(xcnt<<<$hardcoded_size_detection);
		printf $hardcoded_size_detection;
		mov $r_out 8;
		je $(xcnt<<<$proc_arg)
	});
	cmp r15 0; # r15 is zero only on root stack frame layer, so we don't have types on args
	jz $(xcnt<<<$func_arg); # if zero goto proc_arg
	printf $func_arg;
	printf $proc_arg;
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
get_arg()
{
	debug get_arg $@;
	local args_ptr="$1"; # the mmap allocated root address where to store parsed/copied arguments.
	local argn="$2";	# index of the argument starting with 0 to the program name (or function address ptr);
	local arg_ptr="$3";	# address where to put the pointer to the target address where the argument will be copied into;
	mov rax "($args_ptr)"; # args_ptr is the memory value that has the pointer to mmap;
	mov rsi "(rax)";
	cmp rsi 0;
	local init_argsptr=$({
		mov "(rax)" rax;
		mov rsi "(rax)";
	});
	jne $(xcnt<<<$init_argsptr);
	printf $init_argsptr;
	add rsi 8;
	mov "$arg_ptr" rsi;
	mov "(rax)" rsi; # set the args_ptr value to the position where to write the argument;
	local func_arg=$({
		# this should be used only on call functions
		# so we use typed data and we have the return addr ptr on rsp
		add r15 rsp ; # r15 is argc
		mov rsi r15;
		sub r15 rsp;
		add rsi $(( 8 * (1 + argn * 2) )); # "1 +" the first 8 bytes are the argc *2 because each argument has the type prefix byte
	});
	local process_arg=$({
		# in process root level we don't have typed args and rsp points to argc
		mov rsi rsp;
		add rsi $(( 8 * (1 + argn) )); # +1 because the first arg is the argc
		jump $(xcnt<<<${func_arg});
	});
	cmp r15 0; # this means we are not root level and rsp is the return value
	jnz $(xcnt<<<${process_arg});
	printf $process_arg;
	printf $func_arg;
	detect_argsize $argn;
	# now rcx has the string size
	cmp r15 0;
	skip_type=$({
		printf $func_arg;
		add rsi 8;
	});
	jz $(xcnt<<<$skip_type);
	printf $skip_type;
	mov rax "($args_ptr)"; # args_ptr is the memory value that has the pointer to mmap;
	mov rax "(rax)";
	add rax rcx;
	mov "$args_ptr" rax;
	mov rdi "($arg_ptr)"; # update the root of args memory space (first ptr bytes) to the first free space (end of used memory)
	# here rax have the args_ptr
	movs rsi rdi rcx; # copy the (rsi) contents to (rdi), limit by rcx bytes
}

# The RSP (Register Stack Pointer) integer value is by convention the argc(argument count)
# In x86_64 is the rsp with integer size.
# It can be recovered in gdb by using
# (gdb) print *((int*)($rsp))
#
# But given it is a runtime only value, we don't have that value at build time,
# so we need to create a dynamic ref that can be evaluatet at runtime.
#
# My strategy is to set the constant _ARG_CNT_ then I can figure out latter that is means "rsp Integer"
# Probably should prefix it with the jump sort instruction to make sure those bytes will not affect
# the program execution. But not a issue now.

get_arg_count()
{
	# I don't need the bytecode at this point
	# I do need to store the value result form the bytecode to a memory address and set it to a var
	# because in inner functions I will be able to recover it using a variable
	#
	# # TODO HOW TO ALLOCATE A DYNAMIC VARIABLE IN MEMORY?
	# 	This function should receive the variable position (hex) to set
	# 	This function should copy the pointer value currently set at rsp and copy it to the address
	local addr="$1"; # memory where to put the argc count
	local code="";
	code="${code}$(mov r14 rsp)";
	code="${code}$(add r14 r15)"; # this allows set r15 as displacement and use this code in function get args
	code="${code}$(mov r14 "(r14)")";
	code="${code}$(mov $addr "r14")";
	echo -en "${code}";
}
