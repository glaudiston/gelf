#!/bin/bash
#
# tests should be functions prefixed with test_A
#

test_sys_exit_code(){
	compile_test <<EOF
:	v	42
!	sys_exit	v
EOF
	run_test
	expect $? 42
}

test_hello_world(){
	compile_test <<EOF
:	stdout	1
:	m	hello world
!	sys_write	stdout	m
:	with no error	0
!	sys_exit	with no error
EOF
	o=$(run_test);
	expect $? 0 "hello world" "$o";
}

test_hello_world_base64(){
	compile_test <<EOF
:	input	base64
:	m	aGVsbG8Jd29ybGQK
:	input	ascii
:	stdout	1
!	sys_write	stdout	m
:	ok	0
!	sys_exit	ok
EOF
	o="$(run_test | xxd --ps)";
	eo="68656c6c6f09776f726c640a";
	expect $? 0 "$eo" "$o";
}

test_sys_write_hard_coded_value(){
	compile_test <<EOF
:	stdout	1
:	v	65536
!	sys_write	stdout	v
:	with no error	0
!	sys_exit	with no error
EOF
	o=$(run_test | xxd);
	eo="$(echo -n 0000010000000000 | xxd --ps -r | xxd)"; # little endian value of 65536 (64bit)
	expect $? 0 "$eo" "$o";
}

test_arg_count(){
	compile_test <<EOF
:	stdout	1
:	c	@$
!	sys_write	stdout	c
:	with no error	0
!	sys_exit	with no error
EOF
	o=$(run_test abc def|xxd --ps);
	expect $? 0 03 "$o"
}

test_sys_write_out_arg(){
	compile_test <<EOF
:	stdout	1
:	a	@1
!	sys_write	stdout	a
:	with no error	0
!	sys_exit	with no error
EOF
	o=$(run_test abc def);
	expect $? 0 abc "$o";
}


# a known bug is that the sys_write autodetect the size by the \x00 byte;
# so the read will stop at the first \x00 byte
test_read_text_file(){
	local tmpfile=/dev/shm/gelf-test-$RANDOM
	head /dev/random | xxd > $tmpfile;
	chk=$(md5sum $tmpfile | cut -d " " -f1);
	compile_test <<EOF
:	file name	$tmpfile
:	f	<=	file name
:	stdout	1
!	sys_write	stdout	f
:	with no error	0
!	sys_exit	with no error
EOF
	o=$(run_test | md5sum | cut -d " " -f1);
	expect $? 0 $chk "$o";
	rm $tmpfile
}

test_read_virtual_file(){
	chk=$(cat /proc/sys/vm/mmap_min_addr);
	compile_test <<EOF
:	file name	/proc/sys/vm/mmap_min_addr
:	f	<=	file name
:	stdout	1
!	sys_write	stdout	f
:	with no error	0
!	sys_exit	with no error
EOF
	o=$(run_test);
	expect $? 0 $chk "$o";
}

test_exec(){
	compile_test <<EOF
:	cmd	/usr/bin/whoami
!	cmd
:	ok	0
!	sys_exit	ok
EOF
	chk=$(whoami)
	o=$(run_test)
	expect $? 0 $chk "$o"
}

test_exec_capture_stdout(){
	compile_test <<EOF
:	cmd	/usr/bin/whoami
:	v	!	cmd
:	s	command output: 
:	t	s	v
:	stdout	1
!	sys_write	stdout	t
:	success	0
!	sys_exit	success
EOF
	eo=$(echo -n "command output: "; /usr/bin/whoami)
	o=$(run_test)
	expect $? 0 "$eo" "$o"
}

test_exec_with_input_args(){
	compile_test <<EOF
:	cmd	@1
:	arg a	@2
:	arg b	@3
!	cmd	arg a	arg b
:	succeed	0
!	sys_exit	succeed
EOF
	cmd="/usr/bin/ls";
	arg_a="-1";
	arg_b="/";
	chk=$(LANG=C "$cmd" "$arg_a" "$arg_b"|md5sum | cut -d " " -f1);
	expect_sys_exit=$?
	out_test=$(run_test "$cmd" "$arg_a" "$arg_b" | md5sum | cut -d " " -f1);
	expect $? "$expect_sys_exit" "$chk" "$out_test";
}

test_exec_with_static_args(){
# this should be the last line on file:
	compile_test <<EOF
:	cmd	/usr/bin/id
:	args	-u
!	cmd	args
:	success	0
!	sys_exit	success
EOF
	chk=$(id -u)
	o=$(run_test)
	expect $? 0 $chk "$o"
}

test_concat_static_symbols(){
	compile_test <<EOF
:	a	abc
:	b	def
:	c	a	b
:	out	1
!	sys_write	out	c
:	d	0
!	sys_exit	d
EOF
	o=$(run_test)
	expect $? 0 "abcdef" "$o"
}

test_concat_dyn_symbols(){
	compile_test <<EOF
:	a	@1
:	b	@2
:	c	a	b
:	out	1
!	sys_write	out	c
:	d	0
!	sys_exit	d
EOF
	o=$(run_test "abc" "def")
	expect $? 0 "abcdef" "$o"
}

test_concat_stat_dyn_symbols(){
	compile_test <<EOF
:	s	xpto
:	a	@1
:	b	@2
:	c	s	a	b
:	out	1
!	sys_write	out	c
:	d	0
!	sys_exit	d
EOF
	o=$(run_test "abc" "def")
	expect $? 0 "xptoabcdef" "$o"
}

test_concat_dyn_stat_symbols(){
	compile_test <<EOF
:	s	xpto
:	a	@1
:	b	@2
:	c	b	s	a
:	out	1
!	sys_write	out	c
:	d	0
!	sys_exit	d
EOF
	o=$(run_test "abc" "def")
	expect $? 0 "defxptoabc" "$o"
}

test_exec_concat(){
	compile_test <<EOF
:	a	/usr/bin/
:	b	@1
:	c	a	b
!	c	c
:	succeed	0
!	sys_exit	succeed
EOF
	o=$(run_test ls)
	# known bug space inside arguments are trimed
	eo=$(/usr/bin/ls /usr/bin/ls)
	expect $? 0 "$eo" "$o"
}

test_custom_bytecode(){
	compile_test <<EOF
# mov 60, %rax
# 48b83c00000000000000
48c7c03c000000
# mov 42, %rdi
# 64bit: 48bf2a00000000000000
48c7c72a000000
# syscall
0f05
EOF
	o=$(run_test)
	expect $? 42 "" "$o"
}

test_fn(){
	compile_test <<EOF
:	fn	{
	:	r1	1
	!	sys_exit	r1
}
!	fn
:	r2	2
!	sys_exit	r2
EOF
	o=$(run_test)
	expect $? 1
}

test_fn_args(){
	compile_test <<EOF
:	fn	{
	:	af	@1
	:	bf	@2
	:	cf	+	af	bf
	!	ret	cf
}
:	a	1
:	b	2
:	c	[]	fn	a	b
:	d	!	c
!	sys_exit	d
EOF
	o=$(run_test)
	expect $? 3
}

test_check_var_is_not_empty(){
	compile_test <<EOF
:	ok	{
	:	suc	1
	!	sys_exit	suc
}
:	value	@1
:	empty	
:	test	?	value	empty
!	test	?=	ok
:	err	2
!	sys_exit	err
EOF
	o=$(run_test abc)
	expect $? 2
}

test_check_var_is_empty(){
	compile_test <<EOF
:	ok	{
	:	suc	1
	!	sys_exit	suc
}
:	value	@1
:	empty	
:	test	?	value	empty
!	test	?=	ok
:	err	2
!	sys_exit	err
EOF
	o=$(run_test)
	expect $? 1
}

test_condition(){
	compile_test <<EOF
:	success	{
	:	r0	0
	!	sys_exit	r0
}
:	r1	1
:	r2	1
:	test	?	r1	r2
!	test	?=	success
!	sys_exit	r1
EOF
	o=$(run_test)
	expect $? 0
}

test_loop(){
	compile_test <<EOF
:	end	{
	!	sys_exit	0
}
:	loop	{
	:	v	+	1
	:	t	?	v	5
	!	t	?=	end
}
!	loop
:	err	1
!	sys_exit	err
EOF
	o=$(run_test)
	expect $? 0
}

test_recursive_call(){
	compile_test <<EOF
:	end	{
	!	sys_exit	0
}
:	loop	{
	:	v	+	1
	:	t	?	v	5
	!	t	?=	end
	!	loop
}
!	loop
:	err	1
!	sys_exit	err
EOF
	o=$(run_test)
	expect $? 0
}

test_start_code(){
	compile_test <<EOF
:	stdout	1
:	a	a
!	sys_write	stdout	a
:	f	{
	:	err	1
	!	sys_exit	err
}
:	b	b
!	sys_write	stdout	b
:	ok	0
!	sys_exit	ok
EOF
	o=$(run_test)
	expect $? 0 "ab" "$o"
}

test_fibonacci_generate(){
	compile_test <<EOF
:	stdout	1
:	fib	{
	:	prev	@1
	:	last	@2
	:	limit	@3
	:	fibn	+	prev	last
	:	toStop	?	fibn	limit
	!	toStop	?>	ret
	:	narr	[]	.i2s	fibn
	:	n	!	narr
	!	sys_write	stdout	n
	:	f	[]	fib	last	fibn	limit
	!	f
	!	ret
}
:	a	0
:	b	1
:	c	1000
:	d	[]	fib	a	b	c
!	d
:	ok	0
!	sys_exit	ok
EOF
	o=$(run_test)
	expect $? 0
}

test_s2i(){
	compile_test <<EOF
:	stdout	1
:	nstr	@1
#	convert the arg to integer
:	na	[]	.s2i	nstr
:	n	!	na
!	sys_exit	n
EOF
	n=$(( RANDOM % 126 ));
	{
		o=$(run_test 0);
		expect $? 0;
		o=$(run_test $n);
		expect $? $n;
	} | tr '\n' ';';
	echo
}

test_i2s(){
	compile_test <<EOF
:	stdout	1
:	nstr	@1
#	convert the arg to integer
:	na	[]	.s2i	nstr
:	n	!	na
#	convert integer to string
:	sna	[]	.i2s	n
:	sn	!	sna
!	sys_write	stdout	sn
!	sys_exit	n
EOF
	n=$(( RANDOM % 126 ));
	{
		o=$(run_test 0)
		expect $? 0 0 $o
		o=$(run_test $n)
		expect $? $n $n $o
	} | tr '\n' ';';
	echo
}

test_sys_geteuid(){
	compile_test <<EOF
:	stdout	1
:	uid	!	sys_geteuid
:	a	[]	.i2s	uid
:	textuid	!	a
!	sys_write	stdout	textuid
:	ok	0
!	sys_exit	ok
EOF
	o=$(run_test);
	eo=$(id -u)
	expect $? 0 $eo $o;
}

test_ilog10(){
	# good numbers to test
	numbers_to_test="$({
	for (( n=1; n < 2 ** 32; n = n * 10 )); do if [ "$n" -gt 1 ]; then echo $(( n -1 )); fi; echo $n; echo $(( n +1 )); done;
	for (( n=2; n < 2 ** 32; n = n * 2 )); do echo $(( n -1 )); if [ $n == $(( 2 ** 31 )) ]; then break; fi;echo $n; echo $((n +1)); done;
	} | sort -n | uniq)";
	numbers_to_test="${RANDOM}"
	for n in $numbers_to_test; do
		echo -n "n=$n..." #| tee /dev/stderr;
		local l=$(echo "scale=18; l($n)/l(10)" | bc -l | sed 's/^[.].*/0/; s/[.].*//');
		compile_test <<EOF
:	n	$n
:	c	[]	.ilog10	n
:	x	!	c
!	sys_exit	x
EOF
		o=$(run_test);
		expect $? $l #| tee /dev/stderr;
	done;
}

. ./test_suite.sh
