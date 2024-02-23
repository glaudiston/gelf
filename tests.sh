#!/bin/bash
#
# tests should be functions prefixed with test_A
#

test_exit_code(){
	compile_test <<EOF
v:	42
exit	v
EOF
	run_test
	expect $? 42
}

test_hello_world(){
	compile_test <<EOF
stdout:	1
m:	hello world
write	stdout	m
with no error:	0
exit	with no error
EOF
	o=$(run_test);
	expect $? 0 "hello world" "$o";
}

test_arg_count(){
	compile_test <<EOF
stdout:	1
c::$
write	stdout	c
with no error:	0
exit	with no error
EOF
	o=$(run_test abc def|xxd --ps);
	expect $? 0 03 "$o"
}

test_write_out_arg(){
	compile_test <<EOF
stdout:	1
a::	1
write	stdout	a
with no error:	0
exit	with no error
EOF
	o=$(run_test abc def);
	expect $? 0 abc "$o";
}


# a known bug is that the write autodetect the size by the \x00 byte;
# so the read will stop at the first \x00 byte
test_read_text_file(){
	head /dev/random | xxd > .tmp.file;
	chk=$(md5sum .tmp.file | cut -d " " -f1);
	compile_test <<EOF
file name:	./.tmp.file
f:<=	file name
stdout:	1
write	stdout	f
with no error:	0
exit	with no error
EOF
	o=$(run_test | md5sum | cut -d " " -f1);
	expect $? 0 $chk "$o";
}

test_exec(){
# this should be the last line on file:
	compile_test <<EOF
cmd:	/usr/bin/whoami
!	cmd
success:	0
exit	success
EOF
	chk=$(whoami)
	o=$(run_test)
	expect $? 0 $chk "$o"
}

test_exec_with_input_args(){
	compile_test <<EOF
cmd::	1
arg a::	2
arg b::	3
!	cmd	arg a	arg b
succeed:	0
exit	succeed
EOF
	cmd="/usr/bin/ls";
	arg_a="-l";
        arg_b="/";
	chk=$("$cmd" "$arg_a" "$arg_b"|md5sum | cut -d " " -f1);
	expect_exit=$?
	out_test=$(run_test "$cmd" "$arg_a" "$arg_b" | md5sum | cut -d " " -f1);
	expect $? "$expect_exit" "$chk" "$out_test";
}

test_exec_with_args(){
# this should be the last line on file:
	compile_test <<EOF
cmd:	/usr/bin/id
args:	-u
!	cmd	args
success:	0
exit	success
EOF
	chk=$(id -u)
	o=$(run_test)
	expect $? 0 $chk "$o"
}

test_concat_static_symbols(){
	compile_test <<EOF
a:	abc
b:	def
c:|	a	b
out:	1
write	out	c
d:	0
exit	d
EOF
	o=$(run_test)
	expect $? 0 "abcdef" "$o"
}

test_concat_dyn_symbols(){
	compile_test <<EOF
a::	1
b::	2
c:|	a	b
out:	1
write	out	c
d:	0
exit	d
EOF
	o=$(run_test "abc" "def")
	expect $? 0 "abcdef" "$o"
}

. ./test_suite.sh
