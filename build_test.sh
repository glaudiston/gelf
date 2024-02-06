#!/bin/bash
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
	expect $? 0 "hello world";
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
	expect $? 0 03
}

# this should be the last line on file:
. ./test_suite.sh
