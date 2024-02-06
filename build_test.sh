RED='\033[0;31m';
GREEN='\033[0;32m';
NC='\033[0m';

msg(){ echo -en "$1${FUNCNAME[1]^^}$NC "; shift; echo $@; }
error(){ msg $RED $@; }
fail(){ msg $RED $@; }
pass(){ msg $GREEN; }

compile_test(){
	mkdir -p tests
	./make-elf.sh <(cat) tests/${FUNCNAME[1]}.elf 2>tests/${FUNCNAME[1]}.build-stderr;
	r=$?;
	if [ $r -ne 0 ]; then
		error	compilation failed. See tests/${FUNCNAME[1]}.build-stderr;
		return $r;
	fi;
	chmod +x ./tests/${FUNCNAME[1]}.elf
}

run_test(){
	./tests/${FUNCNAME[1]}.elf $@
}

test_exit_code(){
	compile_test <<EOF
v:	42
exit	v
EOF
	r=$?;
	if [ $r -ne 0 ]; then
		fail build error: $r;
		return $r;
	fi;
	run_test;
	r=$?
	if [ $r -ne 42 ]; then
		fail expected exit 42 but got $r;
		return 1;
	fi
	pass;
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
	r=$?;
	if [ "$r" != 0 ]; then
		fail "expected no error but got $r at exit code";
	fi;

	if [ "$o" != "03" ]; then
		fail "expected [03] but got [$o]";
	fi;
	pass;
}

expect(){
	r=$1;
	er=$2;
	eo=$3;
	if [ "$r" != 0 ]; then
		fail "expected no error but got $r at exit code";
		return 1;
	fi;

	if [ "$o" != "hello world" ]; then
		fail "expected [hello world] but got [$o]";
		return 2;
	fi;
	pass;
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

cat $0 | grep -E "^test_[^(]*\(\)\{" | cut -d "(" -f1 | 
	while read f; 
		do echo -ne "Test case: $f\t..."; $f; 
	done
