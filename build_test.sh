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

expect(){
	r=$1;
	er=$2;
	eo=$3;
	if [ "$r" != "$er" ]; then
		fail "expected [${er}] but got [$r] at exit code";
		return 1;
	fi;

	if [ "$o" != "$eo" ]; then
		fail "expected [$eo] but got [$o]";
		return 2;
	fi;
	pass;
}

test_exit_code(){
	compile_test <<EOF
v:	42
exit	v
EOF
	run_test
	expect $? 42
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
