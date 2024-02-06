RED='\033[0;31m';
GREEN='\033[0;32m';
NC='\033[0m';

msg(){ echo -en "$1${FUNCNAME[1]^^}$NC: "; shift; echo $@; }
error(){ msg $RED $@; }
fail(){ msg $RED $@; }
pass(){ msg $GREEN ${FUNCNAME[1]} $@; }

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


test_hello_world(){
	compile_test <<EOF
stdout:	1
m:	hello world
write	stdout	m
with no error:	0
exit	with no error
EOF
	o=$(run_test);
	if [ "$r" != 0 ]; then
		fail "expected no error but got $r at exit code";
	fi;

	if [ "$o" != "hello world" ]; then
		fail "expected [hello world] but got [$o]";
	fi;
	pass;
}

assert(){
	testRet="$($1 | base64 -w0)";
	r=$?;
	expected_error="$2";
	expected_output="$3";
	if [ $r -ne $expected_error ]; then
		echo -e "${RED}FAIL${NC}: $1: $r";
		return $r;
	fi;
	expected_xxd=$(echo -n "${expected_output}" | xxd)
	tested_xxd=$(echo -n "${testRet}" | base64 -d | xxd)
	if [ "${tested_xxd}" != "${expected_xxd}" ]; then
		echo -e "${RED}FAIL${NC}: $1:\n\texpected: "[${expected_xxd}]"\n\t     got: "[${tested_xxd}]"";
		return 1;
	fi;
	echo -e "${GREEN}PASS${NC}: $1";
}

cat $0 | grep -E "^test_[^(]*\(\)\{" | cut -d "(" -f1 | 
	while read f; 
		do echo -ne "Test case: $f\t..."; $f; 
	done
