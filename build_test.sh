RED='\033[0;31m';
GREEN='\033[0;32m';
NC='\033[0m';

hello_world(){
	./make-elf.sh <(cat <<EOF
stdout:	1
m:	hello world
write	stdout	m
with no error:	0
exit	with no error
EOF
	) test.bin 2>test.err;

	chmod +x test.bin;
	./test.bin;
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

assert hello_world 0 "hello world";
