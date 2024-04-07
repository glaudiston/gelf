RED='\033[0;31m';
GREEN='\033[0;32m';
NC='\033[0m';

msg(){ echo -en "$1${FUNCNAME[1]^^}$NC "; shift; echo $@; }
error(){ msg $RED $@; }
fail(){ msg $RED $@; }
pass(){ msg $GREEN; }

compile_test(){
	mkdir -p tests
	./gelf <(cat) tests/${FUNCNAME[1]}.elf 2>tests/${FUNCNAME[1]}.build-stderr;
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
	local r=$1;
	local er=$2;
	local eo=$3;
	local o="$4";
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

run_all(){
	local test_list=$(cat $0 | grep -E "^test_[^(]*\(\)\{" | cut -d "(" -f1);
	local test_count=$(echo "$test_list" | grep -c "");
	local OUT_TEXT=$(echo "$test_list" | 
		while read f; 
		do
			{
				TEST_OUT=$(echo -e " - $f\t...$($f)");
				echo "$TEST_OUT";
				echo "$TEST_OUT" >&2;
			} &
		done;
		wait;
		echo
	);
	local test_count_fail=$(echo "$OUT_TEXT" | grep FAIL | grep -c "");
	local test_count_pass=$(echo "$OUT_TEXT" | grep PASS | grep -c "");
	echo "$test_list" | while read l; do
		echo -e "$OUT_TEXT" | grep -q "$l" || echo "WARNING: TEST RESULT MISSING FOR [$l] check if it is still running as zombie";
	done
	echo -e "
Resume:
	Total:\t$test_count
	Passed:\t$test_count_pass
	Failed:\t$test_count_fail"
}
run_all
