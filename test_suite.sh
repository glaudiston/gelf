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
	cat $0 | grep -E "^test_[^(]*\(\)\{" | cut -d "(" -f1 | 
		while read f; 
		do echo -e " - $f\t...$($f)" & 
		done
		wait
		echo
}
run_all
