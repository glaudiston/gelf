#!/bin/bash
. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/../../pragma_once/bash/import_bash.sh";
import_bash ../../fsh/fsh.sh;
nasm_hex()
{
	n=/dev/shm/n-${RANDOM}${RANDOM};
	cat > $n.asm; nasm -f elf64 -l $n.lst $n.asm;
	cat $n.lst | tr -s " " | cut -d" " -f4 | tr -d '\n-';
	rm -fr $n.lst $n.asm;
}

nasm_code()
{
	xxd --ps -r <<<"$@" | ndisasm -b 64 - | tr -s " " | cut -d " " -f3-;
}

asm_hex()
{
	as -al -o /dev/null |
		grep -v GAS |
		sed 's/^   1 .... \([^ ]*\).*/\1/g' |
		tr -d '\n';
}

declare -gA colors=(
	[PASS]=$'\033[32m' 
	[FAIL]=$'\033[31m'
	[reset]=$'\033[0m'
)
test_logger(){
	local c='';
	local rc='';
	[ -t 2 ] && {
		rc=${colors[reset]};
		c=${colors[$1]};
	};
	echo -e "$c$1$rc:" "${@:2}";
}
ok(){
	if [[ -v VERBOSE ]]; then
		test_logger PASS "$1; # ${2,,ii}";
	fi;
}
err(){
	local given="$1";
	local expected="${2,,}";
	local got="${3,,}";
	test_logger FAIL "given [$given] expected [${expected}] but got [${got}]";
	return 1;
}

test_op_reg_reg(){
	local got;
	got="$("$@" 2>/dev/null)";
	local expected;
	expected="$(nasm_hex<<<"$1 $2, $3")";
	if [ "${got,,}" != "${expected,,}" ]; then
		local given;
		given="$*";
		err "$given" "$expected" "$got";
		return;
	fi;
	ok "$*" "${got}";
}

test_op_ptrreg_reg() {
	local got;
	got="$("$1" "[$2]" "$3" 2>/dev/null)";
	local expected;
	expected="$(nasm_hex<<<"$1 [$2], $3")";
	if [ "${got,,}" != "${expected,,}" ]; then
		local given;
		given="$1 [$2] $3";
		err "$given" "$expected" "$got":
		return;
	fi;
	ok "$1 [$2] $3" "${got}";
}

test_op_reg_ptrreg() {
	local got;
	got="$("$1" "$2" "[$3]" 2>/dev/null)";
	local expected;
	expected="$(nasm_hex<<<"$1 $2, [$3]")";
	if [ "${got,,}" != "${expected,,}" ]; then
		local given;
		given="$1 $2 [$3]";
		err "$given" "$expected" "$got";
		return;
	fi;
	ok "$1 $2 [$3]" "${got}";
}

test_op_ptrsbits_reg(){
	local ubits="$2";
	[ "$ubits" == 64 ] && ubits=63; # bash does not support 64 so fallback to 63bit
	local r=$RANDOM$RANDOM$RANDOM$RANDOM
	local uval=$(( r % ( 2 ** (ubits-1) ) * (RANDOM % 2 ? 1 : -1) ));
	local got;
	got="$("$1" "[$uval]" "$3" 2>>/tmp/gelf.log)";
	local expected;
	expected="$(nasm_hex<<<"$1 [abs $uval], $3")";
	#echo given $1 [$uval] $3 got $got\; expected $expected
	if [ "${got,,}" != "${expected,,}" ]; then
		local given="$1 [$uval] $3";
		err "$given" "$expected" "$got that is $(nasm_code "$got")";
		return;
	fi;
	ok "$1 [$uval] $3" "${got}";
}
test_op_ubits_reg(){
	local ubits="$2";
	[ "$ubits" == 64 ] && ubits=63; # bash does not support 64 so fallback to 63bit
	local r=$RANDOM$RANDOM$RANDOM$RANDOM
	local uval=$(( r % ( 2 ** ubits ) - (2 ** (ubits-1)) ));
	local got;
	got="$("$1" "$uval" "$3" 2>>/tmp/gelf.log)";
	local expected;
	expected="$(nasm_hex<<<"$1 $uval, $3")";
	if [ "${got,,}" != "${expected,,}" ]; then
		local given="$1 $uval $3";
		err "$given" "$expected" "$got that is $(nasm_code "$got")";
		return;
	fi;
	ok "$1 $uval $3" "${got}";
}
test_op_ubits_ptrreg(){
	test_op_ubits_reg "$@"
}
test_op_u8_reg(){
	test_op_ubits_reg "$1" 8 "$2";
}
test_op_u8_ptrreg(){
	test_op_ubits_ptrreg "$1" 8 "$2";
}
test_op_ptrs32_reg(){
	test_op_ptrsbits_reg "$1" 32 "$2";
}
test_op_u32_reg(){
	test_op_ubits_reg "$1" 32 "$2";
}
test_op_u32_ptrreg(){
	test_op_ubits_ptrreg "$1" 32 "$2";
}
test_op_u64_reg(){
	test_op_ubits_reg "$1" 64 "$2";
}

test_op_reg_sbits(){
	local ubits="$3";
	[ "$ubits" == 64 ] && ubits=63; # bash does not support 64 so fallback to 63bit
	local r=$RANDOM$RANDOM$RANDOM$RANDOM
	local uval=$(( r % (2 ** (ubits-1)) * (RANDOM % 2 ? -1: 1) ));
	local got;
	got="$("$1" "$2" "$uval" 2>>/tmp/gelf.log)";
	local expected;
	expected="$(nasm_hex<<<"$1 $2, $uval")";
	if [ "${got,,}" != "${expected,,}" ]; then
		local given="$1 $2 $uval";
		err "$given" "$expected" "$got that is $(nasm_code "$got")";
		return;
	fi;
	ok "$1 $2 $uval" "${got}";
}

test_op_reg_ubits(){
	local ubits="$3";
	[ "$ubits" == 64 ] && ubits=63; # bash does not support 64 so fallback to 63bit
	local r=$RANDOM$RANDOM$RANDOM$RANDOM
	local uval=$(( r % ( 2 ** ubits ) ));
	local got;
	got="$("$1" "$2" "$uval" 2>>/tmp/gelf.log)";
	local expected;
	local nasm_code="$1 $2, $uval";
	expected="$(nasm_hex<<<"$nasm_code")";
	#echo "nasm_code=$nasm_code; expected $expected; got $got"
	if [ "${got,,}" != "${expected,,}" ]; then
		local given="$1 $2 $uval";
		err "$given" "$expected" "$got that is $(nasm_code "$got")";
		return;
	fi;
	ok "$1 $2 $uval" "${got}";
}

test_op_reg_s8(){
	test_op_reg_sbits "$1" "$2" 8;
}
test_op_reg_s32(){
	test_op_reg_sbits "$1" "$2" 32;
}
test_op_reg_s64(){
	test_op_reg_sbits "$1" "$2" 64;
}
test_op_reg_u8(){
	test_op_reg_ubits "$1" "$2" 8;
}
test_op_reg_u32(){
	test_op_reg_ubits "$1" "$2" 32;
}
test_op_reg_u64(){
	test_op_reg_ubits "$1" "$2" 64;
}
