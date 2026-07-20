#!/bin/bash
. $(dirname $(realpath $BASH_SOURCE))/../../pragma_once/bash/import_bash.sh
import_bash ../../fsh/fsh.sh;
nasm_hex()
{
	n=/dev/shm/n-${RANDOM}${RANDOM};
	cat > $n.asm; nasm -f elf64 -l $n.lst $n.asm;
	cat $n.lst | tr -s " " | cut -d" " -f4;
	rm -fr $n.lst $n.asm;
}

asm_hex()
{
	as -al -o /dev/null |
		grep -v GAS |
		sed 's/^   1 .... \([^ ]*\).*/\1/g' |
		tr -d '\n';
}

declare -gA colors=(
	[ok]=$'\033[32m' 
	[error]=$'\033[31m'
	[reset]=$'\033[0m'
)
test_logger(){
	local c='';
	local rc='';
	[ -t 2 ] && {
		rc=${colors[reset]};
		c=${colors[$1]};
	};
	echo -e "$c$1$rc: ${@:2}";
}
ok(){
	test_logger ok "[$1] == [${2,,ii}]";
}
err(){
	local given="$1";
	local expected="${2,,}";
	local got="${3,,}";
	test_logger error "given [$given] expected [${expected}] but got [${got}]";
	return 1;
}

test_op_reg_reg(){
	local got="$($@ 2>/dev/null)";
	local expected="$(nasm_hex<<<"$1 $2, $3")";
	if [ "${got,,}" != "${expected,,}" ]; then
		local given="$@";
		err "$given" "$expected" "$got":
		return;
	fi;
	ok "$*" "${got}";
}

test_op_reg_u8(){
	local u8=$(( RANDOM % ( 2 ** 8 ) - (2 ** 7) ));
	local got="$($@ $u8 2>>/tmp/gelf.log)";
	local expected="$(nasm_hex<<<"$1 $2, $u8")";
	if [ "${got,,}" != "${expected,,}" ]; then
		local given="$@ $u8";
		err "$given" "$expected" "$got";
		return;
	fi;
	ok "$* $u8" "${got}";
}
