#!/bin/sh
SCRIPT_DIR=$(dirname $(realpath $0));
. ${SCRIPT_DIR}/fsh.sh

echo testing iterate
iterate 0 '[ $1 -lt 10 ]' echo |
	filter '[ $1 -lt 7 -a $1 -gt 1 ]' |
	map 'echo { \"id\": $1, \"s\": $RANDOM }' |
	sort_json .s desc |
	take 10

echo testing flatmap:
echo -e "a\nb\nc" | flatMap x y z
echo testing optional
getUser()
{
	read input;
	case $input in
	1)
		echo john
		;;
	2)
		echo mary
		;;
	*)
	esac;
}
getPet()
{
	read input;
	if [ "$input" == john ]; then
		echo dog
	fi;
}
getPetName()
{
	read input;
	if [ "$input" == dog ]; then
		echo "barker"
	fi;
}
echo 1| runOptional getUser | runOptional getPet | runOptional getPetName

echo testing withlogs
addOne()
{
	read x;
	let x++;
	echo $x;
}

square()
{
	read x;
	x=$(( x * x ));
	echo $x;
}

echo 2 | withLogs | runWithLogs square | runWithLogs addOne

