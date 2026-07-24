#!/bin/bash
. ./xd.sh
test_xd(){
	v=$(echo abcdefghijklmnopqrstuvwxyz | xd)
	exp_v=$(echo abcdefghijklmnopqrstuvwxyz | xxd --ps | tr -d '\n')
	if [ "$v" != "$exp_v" ]; then 
		echo failed
		return 1;
	fi;
	exp_v=$(dd status=none if=/dev/random bs=1024 count=1 | xxd --ps | tr -d '\n');
	v=$( echo -n "$exp_v" | xxd --ps -r | xd );
	if [ "$v" != "$exp_v" ]; then 
		echo random test failed
		echo -e "expected:\n\t$exp_v\nbut got:\n\t$v"
		return 1;
	fi;
	echo OK
}

test_xd
