#!/bin/bash

. $(dirname $(realpath $BASH_SOURCE))/add.sh

add_test(){
	got=$(add rax 24);
	expected=4883c018;
	if [ "$got" != "$expected" ]; then
		echo "got [$got] but expected [$expected]" >&2;
	fi;
}
add_test

