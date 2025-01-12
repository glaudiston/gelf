#!/bin/bash
if ! declare -F is_addr_ptr >/dev/null; then
. number.sh
. encoding.sh

is_ptr(){
    [[ "$1" =~ ^\(.*\)$ ]];
}
is_addr_ptr(){
    [[ "$1" =~ ^\(.*\)$ ]];
}
fi;
