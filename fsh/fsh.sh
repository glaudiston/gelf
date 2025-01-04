#!/bin/sh
SCRIPT_DIR=$(dirname $(realpath $0));

. ${SCRIPT_DIR}/monoid.sh

iterate()
{
	eval "c(){ $2; }";
	c $1 || return 0;
	$3 $1;
	iterate $(( $1 + 1 )) "$2" "$3";
}

filter()
{
	local data && read data || return 0;
	eval "c(){ $1; }" && c "${data}" && echo "${data}";
	local idx=${2:-0};
	filter "$1" "$((idx + 1))";
}

map()
{
	local data && read data || return 0;
	eval "c(){ $1; }" && c ${data};
	local idx=${2:-0};
	map "$1" "$((idx + 1))";
}

sort_json()
{
	local data=$(cat);
	#sort []      =   []
	#sort (p:xs)  =   sort [x | x<- xs, x <= p]
	#              ++ [p]
	#              ++ sort [x | x <- xs, x > p]
	local a=$(echo "$data" | take 1);
	[ "$a" == "" ] && return 0;
	local v=$(jq .s <<<$a);
	local set_a="local a='$a';";
	local set_b='local b="$1";';
	local not_equal='[ "$b" != "$a" ]';
	local direction="-lt";
	[ "$2" == "desc" ] && direction="-gt";
	local sort_condition='[ $(jq '$1'<<<"$b") '$direction' $(jq '$1'<<<"$a") ]'
	echo "$data" | filter "${set_a}${set_b}${sort_condition}" | sort_json "$1" "$2";
	echo $a;
	echo "$data" | filter "${set_a}${set_b}${not_equal} && ! ${sort_condition}" | sort_json "$1" "$2";
}

take(){
	head -$1
}
