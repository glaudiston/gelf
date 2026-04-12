#!/bin/bash
. $(dirname $(realpath $BASH_SOURCE))/pragma_once.sh && return 0
shopt -s extdebug # Activate BASH_ARGV/BASH_ARGC variables
backtrace(){
	local caller_info;
	echo backtrace:
	local argc=0;
	local argv_pos=$argc;
	#echo "FULL BASH_ARGC = [${BASH_ARGC[@]}]"
	#echo "FULL BASH_ARGV = [${BASH_ARGV[@]}]"
	for ((i=0;;i++,argv_pos+=argc));do
		caller_info=( $(caller $i) );
		[ "$?" != 0 ] && break;
		line=${caller_info[0]}
		funcname=${caller_info[1]};
		script=$(realpath "${caller_info[2]}" --relative-to .)
		argc=${BASH_ARGC[i+1]};
		args=$(echo ${BASH_ARGV[@]:argv_pos:argc} | tac -s ' ' | tr '\n' ' ' | sed 's/ $//g');
		printf "%-10s\t%-4s %s\n" "$script:$line" "$funcname" "$args"
	done|column -t -s $'\t'
}

