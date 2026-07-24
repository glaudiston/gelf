#!/bin/bash
xd(){
	# we can use $- to check the current shell set opts
	set -eumo pipefail;
	local LC_ALL=C;
	local IFS=;
	local rec; #read exit code
	local n; # chunk read size
	local i;
	local read_step_size=16;
	while true;
	do
		read -n $read_step_size -d '' -r data_chunk && rec=0 || rec=$?;
		n=${#data_chunk};
		for ((i=0;i<n;i++));
		do
			printf %02x "'${data_chunk:i:1}"
		done
		(( rec == 0 && n < read_step_size )) && printf 00;
		(( rec != 0 )) && break;
	done
}
