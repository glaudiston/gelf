concat()
{
	v=$(jq -R<<<"$@")
	cat | jq '[.[]] + [ '"$v"' ]'
}

runWithLogs()
{
	read j;
	pv=$(jq .result <<<"$j");
	v=$(echo $pv | $1);
	l="$1 from $pv to get $v"
	logs=$(jq .logs <<<"$j");
	logs=$(echo $logs | concat $l)
	echo '{ "result": '$v', "logs": '$logs' }'
}

withLogs()
{
	read x;
	echo '{ "result": '$x', "logs": [] }';
}


runOptional()
{
	local transform=$1;
	read input;
	[ "$input" == "" ] && return 0;
	echo "$input" | $transform
}


flatMap()
{
	declare -a args=$@
	read input;
	[ "$input" == "" ] && return;
	echo "$input$1"
	if [ "$2" != "" ]; then
		shift
		echo $input | flatMap $@;
	fi
	flatMap $args;
}

