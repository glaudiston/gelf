#!/bin/sh
. fsh/fsh.sh

iterate 0 '[ $1 -lt 10 ]' echo |
	filter '[ $1 -lt 7 -a $1 -gt 1 ]' |
	map 'echo { \"id\": $1, \"s\": $RANDOM }' |
	sort_json .s desc |
	take 10
