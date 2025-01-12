#!/bin/bash

if ! declare -F backetrace >/dev/null; then
backtrace(){
	local i=1;
	while caller $i;
	do let i++;
	done
}

function debug()
{
	local IFS='	'
	echo -e "[DEBUG] $@" >&2
}

function warn()
{
	local IFS='	'
	echo -e "[WARN] $@" >&2
}

function error()
{
	echo -e "[ERROR] $@" >&2
	backtrace >&2
}

fi;
