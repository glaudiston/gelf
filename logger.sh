#!/bin/bash

backtrace(){
	local i=1;
	while caller $i;
	do let i++;
	done
}

function debug()
{
	echo "[DEBUG] $@" >&2
}

function error()
{
	echo "[ERROR] $@" >&2
	backtrace >&2
}
