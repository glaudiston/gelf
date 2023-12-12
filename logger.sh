#!/bin/bash

backtrace(){
	local i=1;
	while caller $i;
	do let i++;
	done
}

function debug()
{
	local IFS='	'
	echo "[DEBUG] $@" >&2
}

function warn()
{
	local IFS='	'
	echo "[WARN] $@" >&2
}

function error()
{
	echo "[ERROR] $@" >&2
	backtrace >&2
}
