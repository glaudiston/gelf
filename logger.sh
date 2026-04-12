#!/bin/bash
. $(dirname $(realpath $BASH_SOURCE))/pragma_once.sh && return 0
. $(dirname $(realpath $BASH_SOURCE))/backtrace.sh

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

