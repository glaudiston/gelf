#!/bin/bash

is_valid_number()
{
	[ "$1" -eq "$1" ] 2>/dev/null;
	return $?
}

