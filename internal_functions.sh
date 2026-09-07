#!/bin/bash

#TODO: use strategy pattern here, so functions should register themselves as internal
declare -gA internal_functions=( )
# functions coded by the gelf language that will have and address to be called as a function
is_internal_function(){
	[[ -v internal_functions[$1] ]];
}

internal_function_register(){
	internal_functions[$1]=$2
}

