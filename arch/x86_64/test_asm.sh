#!/bin/bash

asm_hex()
{
	as -al -o /dev/null |
		grep -v GAS |
		sed 's/^   1 .... \([^ ]*\).*/\1/g' |
		tr -d '\n';
}
