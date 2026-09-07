#!/bin/bash
# get_args_ptr recover the allocated address where the arguments should be stored
get_args_ptr()
{
	local snippets="$1";
	echo "$snippets" |
	grep "SYMBOL_TABLE,2,_INTERNAL_ARGS_MMAP," |
	tail -1 |
	cut -d, -f${SNIPPET_COLUMN_DATA_OFFSET};
}
