#!/bin/bash
# about the functions, I don't really want the {} brackets ...
# but it is easier to parse this way.
# since I need to read until detect it is closed,
# and without it I will be reading the next line outside the function.
inbloc=false;
read_code_bloc()
{
	local deep="$1"
	while read; do
		echo "$REPLY";
		# end of bloc
    # TODO it should consider the correct identation(tabs) and definition mark(:)
		if [[ "$(echo -n "$REPLY" | xxd --ps )" =~ 7d$ ]]; then # has closed brackets("}") at end of line
			if [ ! "$inbloc" == true ]; then
				return
			fi;
		fi;
	done;
}
