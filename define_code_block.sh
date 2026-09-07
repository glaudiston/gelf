define_code_block(){
	# TODO add identation validation
	#
	# TODO prepend a jump move over the end of this block, so this code will be executed only if a explicit goto or call is requested.
	new_bloc="$(parse_code_bloc "$SNIPPETS")";
	local bloc_name=$(echo "$new_bloc" | cut -d, -f${SNIPPET_COLUMN_SUBNAME})
	if [ "$SNIPPETS" == "" ]; then
		SNIPPETS="$( echo "$new_bloc")";
	else
		SNIPPETS="$( echo -e "$SNIPPETS\n$new_bloc")";
	fi;
	echo "$new_bloc";
}

