#!/bin/bash
import_bash ./get_static_data_size.sh
get_current_static_data_displacement()
{
	local snippets="$1";
	local current_line="$2";
	local SNIPPETS="$(get_snippets_until_line "$current_line" "$snippets")";
	local static_data_offset=$(get_static_data_size "$SNIPPETS");
	echo -n "$static_data_offset";
}
