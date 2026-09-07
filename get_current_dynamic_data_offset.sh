#!/bin/bash
import_bash ./get_dynamic_data_size.sh;
get_current_dynamic_data_offset()
{
	local snippets="$1";
	local current_line="$2";
	local SNIPPETS="$(get_snippets_until_line "$current_line" "$snippets")";
	get_dynamic_data_size "$snippets"
}
