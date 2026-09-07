#!/usr/bin/env bash
. "$(dirname "$(realpath "${BASH_SOURCE[0]}")")/pragma_once/bash/import_bash.sh";

import_bash <<-EOF
	./struct_parsed_snippet.sh
	./internal_functions.sh
	../logger/bash/logger.sh
EOF

detect_internal_dependencies(){
	local snippets="$1";
	local tmpfile="${2}.tmp"
	printf "" > "$tmpfile";
	unsorted_deps="$(
		echo "$snippets" |
			cut -d, -f"$SNIPPET_COLUMN_DEPENDENCIES" |
			tr "," "\n" | uniq | sed '/^$/d' |
		while read -r dep;
		do
			info "found [$dep]"
			if is_internal_function "$dep"; then
				info "$dep is a internal func"
				echo "$dep";
			else
				info "$dep is not a internal func"
			fi;
		done;
	)";
	info "unsorted_deps=$unsorted_deps"
	echo "$unsorted_deps" |
	while read -r dep;
	do
		if grep -q "$dep" "$tmpfile"; then
			continue;
		fi;
		echo "$dep" >> "$tmpfile";
	done;
	cat "$tmpfile";
}

