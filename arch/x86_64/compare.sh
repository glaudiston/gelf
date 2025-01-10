compare()
{
	local a="$1";
	local b="$2";
	local type_a="$3";
	local type_b="$4";
	debug "compare [$a](type $type_a) and [$b](type $type_b)";
	# types can be hardcoded, static or dynamic
	if [ "${type_a}" == "$SYMBOL_TYPE_HARD_CODED" ]; then
		mov rax "$a";
	fi;
	if [ "${type_b}" == "$SYMBOL_TYPE_HARD_CODED" ]; then
		mov rcx "$b";
	fi;
	if [ "${type_a}" == "$SYMBOL_TYPE_STATIC" ]; then
		mov rax "$a";
	fi;
	if [ "${type_b}" == "$SYMBOL_TYPE_STATIC" ]; then
		mov rcx "$b";
	fi;
	if [ "${type_a}" == "$SYMBOL_TYPE_DYNAMIC_ARGUMENT" ]; then
		printf "${LEA_V4_rax}$(printEndianValue "$a" "${SIZE_32BITS_4BYTES}")";
		mov "(rax)" rax;
	fi;
	if [ "${type_a}" == "$SYMBOL_TYPE_DYNAMIC" ]; then
		mov rax "$a";
		mov rax "(rax)";
	fi;
	if [ "${type_b}" == "$SYMBOL_TYPE_DYNAMIC" ]; then
		printf "${LEA_V4_rcx}$(printEndianValue "$b" "${SIZE_32BITS_4BYTES}")";
		mov rcx "(rcx)";
		mov rcx "(rcx)";
	fi;
	cmp rax rcx;
}
