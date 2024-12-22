compare()
{
	local a="$1";
	local b="$2";
	local type_a="$3";
	local type_b="$4";
	# types can be hardcoded, static or dynamic
	local code="";
	if [ "${type_a}" == "$SYMBOL_TYPE_HARD_CODED" ]; then
		code="${code}${MOV_V4_rax}$(printEndianValue "$a" "${SIZE_32BITS_4BYTES}")";
	fi;
	if [ "${type_b}" == "$SYMBOL_TYPE_HARD_CODED" ]; then
		code="${code}${MOV_V4_rcx}$(printEndianValue "$b" "${SIZE_32BITS_4BYTES}")";
	fi;
	if [ "${type_a}" == "$SYMBOL_TYPE_STATIC" ]; then
		code="${code}${MOV_V4_rax}$(printEndianValue "$a" "${SIZE_32BITS_4BYTES}")";
	fi;
	if [ "${type_b}" == "$SYMBOL_TYPE_STATIC" ]; then
		code="${code}${MOV_V4_rcx}$(printEndianValue "$b" "${SIZE_32BITS_4BYTES}")";
	fi;
	if [ "${type_a}" == "$SYMBOL_TYPE_DYNAMIC_INDIRECT" ]; then
		code="${code}${LEA_V4_rax}$(printEndianValue "$a" "${SIZE_32BITS_4BYTES}")";
		code="${code}$(mov "(rax)" rax | xd2esc)";
		code="${code}$(mov "(rax)" rax | xd2esc)";
	fi;
	if [ "${type_a}" == "$SYMBOL_TYPE_DYNAMIC" ]; then
		code="${code}${LEA_V4_rax}$(printEndianValue "$a" "${SIZE_32BITS_4BYTES}")";
		code="${code}$(mov "(rax)" rax | xd2esc)";
	fi;
	if [ "${type_b}" == "$SYMBOL_TYPE_DYNAMIC" ]; then
		code="${code}${LEA_V4_rcx}$(printEndianValue "$b" "${SIZE_32BITS_4BYTES}")";
		code="${code}$(mov "(rcx)" rcx | xd2esc)";
		code="${code}$(mov "(rcx)" rcx | xd2esc)";
	fi;
	code="${code}$(cmp rax rcx | xd2esc)";
	echo -en "${code}" | base64 -w0;
}
