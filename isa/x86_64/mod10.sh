mod10(){
	local code="";
	code="${code}$(div10 | b64_2esc)";
	# shr    $0x23,%rax
	code="${code}${SHR_V1_rax}\x23";
	# lea    (%rax,%rax,4),%eax
	code="${code}${LEA_rax_rax_4}";
	# add    %eax,%eax
	code="${code}$(add eax eax | b64_2esc)";
	echo -en "$code" | base64 -w0;
}
