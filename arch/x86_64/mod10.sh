mod10(){
	local code="";
	code="${code}$(div10 | b64_2esc)";
	# shr    $0x23,%rax
	code="${code}${SHR_V1_rax}\x23";
	# lea    (%rax,%rax,4),%eax
	code="${code}${LEA_rax_rax_4}";
	# add    %eax,%eax
	code="${code}${ADD_EAX_EAX}";
	echo -en "$code" | base64 -w0;
}
