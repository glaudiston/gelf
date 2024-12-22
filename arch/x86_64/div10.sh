div10(){
	local code="";
	# 0xcccccccd is the float value for 0.1;
	# ba cd cc cc cc       	mov   $0xcccccccd,%edx
	local float_by_10="\xcd\xcc\xcc\xcc";
	MOV_V4_EDX="\xba";
	code="${code}${MOV_V4_EDX}${float_by_10}";
	code="${code}$(imul rdx rax | xd2esc)";
	echo -ne "$code" | base64 -w0;
}
