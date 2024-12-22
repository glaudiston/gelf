function get_arg()
{
	local argn="$1";
	local addr_ptr="$2";
	local dyn_addr="$3";
	# MOV %rsp %rsi
	mov rsp rsi;
	add $(( 8 * (1 + argn) )) rsi; # "1 +" the first 8 bytes are the argc
	add r15 rsi;
	# RESOLVE rsi (Copy pointer address content to rsi)
	# TODO: detect string size:
	detect_argsize # this change rsi
	# now rdx has the string size
	mov $dyn_addr $addr_ptr;
	movs rsi $dyn_addr rcx
	#detect_string_length rsi rdx; # rdx has the string size
	# if multiple of 8; set it to addr_ptr and we are done;
	# modulus8(int, int):
	#        mov    edx, edi
	#        sar     edx, 31
	#        shr     edx, 29
	#        lea     eax, [rdi+rdx]
	#        and     eax, 7
	#        sub     eax, edx
	#        ret
	# if not multiple of 8; we need to pad zeros to align 64 bits;
	# 	otherwise we will have issues with bsr and other number functions on registers
	# TODO: move string to memory:
	# 	because we need to zero higher bits in byte, avoiding further issues with bsr
	# TODO: set me address to the target address
	# MOV rsi addr_ptr
}
