; tiny.asm
BITS 32
EXTERN _exit
GLOBAL _start
SECTION .text
_start:
	mov	eax, 60
	mov	edi, 42
	syscall
