sys_execve equ 59
sys_exit equ 60

section .data
    child db "/bin/sh", 0

global _start

section .text
    _start:
        mov rdi, child      ; #1 filename
        lea rsi, [rsp + 8]      ; #2 argv
        mov rdx, 0      ; #3 envp = 0

        mov rax, sys_execve ; execve
        syscall
        mov rax, rdi        ; #1 Return value
        mov rax, sys_exit   ; exit
        syscall
