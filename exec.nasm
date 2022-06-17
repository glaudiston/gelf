section .text
global _start

_start:
  mov rax, 59
  mov rdi, file  // *filename
  mov rsi, 0     // *argv
  mov rdx, 0     // *envp
  syscall

section .data
  file db "/bin/sh",0
