#ifndef _debugger_h_
#define _debugger_h_
#include <stdio.h>
#include <stdlib.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

#define TRUE 1
#define RAX 0
#define RCX 1
#define RDX 2
#define RBX 3
#define RSP 4
#define RBP 5
#define RSI 6
#define RDI 7
#define R8 8 
#define R9 9 
#define R10 10
#define R11 11
#define R12 12
#define R13 13
#define R14 14
#define R15 15

//Good ref https://www.felixcloutier.com/x86/
//
struct user_regs_struct regs;

extern void copy_bytes(pid_t child, long unsigned addr, char * target, size_t size);
extern void peek_string(pid_t child, void *addr, char* out);
#include "arch_x86-64.c"
#endif
