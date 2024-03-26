#ifndef _debugger_h_
#define _debugger_h_
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>
#include <string.h>
#include <sys/wait.h>

#define TRUE 1

//Good ref https://www.felixcloutier.com/x86/
//
struct user_regs_struct regs;

extern int running_forks;
extern void printRegValue(pid_t child, unsigned long r, int deep);
extern void printRelevantRegisters(pid_t pid, struct user_regs_struct regs, int printNextData);
extern void copy_bytes(pid_t child, long unsigned addr, char * target, size_t size);
extern void peek_string(pid_t child, void *addr, char* out);
extern void peek_array(pid_t child, void *addr, char* out);
#define ANSI_COLOR_RED     "\x1b[31m"
#define ANSI_COLOR_GREEN   "\x1b[32m"
#define ANSI_COLOR_YELLOW  "\x1b[33m"
#define ANSI_COLOR_BLUE    "\x1b[34m"
#define ANSI_COLOR_MAGENTA "\x1b[35m"
#define ANSI_COLOR_CYAN    "\x1b[36m"
#define ANSI_COLOR_WHITE   "\x1b[37m"
#define ANSI_COLOR_GRAY    "\x1b[38;5;240m"
#define ANSI_COLOR_RESET   "\x1b[0m"
#ifdef __aarch64__
#include "arch_aarch64.c"
#endif
#ifdef __x86_64__
#include "arch_x86-64.c"
#endif
#endif
