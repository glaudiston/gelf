#!/bin/bash
# System Interrupt call table for 64bit linux:
# http://www.cpu2.net/linuxabi.html
#
# x86 Instruction set
# https://en.wikipedia.org/wiki/X86_instruction_listings#Original_8086.2F8088_instructions
#
# Intel i64 and IA-32 Architectures
# https://software.intel.com/sites/default/files/managed/39/c5/325462-sdm-vol-1-2abcd-3abcd.pdf
# Linux syscall:
# https://blog.rchapman.org/posts/Linux_System_Call_Table_for_x86_64/
# See Table A-2. One-byte Opcode Map on Intel i64 documentation (page 2626)
# See Table B-13.  General Purpose Instruction Formats and Encodings for Non-64-Bit Modes (Contd.) (page 2658)
# x86 has:
# 8 general purpose registers
#  EAX: Accumulator: Used In Arithmetic operations
#  ECX: Counter: Used in loops and shift/rotate instructions
#  EDX: Data: Used in arithmetic operations and I/O operations
#  EBX: Base: Used as a pointer to data
#  ESP: Stack Pointer: Points to top of stack
#  EBP: Stack Base Pointer: Points to base of stack
#  ESI: Points to source in stream operations
#  EDI: Points to destination in streams operations
# 6 segment registers: points to memory segment addresses
# 1 flag register: used to support arithmetic functions and debugging.
#  EFLAG
# Instruction Pointer: Address of the next instruction to execute.
#  EIP
#
