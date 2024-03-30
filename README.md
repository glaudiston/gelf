Gelf - What is this?
====================
This started as a playground for elf related stuff. I created a bash script to generate a tiny working elf file. Just using bash. Useless for anything else than learn how elf files work. But as it grows up started to look like a compiler. Then I started to define my own source file syntax. Maybe some day I can call it my own programming language. For now it is just a prototype.

In early tests it did work on native linux `x86_64` and in a `aarch64`(osx, using ubuntu within docker container). Currently it is only working on `x86_64`. I pretend to update the `aarch64` latter. But first I want to bootstrap it in `x86_64` without using bash anymore.

ELF
===
Executable and Linkable Format(ELF) are the format used in all linux executables and libraries.

This repo is my try to write them from scratch. For fun and learning.

Debugging
=========
I did created a very simple debugger. Look at makefile. And you can use gdb to debug the execution. Here some tips
* Use objdump -x to get the start address
put a break point at the start address:
* `br *0x010078`
* use si to step each instruction
* you can move the program counter to read any virtual address by using:
* `set $pc=0x00010168`
Print string at some address:
```
(gdb) p/x ($rdi)
$33 = 0x1013e
(gdb) x/s 0x1013e
0x1013e:        "sample-code.gg"
```
* `argc` is `$rsp`
```
(gdb) print *((int*)$rsp)
```
* when not in first backtrace, after a call like functions or procedures `argv` is `$rsp + 8`
```
(gdb) print *((char**)($rsp + 8))
```
after copy to a mem address `(mov %rsp, *0x000100b6; # 48892425b6000100)`
```
(gdb) p *(void**)(*(void**)0x0100b6+8)
$43 = (void *) 0x3
(gdb) p *(char**)(*(void**)0x0100b6+16)
$44 = 0x7fffffffe6ff "/home/glaudiston/src/gelf/tests/test_arg_count.elf"
(gdb) p *(char**)(*(void**)0x0100b6+24)
$45 = 0x7fffffffe732 "abc"
(gdb) p *(char**)(*(void**)0x0100b6+32)
$46 = 0x7fffffffe736 "def"
```

References
==========
There is some refs on the code. Read it.
```
https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
https://anee.me/reversing-an-elf-from-the-ground-up-4fe1ec31db4a
https://reverseengineering.stackexchange.com/questions/1992/what-is-plt-got/1993#1993?newreg=360ad3611f2041ed84fa064d413f5de1
https://www.technovelty.org/linux/plt-and-got-the-key-to-code-sharing-and-dynamic-libraries.html
```

# What should be a nice language
Maybe someday this can be a new lang... then here I go with some notes about it
- profiling/telemetry oriented
- debugging oriented
- binary updatable at real time
- high level user friendly interface
- allowing automation / text mode control
- portable, but what if emulated in any env ?
- what if a language can detect the target algorithm and suggest the best one ?

ASM
===
To discover bytecode one good way is create an asm file with the instruction, compile it and use ld with the --oformat binary:
```
echo "mov %r8, %r10" | as -al -o /dev/null - 
GAS LISTING  			page 1


   1 0000 4D89C2   	mov %r8,%r10
```
to disasm a bytecode to the asm instruction:
```
echo -ne "\x48\x89\xc2" | ndisasm -b 64 -
00000000  4889C2            mov rdx,rax
```
