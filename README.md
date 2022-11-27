What is this?
=============

This is my playground for elf related stuff... I started to scratch it... and here I put my notes... maybe you can learn something with it too.

I'm testing it on native linux `x86_64` and in a `aarch64`(osx, using ubuntu within docker container).

ELF
===
Executable and Linkable Format(ELF) are the format used in all linux executables and libraries.

This repo is my try to write them from scratch. Just for fun and learning.

References
==========
There is some refs on the code. Read it.
https://www.muppetlabs.com/~breadbox/software/tiny/teensy.html
https://anee.me/reversing-an-elf-from-the-ground-up-4fe1ec31db4a
https://reverseengineering.stackexchange.com/questions/1992/what-is-plt-got/1993#1993?newreg=360ad3611f2041ed84fa064d413f5de1
https://www.technovelty.org/linux/plt-and-got-the-key-to-code-sharing-and-dynamic-libraries.html

# What should be a nice language
Just a Maybe someday this can be a new lang... then here I go with some notes about it
- profiling/telemetry oriented
- debugging oriented
- binary updatable at real time
- high level user friendly interface
- allowing automation / text mode control
- portable, but what if emulated in any env ?
- what if a language can detect the target algorithm and suggest the best one ?
