sample: *.sh
	bash make-elf.sh sample-code.gg sample-elf
	chmod +x sample-elf
debugger: debugger.c
	gcc -o debugger debugger.c

clean:
	rm elf
