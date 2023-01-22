elf: *.sh
	bash make-elf.sh
	chmod +x elf
debugger: debugger.c
	gcc -o debugger debugger.c

clean:
	rm elf
