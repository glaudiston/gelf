elf: *.sh
	bash make-elf.sh
	chmod +x elf
clean:
	rm elf
