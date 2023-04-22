BUILD_DIR=build
sample: *.sh
	mkdir -pv $(BUILD_DIR)
	bash make-elf.sh samples/sample-code.gg $(BUILD_DIR)/sample-elf
	chmod +x $(BUILD_DIR)/sample-elf
debugger: debugger.c
	mkdir -pv $(BUILD_DIR)
	gcc -o $(BUILD_DIR)/debugger debugger.c

clean:
	rm -fr elf $(BUILD_DIR)
