BUILD_DIR=build

all: samples debugger

prepare: *.sh
	mkdir -pv $(BUILD_DIR)

samples: prepare

sample-elf:
	bash make-elf.sh samples/sample-code.gg $(BUILD_DIR)/sample-elf
	chmod +x $(BUILD_DIR)/sample-elf

readfile:
	bash make-elf.sh samples/readfile.gg $(BUILD_DIR)/readfile
	chmod +x $(BUILD_DIR)/sample-elf

debugger: debugger.c
	mkdir -pv $(BUILD_DIR)
	gcc -o $(BUILD_DIR)/debugger debugger.c -fdiagnostics-color=always

clean:
	rm -fr elf $(BUILD_DIR)
