BUILD_DIR=build

help: ## This message listing all useful make targets
	@cat Makefile | grep ' ##' | grep -v "cat Makefile" | sed "s/\(.*\):.*## \(.*\)/\1:\n\t\2/"
all: gelf samples debugger ## Build everithing, gelf compiler, samples and the debugger.

prepare: *.sh
	mkdir -pv $(BUILD_DIR)

gelf: prepare ## Build the gelf compiler to the $(BUILD_DIR) folder
	bash make-elf.sh gelf.gg $(BUILD_DIR)/gelf
	chmod +x $(BUILD_DIR)/gelf
samples: prepare sample-elf readfile ## Compile all samples in sample folder. Currently sample-elf and readfile

sample-elf: prepare ## Build the sample-elf.gg that shows some working features
	bash make-elf.sh samples/sample-code.gg $(BUILD_DIR)/sample-elf
	chmod +x $(BUILD_DIR)/sample-elf

readfile: prepare ## Build the readfile.gg file that is a very limited cat clone.
	bash make-elf.sh samples/readfile.gg $(BUILD_DIR)/readfile
	chmod +x $(BUILD_DIR)/readfile

debugger: prepare debugger.c ## Build the debugger binary that print all registers changes and syscalls
	mkdir -pv $(BUILD_DIR)
	gcc -o $(BUILD_DIR)/debugger debugger.c -fdiagnostics-color=always

clean: ## Remove the build directory
	rm -fr elf $(BUILD_DIR)
