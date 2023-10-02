help: ## This message listing all useful make targets
	@cat Makefile | grep ' ##' | grep -v "cat Makefile" | sed "s/\(.*\):.*## \(.*\)/\1:\n\t\2/"
prepare: *.sh
	mkdir -pv build

build/gelf: ## Build the gelf compiler to the build folder
	bash make-elf.sh gelf.gg build/gelf
	chmod +x build/gelf

samples: prepare build/sample-elf build/readfile ## Compile all samples in sample folder. Currently sample-elf and readfile

build/sample-elf: samples/sample-code.gg ## Build the sample-elf.gg that shows some working features
	bash make-elf.sh samples/sample-code.gg build/sample-elf
	chmod +x build/sample-elf

build/readfile: samples/readfile.gg ## Build the readfile.gg file that is a very limited cat clone.
	bash make-elf.sh samples/readfile.gg build/readfile
	chmod +x build/readfile

build/debugger: debugger.c ## Build the debugger binary that print all registers changes and syscalls
	mkdir -pv build
	gcc -o build/debugger debugger.c -fdiagnostics-color=always

all: prepare build/gelf samples build/debugger ## Build everithing, gelf compiler, samples and the debugger.

clean: ## Remove the build directory
	rm -fr elf build
