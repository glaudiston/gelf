help: ## This message listing all useful make targets
	@cat Makefile | grep ' ##' | grep -v "cat Makefile" | sed "s/\(.*\):.*## \(.*\)/\1:\n\t\2/"
prepare: *.sh
	mkdir -pv build

gelf: prepare ## Build the gelf compiler to the build folder
	./gelf gelf.gg build/gelf
	chmod +x build/gelf
	cp build/gelf ./gelf

samples: prepare build/sample-elf build/readfile ## Compile all samples in sample folder. Currently sample-elf and readfile

build/sample-elf: samples/sample-code.gg ## Build the sample-elf.gg that shows some working features
	bash make-elf.sh samples/sample-code.gg build/sample-elf
	chmod +x build/sample-elf

build/readfile: prepare samples/readfile.gg ## Build the readfile.gg file that is a very limited cat clone.
	bash make-elf.sh samples/readfile.gg build/readfile
	chmod +x build/readfile

debugger: prepare debugger/debugger.c ## Build the debugger binary that print all registers changes and syscalls
	make -C debugger build

all: prepare build/gelf samples build/debugger ## Build everithing, gelf compiler, samples and the debugger.

clean: ## Remove the build directory
	rm -fr elf build

check:
	./tests.sh
