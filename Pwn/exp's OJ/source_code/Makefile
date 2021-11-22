all: noj  runner

.PHONY : clean

noj: main.c
	gcc main.c -o noj -lcrypto

runner: shellcode_runner/runner.c
	gcc -nostdlib -nodefaultlibs -fPIC shellcode_runner/runner.c -o runner

clean:
	rm runner noj
