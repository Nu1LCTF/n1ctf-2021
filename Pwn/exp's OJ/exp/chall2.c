typedef int ssize_t;
typedef unsigned int size_t;
#define STDIN_FILENO 0
#define STDOUT_FILENO 1
ssize_t read(int fd, void *buf, size_t count) {
    ssize_t re;
    asm("movl %1, %%edi;\n" \
    "movq %2, %%rsi;\n"     \
    "movl %3, %%edx;\n"     \
    "movl $0, %%eax;\n"      \
    "syscall;\n"        \
    "movl %%eax, %0;\n"   \
    : "=r"(re)              \
    : "m"(fd), "m"(buf), "m"(count)  \
    );
    return re;
}

ssize_t write(int fd, void *buf, size_t count) {
    ssize_t re;
    asm("movl %1, %%edi;\n" \
    "movq %2, %%rsi;\n"     \
    "movl %3, %%edx;\n"     \
    "movl $1, %%eax;\n"      \
    "syscall;\n"        \
    "movl %%eax, %0;\n"   \
    : "=r"(re)              \
    : "m"(fd), "m"(buf), "m"(count)  \
    );
    return re;
}

__attribute__((section(".text"))) char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void base64(unsigned char *data) {
	char * b = base64_table;
	for(int i=0;i<85;i++) {
		unsigned char a1 = data[i*3];
		unsigned char a2 = data[i*3+1];
		unsigned char a3 = data[i*3+2];
		write(STDOUT_FILENO, b + (a1>>2), 1);
		write(STDOUT_FILENO, b + ((a1&3)<<4 | (a2>>4)), 1);
		write(STDOUT_FILENO, b + ((a2&0xf)<<2 | (a3>>6)), 1);
		write(STDOUT_FILENO, b + (a3&0x3f), 1);
	}

	char c = '=';
	write(STDOUT_FILENO, b + (data[255]>>2),1);
	write(STDOUT_FILENO, b+ ((data[255]&3)<<4), 1);
	write(STDOUT_FILENO, &c, 1);
	write(STDOUT_FILENO, &c, 1);
}

int _start(){
	unsigned char data[0x100];
	
	//read(STDIN_FILENO, data, 0x1);

	read(STDIN_FILENO, data, 0x100);
	base64(data);
}

