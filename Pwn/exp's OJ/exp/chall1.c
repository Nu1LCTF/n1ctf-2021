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


void sort(unsigned int * numbers) {
	for(int i = 0x1000-1; i>0; i--) {
		for(int j=0; j<i;j++) {
			if(numbers[j] > numbers[j+1]) {
				unsigned int tmp = numbers[j];
				numbers[j] = numbers[j+1];
				numbers[j+1] = tmp;
			}
		}
	}
}

int _start() {
	unsigned int numbers[0x1000];

	//read(STDIN_FILENO, numbers, 4);
	for(int i = 0; i< 0x1000;i++) {
		read(STDIN_FILENO, numbers+i, 4);
	}
	sort(numbers);
	for(int i=0;i<0x1000;i++) {
		write(STDOUT_FILENO, numbers+i, 4);
	}
}
