__attribute__((section(".text"))) char magic_space[0x1000];

#include <sys/mman.h>
#include <string.h>

#define PR_SET_SECCOMP 22
#define SECCOMP_MODE_STRICT 1

void *mmap(void *addr, size_t length, int prot, int flags,
           int fd, off_t offset) {
    void *re;
    asm("movq %1, %%rdi;\n" \
    "movq %2, %%rsi;\n"     \
    "movl %3, %%edx;\n"     \
    "movl %4, %%r10d;\n"     \
    "movl %5, %%r8d;\n"     \
    "movq %6, %%r9;\n"     \
    "movl $9, %%eax;\n"      \
    "syscall;\n"        \
    "movq %%rax, %0;\n"   \
    : "=r"(re)              \
    : "m"(addr), "m"(length), "m"(prot), "m"(flags), "m"(fd), "m"(offset)      \
    );
    return re;
}

int prctl(int option, unsigned long arg1) {
    long int re;
    asm("movq %1, %%rdi;\n" \
    "movq %2, %%rsi;\n"     \
    "movl $157, %%eax;\n"      \
    "syscall;\n"        \
    "movq %%rax, %0;\n"   \
    : "=r"(re)              \
    : "m"(option), "m"(arg1)  \
    );
    return re;
}

void exit(int staus_code) {
    asm("movq %0, %%rdi;\n" \
    "movl $60, %%eax;\n"      \
    "syscall;\n"        \
    :             \
    : "m"(staus_code)  \
    );
}

void sandbox() {
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_STRICT) == -1) {
        exit(0);
    }
}

int main() {
    unsigned char *addr = mmap(0, 0x210000, PROT_EXEC | PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0);
    memcpy(addr, magic_space, 0x1000);
    sandbox();
    void (*f)() = addr;
    f();
}

void _start() {
    main();
}
