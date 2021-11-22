//
// Created by explorer on 2021/11/18.
//
typedef int ssize_t;
typedef unsigned int size_t;
#define STDIN_FILENO 0
#define STDOUT_FILENO 1


ssize_t rwead(int fd, void *buf, size_t count, int call) {
    ssize_t re;
    asm("movl %1, %%edi;\n" \
    "movq %2, %%rsi;\n"     \
    "movl %3, %%edx;\n"     \
    "movl %4, %%eax;\n"      \
    "syscall;\n"        \
    "movl %%eax, %0;\n"   \
    : "=r"(re)              \
    : "m"(fd), "m"(buf), "m"(count), "m"(call)  \
    );
    return re;
}

#define read(a, b, c) rwead((a),(b),(c), 0)
#define write(a, b, c) rwead((a),(b),(c), 1)

//ssize_t read(int fd, void *buf, size_t count) {
//    ssize_t re;
//    asm("movl %1, %%edi;\n" \
//    "movq %2, %%rsi;\n"     \
//    "movl %3, %%edx;\n"     \
//    "movl $0, %%eax;\n"      \
//    "syscall;\n"        \
//    "movl %%eax, %0;\n"   \
//    : "=r"(re)              \
//    : "m"(fd), "m"(buf), "m"(count)  \
//    );
//    return re;
//}
//
//ssize_t write(int fd, void *buf, size_t count) {
//    ssize_t re;
//    asm("movl %1, %%edi;\n" \
//    "movq %2, %%rsi;\n"     \
//    "movl %3, %%edx;\n"     \
//    "movl $1, %%eax;\n"      \
//    "syscall;\n"        \
//    "movl %%eax, %0;\n"   \
//    : "=r"(re)              \
//    : "m"(fd), "m"(buf), "m"(count)  \
//    );
//    return re;
//}

int func(int num) {
    int d = num / 4 - 20;
    if (d < 0) {
        d = 0;
    }
    return d;
}

void align(unsigned short map[0x400][0x400], unsigned char *seq1, unsigned char *seq2) {
    for (int x = 0; x < 0x400; x++) {
        map[x][0] = 1;
        map[0][x] = 2;
    }
    int max_m = 0;
    int max_x;
    int max_y;
    for (int x = 1; x < 0x400; x++) {
        for (int y = 1; y < 0x400; y++) {
            int m1 = func(map[x - 1][y]);
            int m2 = func(map[x][y - 1]);
            int m3 = map[x - 1][y - 1] / 4;
            unsigned char dd = seq1[x - 1] - seq2[y - 1];
            int d = (char) dd;
            if (d < 0) {
                if (d <= -10) {
                    d = -10000;
                } else {
                    d = 40 + d;
                }
            } else {
                if (d < 10) {
                    d = 40 - d;
                } else {
                    d = -10000;
                }
            }
            m3 += d;
            if (m3 < 0) {
                m3 = 0;
            }

            int m;
            if (m1 > m2) {
                if (m1 >= m3) {
                    m = m1 * 4 + 1;
                } else {
                    m = m3 * 4 + 3;
                }
            } else {
                if (m2 >= m3) {
                    m = m2 * 4 + 2;
                } else {
                    m = m3 * 4 + 3;
                }
            }
            map[x][y] = m;
            if ((m & 0xfffc) > max_m) {
                max_m = map[x][y];
                max_x = x;
                max_y = y;
            }
        }
    }
    unsigned char buf2[32];
    int i = 31;
    while (i >= 0) {
        int c = map[max_x][max_y] & 0x3;
        if (c == 1) {
            max_x -= 1;
        } else if (c == 2) {
            max_y -= 1;
        } else {
            max_x -= 1;
            max_y -= 1;
            buf2[i] = seq2[max_y];
            i -= 1;
        }
    }
    write(STDOUT_FILENO, buf2, 32);
}

int _start() {
    unsigned char seq1[0x400];
    unsigned char seq2[0x400];
    //read(STDIN_FILENO, seq1, 1);
    read(STDIN_FILENO, seq1, 0x400);
    read(STDIN_FILENO, seq2, 0x400);
    void *addr;
    asm("call a;\n" \
        "a: pop %%rax;\n" \
        "movq %%rax, %0;\n"      \
        : "=r"(addr)
    );
    align(addr, seq1, seq2);
}
