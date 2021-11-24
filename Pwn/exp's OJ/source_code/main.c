//
// Created by explorer on 2021/11/16.
//

#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <stdlib.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/wait.h>

#define MAX_CODE_SIZE 1400
#define SHELLCODE_OFF 0x2C0
unsigned char *runner_code;
size_t runner_size;

void random_buffer(unsigned char *buffer, size_t size) {
    RAND_bytes(buffer, size);
}

int random_range(int min, int max) {
    long int l = max - min;
    unsigned long random_num;
    random_buffer(&random_num, sizeof(random_num));
    return min + (random_num % l);
}

void read_data(unsigned char *buffer, size_t size) {
    int i = 0;
    while (i < size) {
        int re = read(STDIN_FILENO, buffer + i, size - i);
        if (re <= 0) {
            puts("read error");
            exit(0);
        }
        i += re;
    }
}


int read_n(unsigned char *buffer, size_t size) {
    int i;
    for (i = 0; i < size - 1; i++) {
        int re = read(STDIN_FILENO, buffer + i, 1);
        if (re != 1) {
            puts("read error");
            exit(1);
        }
        if (buffer[i] == '\n') {
            break;
        }
    }
    buffer[i] = 0;
    return i;
}

unsigned int read_int() {
    char num[0x10];
    read_n(num, 0x10);
    return atoi(num);
}

void *read_code(size_t *re_size) {
    puts("now, show me the code");
    puts("code size: ");
    unsigned int size = read_int();
    if (size > MAX_CODE_SIZE) {
        puts("code too large");
        exit(1);
    }

    unsigned char *code = malloc(MAX_CODE_SIZE);
    if (code == NULL) {
        puts("malloc failed");
        exit(1);
    }
    read_data(code, size);
    for (int i = 0; i < size; i++) {
        char ch = code[i];
        if (!(('a' <= ch && ch <= 'z') || ('A' <= ch && ch <= 'z') || ('0' <= ch && ch <= '9'))) {
            puts("you code is invalid");
            exit(1);
        }
    }
    if (re_size != NULL) {
        *re_size = size;
    }
    return code;
}

void write_runner(char *runner_name, char *code, size_t code_size) {
    char *chal = malloc(runner_size);
    if (chal == NULL) {
        puts("malloc failed");
        exit(1);
    }
    memcpy(chal, runner_code, runner_size);
    memcpy(chal + SHELLCODE_OFF, code, code_size);
    FILE *fp = fopen(runner_name, "wb");
    if (fp == NULL) {
        puts("open error");
        exit(1);
    }
    fwrite(chal, runner_size, 1, fp);
    fclose(fp);
    free(chal);
    chmod(runner_name, S_IRUSR | S_IWUSR | S_IXUSR | S_IRGRP | S_IXGRP | S_IROTH | S_IXOTH);
}

pid_t start_runner(char *runner_name, int *read_fd, int *write_fd) {
    pid_t cpid;
    int child_read[2];
    int child_write[2];

    if (pipe(child_read) == -1) {
        puts("pipe error");
        exit(1);
    }
    if (pipe(child_write) == -1) {
        puts("pipe error");
        exit(1);
    }

    cpid = fork();
    if (cpid == -1) {
        puts("fork error");
        exit(0);
    }
    if (cpid == 0) { // child
        close(child_read[1]);
        close(child_write[0]);
        dup2(child_read[0], STDIN_FILENO);
        dup2(child_write[1], STDOUT_FILENO);
        dup2(child_write[1], STDERR_FILENO);
        int fdlimit = (int) sysconf(_SC_OPEN_MAX);
        for (int i = STDERR_FILENO + 1; i < fdlimit; i++) close(i);
        execve(runner_name, NULL, NULL);
        exit(1);    // in case exec failed
    } else { // parent
        close(child_read[0]);
        close(child_write[1]);
        *write_fd = child_read[1];
        *read_fd = child_write[0];
    }
    return cpid;
}

int comp(const void *elem1, const void *elem2) {
    unsigned int f = *((unsigned int *) elem1);
    unsigned int s = *((unsigned int *) elem2);
    if (f > s) return 1;
    if (f < s) return -1;
    return 0;
}

char *base64(const unsigned char *input, int length) {
    const auto pl = 4 * ((length + 2) / 3);
    unsigned char *output = malloc(pl + 1); //+1 for the terminating null that EVP_EncodeBlock adds on
    int ol = EVP_EncodeBlock(output, input, length);
    if (pl != ol) {
        puts("b64encode error");
        exit(1);
    }
    return output;
}


//from https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption
int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
            unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;

    int len;

    int ciphertext_len;

    if (!(ctx = EVP_CIPHER_CTX_new())) {
        fputs("internal error, can not create cipher ctx", stderr);
        exit(1);
    }

    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv)) {
        fputs("internal error, can not create cipher init error", stderr);
        exit(1);
    }
    if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len)) {
        fputs("internal error, encrypt failed", stderr);
        exit(1);
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) {
        fputs("internal error, encrypt failed", stderr);
        exit(1);
    }
    ciphertext_len += len;

    /* Clean up */
    EVP_CIPHER_CTX_free(ctx);

    return ciphertext_len;
}


int read_enc_flag(unsigned char *enc_flag, unsigned char *key, unsigned char *iv) {
    char flag[0x100];
    FILE *fp = fopen("flag", "rb");
    if (fp == NULL) {
        puts("you flag is miss");
        exit(1);
    }
    memset(flag, 0, 0x100);
    fread(flag, 0x100, 1, fp);
    fclose(fp);

    if (strncmp(flag, "n1ctf{", 6) != 0 && strlen(flag) != 32 + 7 && flag[strlen(flag) - 1] != '}') {
        puts("flag file error");
        exit(1);
    }

    random_buffer(key, 16);
    random_buffer(iv, 16);

    int re = encrypt(flag + 6, 32, key, iv, enc_flag);
    memset(flag, 0, 0x100);
    return re;
}

unsigned char *hide_flag(unsigned char *data, int *offset) {
    while (1) {
        unsigned char *random_data = malloc(0x400);
        random_buffer(random_data, 0x400);
        unsigned int start_of_hide = random_range(0, 0x400 - 64);

        int p = start_of_hide;
        int i = 0;
        int insert_count = 0;
        while (i < 32) {
            int r = random_range(0, 100);
            if (r > 80) {
                random_data[p++] = random_range(0, 256);
                insert_count++;
            } else {
                offset[i] = random_range(-5, 5);
                random_data[p++] = data[i] + offset[i];
                i++;
            }
            if (insert_count > 16) {    // too many
                free(random_data);
                continue;
            }
        }
        if (insert_count > 5) {
            return random_data;
        }
        free(random_data);
    }
}

void challenge3() {
    puts("here is the third challenge");
    puts("find the flag!!");
    unsigned char key[16];
    unsigned char iv[16];
    unsigned char enc_flag[32];

    size_t code_size;
    char *code = read_code(&code_size);
    write_runner("/tmp/chal3", code, code_size);
    free(code);

    if (read_enc_flag(enc_flag, key, iv) == -1) {
        puts("enc flag error");
        exit(1);
    }

    int offset[32];

    unsigned char *seq1 = hide_flag(enc_flag, offset);
    unsigned char *seq2 = hide_flag(enc_flag, offset);
    memset(enc_flag, 0, 32);

    int read_fd;
    int write_fd;
    pid_t cpid = start_runner("/tmp/chal3", &read_fd, &write_fd);

    int write_size = 0;
    while (write_size < 0x400) {
        int re = write(write_fd, seq1 + write_size, 0x400 - write_size);
        if (re <= 0) {
            puts("code error");
            exit(0);
        }
        write_size += re;
    }

    write_size = 0;
    while (write_size < 0x400) {
        int re = write(write_fd, seq2 + write_size, 0x400 - write_size);
        if (re <= 0) {
            puts("code error");
            exit(0);
        }
        write_size += re;
    }

    unsigned char *recv_data = malloc(32);
    int read_size = 0;
    while (read_size < 32) {
        int re = read(read_fd, recv_data + read_size, 32 - read_size);
        if (re <= 0) {
            puts("code error");
            exit(0);
        }
        read_size += re;
    }

    kill(cpid, SIGKILL);
    wait(NULL);

    puts("last words");
    printf("key: ");
    puts(base64(key, 16));
    printf("iv: ");
    puts(base64(iv, 16));
    printf("your data: ");
    puts(base64(recv_data, 32));
    printf("flag noise: ");
    for (int i = 0; i < 32; i++) {
        printf("%d ", offset[i]);
    }
    putchar('\n');
    puts("bye");
    exit(0);
}

void challenge2() {
    puts("here is the second challenge");
    puts("plz do a base64 encode");

    size_t code_size;
    char *code = read_code(&code_size);
    write_runner("/tmp/chal2", code, code_size);
    free(code);

    int read_fd;
    int write_fd;
    pid_t cpid = start_runner("/tmp/chal2", &read_fd, &write_fd);

    unsigned char *random_data = malloc(0x100);
    random_buffer(random_data, 0x100);
    int write_size = 0;
    while (write_size < 0x100) {
        int re = write(write_fd, random_data + write_size, 0x100 - write_size);
        if (re <= 0) {
            puts("code error");
            exit(0);
        }
        write_size += re;
    }

    unsigned char *recv_data = malloc(344);
    int read_size = 0;
    while (read_size < 344) {
        int re = read(read_fd, recv_data + read_size, 344 - read_size);
        if (re <= 0) {
            puts("code error");
            exit(0);
        }
        read_size += re;
    }

    kill(cpid, SIGKILL);
    wait(NULL);


    unsigned char *base64_data = base64(random_data, 0x100);

//    puts(base64_data);
//    write(STDOUT_FILENO, recv_data, 344);
//    puts(recv_data);

    if (memcmp(recv_data, base64_data, 344) != 0) {
        puts("wrong answer");
        exit(1);
    } else {
        puts("accept");
    }
    free(random_data);
    free(recv_data);
    free(base64_data);
}

void challenge1() {
    puts("here is the first challenge");
    puts("plz sort 1000 numbers from small to large");

    size_t code_size;
    char *code = read_code(&code_size);
    write_runner("/tmp/chal1", code, code_size);
    free(code);

    int read_fd;
    int write_fd;
    pid_t cpid = start_runner("/tmp/chal1", &read_fd, &write_fd);
    unsigned int *random_number = malloc(sizeof(unsigned int) * 0x1000);
    random_buffer(random_number, sizeof(unsigned int) * 0x1000);
    for (int i = 0; i < 0x1000; i++) {
        int re = write(write_fd, random_number + i, sizeof(unsigned int));
        if (re != 4) {
            puts("code error");
            exit(1);
        }
    }

    unsigned int *recv_sorted_number = malloc(sizeof(unsigned int) * 0x1000);
    for (int i = 0; i < 0x1000; i++) {
        int re = read(read_fd, recv_sorted_number + i, sizeof(unsigned int));
        if (re != 4) {
            puts("code error");
            exit(1);
        }
    }

    kill(cpid, SIGKILL);
    wait(NULL);

    qsort(random_number, 0x1000, sizeof(unsigned int), comp);
    if (memcmp(random_number, recv_sorted_number, sizeof(unsigned int) * 0x1000) != 0) {
        puts("wrong answer");
        exit(1);
    } else {
        puts("accept");
    }
    free(random_number);
    free(recv_sorted_number);
}


void init() {
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    signal(SIGABRT, SIG_ERR);   // for init
    alarm(3);

    struct stat statbuf;
    if (stat("./runner", &statbuf) == -1) {
        puts("stat errot");
        exit(1);
    }
    runner_size = statbuf.st_size;
    runner_code = malloc(runner_size);
    if (runner_code == NULL) {
        puts("malloc failed");
        exit(1);
    }
    FILE *fp = fopen("./runner", "rb");
    if (fp == NULL) {
        puts("open error");
        exit(1);
    }
    int re = fread(runner_code, 1, runner_size, fp);
    if (re != runner_size) {
        puts("read runner code error");
        exit(1);
    }
    fclose(fp);
}

int main() {
    init();
    puts("welcome to my oj");
    challenge1();
    challenge2();
    challenge3();
}