#include <unistd.h>
#include <stdarg.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct 
{
    size_t size;
    char author[16];
    char content[];
}book;

int i2a(int x,char *s){
    char tmp[16];
    char *p = tmp;
    int n = 0;
    while(x){
        *p++ = x%10+'0';
        x /= 10;
        n++;
    }
    for(int i = n-1;i >= 0;i--){
        *s = tmp[i];
        s++;
    }
    return n;
}

int babyscanf(char *fmt,...){
    va_list argptr;
    va_start(argptr,fmt);
    char c;
    int *ptri;
    char *ptrc;
    while(*fmt){
        if(*fmt == '%'){
            fmt++;
            switch (*fmt)
            {
            case 'd':
                ptri = va_arg(argptr,int *);
                *ptri = 0;
                int w = 1;
                while(read(0,&c,1)==1){
                    if(c >= '0' && c <= '9'){
                        *ptri = *ptri * 10 + c - '0';
                    }else if(c == '-'){
                        w = -1;
                    }else{
                        break;
                    }
                }
                *ptri *= w;
                if(c == *(fmt+1)){
                    fmt++;
                }else if(c == ' ' || c == '\n' || c == '\t'){
                    break;
                }else{
                    return -1;
                }
                break;
            case 's':
                ptrc = va_arg(argptr,char *);
                int size = va_arg(argptr,int);
                for(int i = 0;i < size;i++){
                    if(read(0,&c,1) != 1){
                        return -1;
                    }
                    if(c == '\n' || c == ' ' || c == '\t'){
                        break;
                    }else{
                        ptrc[i] = c;
                    }
                }
                break;
            default:
                break;
            }
        }else{
            if(read(0,&c,1)!=1){
                return -1;
            }
            if(c != *fmt){
                return -1;
            }
        }
        if(c == '\n')
            break;
        fmt++;
    }
    va_end(argptr);
    return 0;
}


void babyprintf(char *fmt,...){
    va_list argptr;
    va_start(argptr,fmt);
    int n = strlen(fmt);
    int x;
    char *s;
    char *p = fmt;
    while(*p){
        if(*p == '%'){
            n += 0x10;
        }
        p++;
    }
    p = malloc(n);
    char *pp = p;
    for(int i = 0;i < n;i++){
        p[i] = 0;
    }
    while(*fmt){
        if(*fmt == '%'){
            fmt++;
            switch (*fmt)
            {
            case 'm':
                x = va_arg(argptr,int);
                p += i2a(x,p);
                break;
            case 'r':
                s = va_arg(argptr,char *);
                if(strlen(s) > 0x10){
                    memcpy(p,s,0x10);
                    p += 0x10;
                }else{
                    memcpy(p,s,strlen(s));
                    p += strlen(s);
                }
                break;
            case '%':
                *p = '%';
                p++;
                break;
            default:
                p += i2a(*fmt,p);
                break;
            }
        }else{
            *p = *fmt;
            p++;
        }
        fmt++;
    }
    va_end(argptr);
    write(1,pp,strlen(pp));
    free(pp);
}

void menu(){
    babyprintf("1.add\n");
    babyprintf("2.delete\n");
    babyprintf("3.ppppprint\n");
    babyprintf(">");
}

void init(){
    setbuf(stdout,0);
    setbuf(stdin,0);
    setbuf(stderr,0);
    babyprintf("  o.     O        .oOOOo.  oOoOOoOOo OOooOoO \n");
    babyprintf("  Oo     o  oO   .O     o      o     o       \n");
    babyprintf("  O O    O   O   o             o     O       \n");
    babyprintf("  O  o   o   o   o             O     oOooO   \n");
    babyprintf("  O   o  O   O   o             o     O       \n");
    babyprintf("  o    O O   o   O             O     o       \n");
    babyprintf("  o     Oo   O   `o     .o     O     o       \n");
    babyprintf("  O     `o OooOO  `OoooO'      o'    O'      \n");                                          
}

int getNum(){
    int x;
    babyscanf("%d ",&x);
    return x;
}

book *list[16];
void add(){
    int idx = 0;
    for(; idx < 16;idx++){
        if(!list[idx]){
            break;
        }
    }
    if(idx == 16){
        babyprintf("Book store is full!");
        exit(0);
    }
    babyprintf("Size:");
    int size = 0;
    babyscanf("Content size is %d ",&size);
    if(size < 0 || size > 0x500){
        babyprintf("Too large\n");
        return;
    }
    list[idx] = malloc(8+16+size);
    list[idx]->size = size;
    babyprintf("Author:");
    babyscanf("Book author is %s ",list[idx]->author,16);
    babyprintf("Content:");
    babyscanf("Book content is %s ",list[idx]->content,size);
    babyprintf("Success!\n");
}

void del(){
    babyprintf("Idx:");
    int idx = 0;
    babyscanf("Book idx is %d ",&idx);
    if(idx < 0 || idx >= 16){
        babyprintf("No No No\n");
        return;
    }
    free(list[idx]);
    list[idx] = 0;
    babyprintf("Success!\n");
}

void show(){
    babyprintf("Idx:");
    int idx = 0;
    babyscanf("Book idx is %d ",&idx);
    if(idx < 0 || idx >= 16){
        babyprintf("No No No\n");
        return;
    }
    char tmp[0x100];
    memset(tmp,0,sizeof(tmp));
    babyprintf("You can show book by yourself\n");
    babyscanf("My format %s ",tmp,0x100);
    babyprintf(tmp,list[idx]->author,list[idx]->size,list[idx]->content);
    babyprintf("Success!\n");
}

int main(){
    int x;
    init();
    while(1){
        menu();
        int cmd = getNum();
        switch (cmd)
        {
        case 1:
            add();
            break;
        case 2:
            del();
            break;
        case 3:
            show();
            break;
        case 4:
            exit(0);
            break;
        default:
            exit(0);
            break;
        }
    }
    return 0;
}