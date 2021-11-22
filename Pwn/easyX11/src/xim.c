// gcc -g xim.c -o xim -lX11
#include <X11/Xlib.h>
#include <X11/Xutil.h>
#include <X11/Xos.h>
#include <stdlib.h>
#include <stdio.h>
#include <locale.h>
#include <assert.h>
#include <stdbool.h>


void utf8ToLatin(unsigned char *dst, unsigned char *src, size_t len)
{
    int dstIdx = 0;
    for (size_t srcIdx = 0; srcIdx < len;)
    {
        if (src[srcIdx] <= 0x7f)
        {
            dst[dstIdx] = src[srcIdx];
            srcIdx++;
        }
        else if (src[srcIdx] == 0xc2 && srcIdx + 1 < len)
        {
            dst[dstIdx] = src[srcIdx + 1];
            srcIdx += 2;
        }
        else if (src[srcIdx] == 0xc3 && srcIdx + 1 < len)
        {
            dst[dstIdx] = src[srcIdx + 1] + 0x40;
            srcIdx += 2;
        }
        else
        {
            fputs("invalid utf8 character string.\n", stderr);
            exit(0);
        }
        dstIdx++;
    }
}

void refresh(Display *display, Window window, GC graphicalContext, int scr, char *buffer)
{
    XWindowAttributes windowAttributes;
    XGetWindowAttributes(display, window, &windowAttributes);
    int text_x = (windowAttributes.width) / 2;
    int text_y = (windowAttributes.height) / 2;

    XSetForeground(display, graphicalContext, WhitePixel(display, scr));
    XFillRectangle(display, window, graphicalContext, 0, 0, windowAttributes.width, windowAttributes.height);
    XSetForeground(display, graphicalContext, BlackPixel(display, scr));

    XDrawString(display, window, graphicalContext,
                text_x, text_y, buffer, strlen(buffer));
}

void mainLogic(char *overflow)
{
    if (!XSupportsLocale())
    {
        perror("not support locale\n");
        exit(0);
    }

    if (setlocale(LC_CTYPE, "en_US.UTF-8") == NULL)
    {
        perror("can not set locale\n");
        exit(0);
    }
    XSetLocaleModifiers("@im=114514");
    // 根据环境变量中的 DISPLAY 设置 XServer 并且打开
    Display *display = XOpenDisplay(NULL);
    if (display == NULL)
    {
        fprintf(stderr, "Open display %s error.\n", getenv("DISPLAY"));
        perror("XOpenDisplay");
        exit(0);
    }

    int scr = DefaultScreen(display);
    Window window = XCreateSimpleWindow(display,
                                        XDefaultRootWindow(display),
                                        0, 0, 400, 400, 5,
                                        BlackPixel(display, scr),
                                        WhitePixel(display, scr));
    XMapWindow(display, window);

    XStoreName(display, window, "N1CTF Easy X11");

    XSelectInput(display, window, ExposureMask | KeyPressMask);

    GC graphicalContext = XCreateGC(display, window, 0, NULL);

    XIM xim = XOpenIM(display, NULL, NULL, NULL);
    if (xim == NULL)
    {
        fputs("XOpenIM @im=114514 faild.\n", stderr);
        XSetLocaleModifiers("");
        xim = XOpenIM(display, NULL, NULL, NULL);
        if (xim == NULL)
        {
            fputs("XOpenIM faild.\n", stderr);
            exit(0);
        }
    }

    XIC ic = XCreateIC(xim,
                       XNInputStyle, XIMPreeditNothing | XIMStatusNothing,
                       XNClientWindow, window,
                       NULL);
    XSetICFocus(ic);

    char *buff;
    size_t buff_size = 16;
    buff = (char *)malloc(buff_size);
    refresh(display, window, graphicalContext, scr, overflow);
    for (;;)
    {
        KeySym ksym;
        Status status;
        XEvent ev;
        XPoint spot;
        XNextEvent(display, &ev);
        if (XFilterEvent(&ev, None))
            continue;
        if (ev.type == KeyPress)
        {
            size_t stringLen = Xutf8LookupString(ic, &ev.xkey,
                                                 buff, buff_size - 1,
                                                 &ksym, &status);
            if (status == XBufferOverflow)
            {
                printf("reallocate: %lu\n", stringLen + 1);
                buff = realloc(buff, stringLen + 1);
                buff_size = stringLen + 1;
                stringLen = Xutf8LookupString(ic, &ev.xkey,
                                              buff, stringLen,
                                              &ksym, &status);
            }
            if (stringLen)
            {
                buff[stringLen] = 0;
                memset(overflow, 0, 10);
                utf8ToLatin(overflow, buff, stringLen);
                refresh(display, window, graphicalContext, scr, overflow);
                if (!strncmp(overflow, "1919810", 7)) {
                    return;
                }
            }
        }
        else if (ev.type == Expose)
        {
            refresh(display, window, graphicalContext, scr, overflow);
        }
    }
}


int main()
{
    char overflow[10] = "Easy X11";
    mainLogic(overflow);
}
