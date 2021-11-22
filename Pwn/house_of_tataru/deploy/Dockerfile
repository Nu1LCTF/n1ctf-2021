FROM ubuntu:21.04

ENV DEBIAN_FRONTEND=noninteractive
RUN sed -i 's/archive.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list && sed -i 's/security.ubuntu.com/mirrors.tuna.tsinghua.edu.cn/g' /etc/apt/sources.list
RUN apt-get update && apt-get -y dist-upgrade &&\
apt-get install -y lib32z1 xinetd build-essential

RUN useradd -m ctf

WORKDIR /home/ctf

RUN mkdir /home/ctf/lib
RUN mkdir /home/ctf/dev && mknod /home/ctf/dev/null c 1 3 && \
mknod /home/ctf/dev/zero c 1 5 && mknod /home/ctf/dev/random c 1 8 && \
mknod /home/ctf/dev/urandom c 1 9 && chmod 666 /home/ctf/dev/*

COPY ./ctf.xinetd /etc/xinetd.d/ctf
RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail

COPY ./pwn /home/ctf/
COPY ./ld-musl-x86_64.so.1 /home/ctf/lib/

RUN chown -R root:ctf /home/ctf && chmod -R 750 /home/ctf && \
echo "n1ctf{U_Ar3_RE41LY_M43TeR_0f_Mus1!}" > /home/ctf/flag && \
chmod 740 /home/ctf/flag && chmod o+r /home/ctf/flag && chmod a+x /home/ctf/pwn

CMD exec /bin/bash -c "/etc/init.d/xinetd start; trap : TERM INT; sleep infinity & wait"

EXPOSE 23333
