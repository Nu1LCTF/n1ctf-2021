FROM ubuntu:18.04 AS chroot

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
        sed -i "s/http:\/\/security.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list

RUN apt-get update && \
        apt-get -y dist-upgrade && \
        apt-get install -y libcrypto++6 libssl1.0.0 openssl python3

RUN useradd --no-create-home -u 1000 user
COPY flag /app/
COPY noj /app/
COPY runner /app/
COPY pow.py /app/
RUN chown root:root /app/flag && \
        chmod 644 /app/flag && \
        chown root:root /app/noj && \
        chmod 755 /app/noj && \
        chown root:root /app/runner && \
        chmod 755 /app/runner && \
        chown root:root /app/pow.py && \
        chmod 755 /app/pow.py

FROM ubuntu:18.04

RUN sed -i "s/http:\/\/archive.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list && \
        sed -i "s/http:\/\/security.ubuntu.com/http:\/\/mirrors.tuna.tsinghua.edu.cn/g" /etc/apt/sources.list

RUN apt-get update && \
        apt-get -y dist-upgrade && \
        apt-get install -y setpriv libprotobuf10 libnl-route-3-200

COPY --from=chroot / /chroot
COPY setup /usr/bin/
COPY drop_privs /usr/bin/
COPY nsjail /usr/bin/
COPY pwn.cfg /
RUN useradd --no-create-home -u 1000 user

RUN chmod 755 /usr/bin/setup && \
	chmod 755 /usr/bin/drop_privs && \
	chmod 755 /usr/bin/nsjail && \
	chmod 644 /pwn.cfg

EXPOSE 1337
CMD setup && \
    exec drop_privs \
    nsjail --config /pwn.cfg --mode l --port 1337 -- /bin/sh -c "/app/pow.py ask 11337 && /app/noj"
