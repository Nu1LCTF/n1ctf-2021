FROM ubuntu:18.04

RUN echo "deb http://mirrors.aliyun.com/ubuntu/ bionic main restricted universe multiverse" > /etc/apt/sources.list
RUN echo "deb http://mirrors.aliyun.com/ubuntu/ bionic-security main restricted universe multiverse" >> /etc/apt/sources.list
RUN echo "deb http://mirrors.aliyun.com/ubuntu/ bionic-updates main restricted universe multiverse" >> /etc/apt/sources.list
RUN echo "deb http://mirrors.aliyun.com/ubuntu/ bionic-proposed main restricted universe multiverse" >> /etc/apt/sources.list
RUN echo "deb http://mirrors.aliyun.com/ubuntu/ bionic-backports main restricted universe multiverse" >> /etc/apt/sources.list
RUN echo "Asia/Shanghai" > /etc/timezone
ENV TZ=Asia/Shanghai
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
RUN apt-get update && apt-get -y upgrade
RUN apt-get -y install curl
RUN curl -k https://pkg.osquery.io/deb/osquery_5.0.1-1.linux_amd64.deb -o osquery.deb
RUN dpkg -i osquery.deb
RUN apt-get install -y lib32z1 xinetd build-essential
RUN apt-get install -y libsystemd-dev gyp cmake valgrind
RUN apt-get install -y tzdata
RUN apt-get update
RUN apt-get install -y git vim php apache2

RUN mkdir -p /src/
WORKDIR /src/
RUN git clone https://github.com.cnpmjs.org/jerryscript-project/iotjs.git
RUN cd iotjs/deps/ && git clone https://github.com.cnpmjs.org/Samsung/http-parser.git
RUN cd iotjs/deps/ && git clone https://github.com.cnpmjs.org/jerryscript-project/jerryscript.git  jerry
RUN cd iotjs/deps/ && git clone https://github.com.cnpmjs.org/Samsung/libtuv.git
RUN cd iotjs/deps/ && git clone https://github.com.cnpmjs.org/ARMmbed/mbedtls.git
RUN cd iotjs && python ./tools/build.py --cmake-param=-DENABLE_MODULE_NAPI=ON
WORKDIR /

RUN useradd -m ctf

COPY ./ctf.xinetd /etc/xinetd.d/ctf
RUN echo "Blocked by ctf_xinetd" > /etc/banner_fail
RUN echo 'root - nproc 1500' >>/etc/security/limits.conf
COPY flag /flag
RUN chmod 500 /flag
COPY readflag /readflag
RUN chmod 555 /readflag
RUN chmod u+s /readflag
COPY start.sh /root/start.sh
RUN chmod 500 /root/start.sh
RUN chmod 555 -R /home/ctf
RUN chmod 555 -R /src/

RUN rm /var/www/html/index.html
COPY index.php /var/www/html/index.php
RUN chmod -R 555 /var/www/html/

CMD ["/root/start.sh"]