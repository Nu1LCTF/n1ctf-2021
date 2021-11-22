FROM python:3.9-alpine
LABEL Description="n1ogin" VERSION='1.0'

ENV CRYPTOGRAPHY_DONT_BUILD_RUST=1

RUN apk update
RUN apk add gcc musl-dev python3-dev libffi-dev openssl-dev socat

WORKDIR /opt/n1ogin
RUN mkdir -p /opt/n1ogin

COPY start_from_here.py .
COPY server.py .
COPY secret.py .
COPY n1ogin.pem .

RUN pip3 install cryptography
RUN pip3 install pycryptodome

EXPOSE 7777
CMD ["python3", "start_from_here.py", ">>", "log.txt"]