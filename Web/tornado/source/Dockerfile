FROM python:3.9.7-slim

COPY ./app /app
COPY ./readflag /readflag

RUN pip install -i https://mirrors.tuna.tsinghua.edu.cn/pypi/web/simple/ tornado \
    && useradd ctf \
    && chown -R ctf /app/uploads \
    && echo 'n1ctf{t0rn4d0_decim4tes_tr4iler_p4rk}' > /flag \
    && chmod 400 /flag \
    && chmod u+s /readflag

USER ctf
WORKDIR /app
ENTRYPOINT ["python3", "app.py"]
