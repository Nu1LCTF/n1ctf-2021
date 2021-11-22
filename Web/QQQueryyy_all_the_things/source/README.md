### build
 docker build -t n1ctf2022 .
### run
 docker run -d restart=always -p 0.0.0.0:12321:80/tcp n1ctf2022
