FROM python:3

RUN apt-get update;
RUN mkdir -p /usr/src/blog
ADD requirements.txt /usr/src/blog/requirements.txt
WORKDIR /usr/src/blog
RUN ln -sf /usr/share/zoneinfo/Asia/Shanghai  /etc/localtime
RUN pip install -r requirements.txt
