FROM debian:buster-slim
WORKDIR /app
EXPOSE 3000
RUN echo "deb http://mirrors.aliyun.com/debian/ buster main contrib non-free" > /etc/apt/sources.list
RUN echo "deb-src http://mirrors.aliyun.com/debian/ buster main contrib non-free" >> /etc/apt/sources.list
RUN apt-get update
RUN apt-get install -y libssl-dev ca-certificates
COPY . /app
RUN ln -s /app/target/release/nscn-cli /app/nscn
CMD /app/nscn