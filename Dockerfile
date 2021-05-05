FROM buster:slim
WORKDIR /app
EXPOSE 3000
COPY . /app
RUN ln -s /app/target/release/nscn-cli /app/nscn
CMD /nscn