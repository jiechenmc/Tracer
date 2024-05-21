FROM ubuntu:24.04

WORKDIR /app 

RUN apt-get update && \
    apt-get install -y build-essential git cmake \
    zlib1g-dev libevent-dev \
    libelf-dev llvm libbpf-dev \
    clang libc6-dev \
    wget gcc-multilib linux-headers-generic 

RUN ln -s /usr/include/x86_64-linux-gnu/asm/ /usr/include/asm

RUN wget https://go.dev/dl/go1.22.3.linux-amd64.tar.gz && tar -C /usr/local -xzf go1.22.3.linux-amd64.tar.gz

COPY main.go gen.go go.mod go.sum counter.c ./

ENV PATH="${PATH}:/usr/local/go/bin"

RUN go generate && go build

CMD [ "./packed" ]

EXPOSE 8080