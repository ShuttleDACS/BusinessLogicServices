FROM golang:latest

WORKDIR /go/src/app
ADD . .
ADD libsodium.so.23 .
RUN \
    mkdir -p /tmpbuild/libsodium && \
    cd /tmpbuild/libsodium && \
    curl -L https://download.libsodium.org/libsodium/releases/libsodium-1.0.16.tar.gz -o libsodium-1.0.16.tar.gz && \
    tar xfvz libsodium-1.0.16.tar.gz && \
    cd /tmpbuild/libsodium/libsodium-1.0.16/ && \
    ./configure --disable-shared && \
    make && make check && \
    make install && \
    mv src/libsodium /usr/local/ && \
    rm -Rf /tmpbuild/

ENV C_INCLUDE_PATH="/usr/include"
ENV PATH="/usr/local/lib:${PATH}"
ENV LD_LIBRARY_PATH /home/dev/lib
RUN go get -d -v ./...
RUN go install  -v ./...  
RUN CGO_CPPFLAGS="-I/usr/include" \
CGO_LDFLAGS="-L/usr/local/lib -L/usr/local/lib/s390x-linux-gnu -lpthread -lsodium -lrt -lstdc++ -lm -lc -lgcc" \
go build -a -tags netgo --ldflags '-extldflags "-static"' *.go
CMD ["app"]
