# Use latest golang version
FROM golang

# create app directory in container
RUN mkdir -p $GOPATH/src/go-nmap

# set /go-todo directory as default working directory
WORKDIR $GOPATH/src/go-nmap

# --pure-lockfile
RUN go get github.com/gorilla/mux
RUN go get github.com/Ullaakut/nmap/v3
# copy all file from current dir
COPY . .

# expose port 8080
EXPOSE 8080

# cmd to start service
CMD [ "go", "run", "main.go" ]