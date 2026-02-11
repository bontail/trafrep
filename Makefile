.PHONY: all build build_bsd test

all: build build_bsd

build:
	go build -v -o out/smd smd

build_bsd:
	env GOOS=freebsd GOARCH=amd64 \
		go build -v -o ./out/bsd/smd

test:
	go test -count=1 ./test/...
