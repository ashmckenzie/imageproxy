.PHONY: clean deps test install build
.DEFAULT_GOAL := build

DEBUG ?= false

deps:
	go get ./...

test:
	go test

install: build _install clean

_install:
	go install

build: deps test _build

_build:
	go build -o imageproxy

clean:
	@rm -f imageproxy
