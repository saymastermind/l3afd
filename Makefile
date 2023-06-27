.PHONY: all

#export GOPATH := $(HOME)/go
#all: swagger build
export GOPATH := $(shell pwd)/output/go
all: build

#swagger:
#	@mkdir $(GOPATH) || true 
#	@go install github.com/swaggo/swag/cmd/swag@latest
#	@$(GOPATH)/bin/swag init -d "./" -g "apis/configwatch.go"

build:
	# ldflags for static linking: -linkmode=external
	# ldflags to remove symbol table and debug information to reduce overall binary size: -s -w
	@CGO_ENABLED=0 go build -ldflags \
		"-X main.Version=v1.0.0 \
		 -X main.VersionSHA=`git rev-parse HEAD`"
install: build
	@CGO_ENABLED=0 go install -ldflags \
		"-X main.Version=v1.0.0 \
		 -X main.VersionSHA=`git rev-parse HEAD`"
