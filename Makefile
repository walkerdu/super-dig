PROTO_PATHS = $(shell find pkg/ -name '*.proto' | xargs -I {} dirname {} | uniq)

CMD_TARGETS = $(notdir $(shell find cmd/* -maxdepth 0 -type d))

# target 实现

.DEFAULT_GOAL := all

.PHONY: deps all proto $(CMD_TARGETS) lint proto_path codegen test

export PATH := $(shell pwd)/deps/:$(PATH)
export CGO_ENABLED=0

# 依赖工具安装

deps/protoc:
	bash scripts/get-protoc.sh

deps/protoc-gen-go:
	go env
	export GOBIN=`pwd`/deps; cd; GO111MODULE=on go install github.com/golang/protobuf/protoc-gen-go@v1.3.5

deps/golangci-lint:
	bash scripts/get-golangci-lint.sh -b deps v1.39.0

deps/ginkgo:
	export GOBIN=`pwd`/deps; cd; GO111MODULE=on go install github.com/onsi/ginkgo/ginkgo@latest

deps/mockgen:
	export GOBIN=`pwd`/deps; cd; GO111MODULE=on go install github.com/golang/mock/mockgen@v1.5.0

#deps: deps/protoc deps/protoc-gen-go deps/golangci-lint deps/ginkgo deps/mockgen
deps: deps/golangci-lint deps/ginkgo deps/mockgen

# 构建应用

all: $(CMD_TARGETS)

$(CMD_TARGETS): deps codegen
	CGO_ENABLED=0 go build -o bin/$@ ./cmd/$@

# 生成 protobuf 源码

proto: deps proto_path

proto_path: $(PROTO_PATHS)
	@$(foreach p,$^,protoc -I . --go_out=plugins=grpc,paths=source_relative:. $(wildcard $(p)/*.proto);)


# 生成 代码
codegen: deps proto
	go generate ./...

lint: deps codegen
	golangci-lint run ./...

test : deps proto codegen
	go test ./...
