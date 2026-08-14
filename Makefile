.PHONY: build test vet lint run clean demo help

VERSION  := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS  := -X kestrel/internal/config.Version=$(VERSION)

# 默认目标
.DEFAULT_GOAL := build

## build: 编译二进制到 bin/kestrel
build:
	mkdir -p bin
	go build -ldflags "$(LDFLAGS)" -o bin/kestrel .

## test: 运行所有测试
test:
	go test ./test/ -v -count=1

## vet: 静态分析
vet:
	go vet ./...

## lint: 运行 golangci-lint（如果已安装）
lint:
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run ./...; \
	else \
		echo "golangci-lint 未安装，跳过。安装: go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest"; \
	fi

## run: 直接运行（从 stdin 读取）
run:
	go run . -cluster-id dev-cluster

## demo: 运行演示数据
demo:
	@echo '{"kind":"Event","apiVersion":"audit.k8s.io/v1","auditID":"demo-001","stage":"ResponseComplete","requestURI":"/api/v1/namespaces/production/pods/payment-svc/exec?command=/bin/sh&command=-c&command=cat%20%2Fetc%2Fpasswd","verb":"create","user":{"username":"system:anonymous","groups":["system:unauthenticated"]},"sourceIPs":["203.0.113.50"],"userAgent":"kubectl/v1.28.0","objectRef":{"resource":"pods","namespace":"production","name":"payment-svc","subresource":"exec"},"responseStatus":{"code":200},"stageTimestamp":"2026-08-14T03:00:00Z"}' | go run . -cluster-id demo-cluster -v

## clean: 清理构建产物
clean:
	rm -rf bin/

## help: 显示所有可用目标
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## //'
