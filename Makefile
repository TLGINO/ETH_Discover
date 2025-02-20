all: lint vet

lint:
	# Coding style static check.
	@go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.60.1
	@go mod tidy
	golangci-lint run

vet:
	go vet .