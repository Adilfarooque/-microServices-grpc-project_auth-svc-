proto:
	protc --go-out=. --go-grpc_out=. ./pkg/pb/auth.proto

server:
	go run cmd/main.go