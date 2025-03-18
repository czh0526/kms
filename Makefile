.PHONY: all build test clean

all: build

build:
	go build -o bin/kms ./main.go

test:
	go test ./...

clean:
	rm -rf bin

gen-dao:
	@echo "Generating dao code..."
	rm -rf ./store/db/dao ./store/db/model/*.gen.go
	gentool -dsn="root:123456@tcp(localhost:3306)/kms_db?parseTime=true" -outPath="./store/db/dao" -outFile="query.go" -withUnitTest=true