.PHONY: build clean run generate

build:
	go build -o rsa-tools .

clean:
	rm ./rsa
	rm ./id_rsa
	rm ./id_rsa.pub

run: build
	./rsa-tools

generate: build
	./rsa-tools generate --output-format der .