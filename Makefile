.PHONY: build clean run generate

build:
	go build -o rsa .

clean:
	rm ./rsa
	rm ./id_rsa
	rm ./id_rsa.pub

run: build
	./rsa

generate: build
	./rsa generate --output-format pem .

convert: build
	./rsa convert --output-format jwk --key-file id_rsa.pub