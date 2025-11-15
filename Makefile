.PHONY: build clean run generate

build:
	go build -o keys .

clean:
	rm ./rsa
	rm ./id_rsa
	rm ./id_rsa.pub

run: build
	./keys

generate: build
	./keys generate --output-format der .