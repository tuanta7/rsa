.PHONY: build clean run

build:
	go build -o rsa .

clean:
	rm ./rsa
	rm ./id_rsa
	rm ./id_rsa.pub

run: build
	./rsa