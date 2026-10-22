PHP_VERSION ?= 8.3.35
IMAGE ?= php2shell-lab
PORT ?= 8080
BASE_URL ?= http://localhost:$(PORT)

.PHONY: build run patched verify clean

build:
	docker build --build-arg PHP_VERSION=$(PHP_VERSION) -t $(IMAGE):$(PHP_VERSION) .

run: build
	docker run --rm --name $(IMAGE) -p 127.0.0.1:$(PORT):80 $(IMAGE):$(PHP_VERSION)

patched:
	$(MAKE) PHP_VERSION=8.3.36 build

verify:
	BASE_URL=$(BASE_URL) ./scripts/verify.sh

clean:
	docker image rm -f $(IMAGE):$(PHP_VERSION) 2>/dev/null || true
