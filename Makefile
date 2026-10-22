PHP_VERSION ?= 8.3.35
DISTRO_TAG ?= 8.2.32-distro
IMAGE ?= php2shell-lab
PORT ?= 8080
POD ?= US2
BASE_URL ?= http://localhost:$(PORT)

.PHONY: build run patched build-distro run-distro scan-distro verify clean

build:
	docker build --build-arg PHP_VERSION=$(PHP_VERSION) -t $(IMAGE):$(PHP_VERSION) .

run: build
	docker run --rm --name $(IMAGE) -p 127.0.0.1:$(PORT):80 $(IMAGE):$(PHP_VERSION)

patched:
	$(MAKE) PHP_VERSION=8.3.36 build

# Debian-packaged PHP 8.2.32, visible to OS package scanners.
build-distro:
	docker build -f Dockerfile.distro -t $(IMAGE):$(DISTRO_TAG) .

run-distro: build-distro
	docker run --rm --name $(IMAGE) -p 127.0.0.1:$(PORT):80 $(IMAGE):$(DISTRO_TAG)

# Requires QUALYS_CLIENT_ID and QUALYS_CLIENT_SECRET in the environment.
scan-distro: build-distro
	qscanner --pod $(POD) image $(IMAGE):$(DISTRO_TAG)

verify:
	BASE_URL=$(BASE_URL) ./scripts/verify.sh

clean:
	docker image rm -f $(IMAGE):$(PHP_VERSION) $(IMAGE):$(DISTRO_TAG) 2>/dev/null || true
