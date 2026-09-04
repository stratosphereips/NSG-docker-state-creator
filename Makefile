.PHONY: build demo smoke syntax

IMAGE ?= nsg-observer:local

build:
	docker build -t $(IMAGE) .

demo:
	docker compose up --build --abort-on-container-exit

smoke:
	IMAGE_NAME=$(IMAGE) bash tests/smoke.sh

syntax:
	python3 -m py_compile observer/bin/* observer/lib/*.py
	bash -n examples/*.sh tests/*.sh observer/etc/*.sh
