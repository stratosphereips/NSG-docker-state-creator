.PHONY: build demo smoke syntax test

IMAGE ?= nsg-observer:local

build:
	docker build -t $(IMAGE) .

demo:
	docker compose up --build --abort-on-container-exit

smoke:
	IMAGE_NAME=$(IMAGE) bash tests/smoke.sh

syntax:
	python3 -m py_compile $$(find observer/bin -maxdepth 1 -type f) observer/lib/*.py analysis/*.py analysis/detectors/*.py
	bash -n examples/*.sh tests/*.sh observer/etc/*.sh

test:
	python3 -m pytest tests/ -q
