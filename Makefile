.PHONY: build demo smoke state-test syntax

IMAGE ?= nsg-observer:local

build:
	docker build -t $(IMAGE) .

demo:
	docker compose up --build --abort-on-container-exit

smoke:
	IMAGE_NAME=$(IMAGE) bash tests/smoke.sh

syntax:
	python3 -m py_compile $$(find observer/bin observer/lib -maxdepth 1 -type f \( -name '*.py' -o -perm -u+x \))
	bash -n examples/*.sh tests/*.sh observer/etc/*.sh
	python3 -m json.tool observer/etc/state-graph.json >/dev/null

state-test:
	python3 -m unittest -v tests/test_state_graph.py tests/test_trajectory.py tests/test_trajectory_view.py
