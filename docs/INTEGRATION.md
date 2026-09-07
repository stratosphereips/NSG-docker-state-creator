# Integrating other images

## Supported base images

The provided Dockerfile installs packages using `apt` and the Zeek Ubuntu
repository. Its supported default is Ubuntu 24.04. Ubuntu/Debian-derived images
with `apt-get`, glibc, and ordinary GNU userland are the intended integration
target.

Alpine, distroless, scratch, and non-Linux images need a different packaging
layer. Copying these scripts alone is insufficient because Zeek, BCC, strace,
libbpf tools, inotifywait, tcpdump and their shared libraries must also be
present.

## Rebuild on an existing image

From this repository:

```bash
docker build \
  --build-arg BASE_IMAGE=registry.example/team/application:1.2.3 \
  --build-arg ZEEK_REPOSITORY=xUbuntu_24.04 \
  -t registry.example/team/application-observed:1.2.3 \
  .
```

The base image must allow package installation as root. The build changes the
final image user to root because kernel and network collectors need elevated
permissions. To run the workload as the original image user, set
`OBS_WORKLOAD_USER` to the original user, UID, `user:group`, or `uid:gid`.

## Preserve the original command

This image must replace the original `ENTRYPOINT` so observation starts first.
Pass the original entrypoint and command after the observed image name.

Given an original image configured like this:

```dockerfile
ENTRYPOINT ["/usr/local/bin/server"]
CMD ["--listen", "0.0.0.0:8080"]
```

run its observed derivative as:

```bash
docker run --rm \
  --privileged \
  --security-opt seccomp=unconfined \
  -p 8080:8080 \
  -v application-evidence:/observation \
  -v /lib/modules:/lib/modules:ro \
  -v /usr/src:/usr/src:ro \
  registry.example/team/application-observed:1.2.3 \
  /usr/local/bin/server --listen 0.0.0.0:8080
```

Inspect the original configuration with:

```bash
docker image inspect registry.example/team/application:1.2.3 \
  --format 'Entrypoint={{json .Config.Entrypoint}} Cmd={{json .Config.Cmd}} User={{json .Config.User}} WorkingDir={{json .Config.WorkingDir}}'
```

## Compose integration

```yaml
services:
  application:
    image: registry.example/team/application-observed:1.2.3
    privileged: true
    security_opt:
      - seccomp=unconfined
    volumes:
      - application-evidence:/observation
      - /lib/modules:/lib/modules:ro
      - /usr/src:/usr/src:ro
    command:
      - /usr/local/bin/server
      - --listen
      - 0.0.0.0:8080
    environment:
      OBS_SNAPSHOT_INTERVAL: "30"
      OBS_PCAP_FILE_MB: "100"
      OBS_PCAP_FILE_COUNT: "10"
      OBS_STATE_LEVEL: "operational"
      OBS_TRAJECTORY_SENSITIVITY: "material"
      # Optional: preserve an original non-root runtime user.
      # OBS_WORKLOAD_USER: "1000:1000"

volumes:
  application-evidence:
```

Keep the application's original ports, networks, environment variables,
secrets, mounts, working directory and other service settings unchanged.

## Read state inside or outside the container

The observed application and any agent it launches can read the live state from
inside its own container:

```bash
jq . /observation/state/summary.json
```

The default entrypoint keeps that state current. An outside controller can
mount the same evidence volume and run the identical compiler for replay or a
different level:

```bash
docker run --rm \
  --entrypoint state-builder \
  -v application-evidence:/observation \
  registry.example/team/application-observed:1.2.3 \
  --input /observation \
  --output /observation/state-forensic \
  --level forensic
```

Keep `/observation/state` for the embedded live builder. An external build or
sidecar must use another output path, such as `/observation/state-forensic`,
so two processes never overwrite the same state files.

The embedded passive action monitor similarly owns
`/observation/trajectory`. Both the application and an outside controller with
the evidence volume mounted can consume its ordered index:

```bash
# Inside the observed container
tail -n 20 /observation/trajectory/sequence.jsonl

# Outside, without running another writer
docker run --rm -v application-evidence:/evidence:ro ubuntu:24.04 \
  tail -n 20 /evidence/trajectory/sequence.jsonl
```

To operate the state/action compiler from outside instead, disable the
embedded writer with `OBS_ENABLE_TRAJECTORY=0` and keep a sidecar running:

```bash
docker run --rm \
  --entrypoint trajectory-monitor \
  -v application-evidence:/observation \
  registry.example/team/application-observed:1.2.3 \
  --input /observation --output /observation/trajectory-external \
  --level operational --sensitivity material --watch
```

Run the trajectory builder live, beginning before the workload, when accurate
before/after states are required. A one-shot invocation over completed logs is
useful for extracting the action inventory, but the graph compiler sees the
completed evidence set and cannot recreate historical graph cutoffs that were
not captured live.

## Different Ubuntu releases

Select the matching Zeek repository when it exists:

```bash
docker build \
  --build-arg BASE_IMAGE=ubuntu:22.04 \
  --build-arg ZEEK_REPOSITORY=xUbuntu_22.04 \
  -t nsg-observer:ubuntu-22.04 .
```

Do not mix a Zeek repository built for a newer Ubuntu release into an older
base image.

## Operational checklist

1. Record the original image digest, entrypoint, command, user and working
   directory.
2. Build and tag the observed derivative without modifying the original tag.
3. Create a dedicated persistent evidence volume.
4. Run on a native Linux Docker host with `--privileged` and unconfined seccomp.
5. Mount `/lib/modules` and `/usr/src` read-only if BCC is required.
6. Set `OBS_WORKLOAD_USER` if the original image did not run as root.
7. Confirm `/observation/health.json` reports `running`.
8. Generate a file, process and network event before starting the real test.
9. Preserve or export the evidence volume after the workload exits.
10. Consume `/observation/state/summary.json` for the six core categories,
    `/observation/state/graph.json` for graph reasoning, or
    `/observation/state/embedding.jsonl` for embedding ingestion.
11. Consume `/observation/trajectory/sequence.jsonl` for ordered state/action
    training or decision records.

The raw Docker socket is not needed and should not be mounted into the
container.
