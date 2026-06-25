# Ephemeral cloud-IR container

Runs the cloud collection inside a throwaway `alpine:edge` container that bundles the
AWS / Azure / GCP CLIs, Terraform, and Python. The investigation leaves **no trace on the
launching host** - evidence is shipped to locked-down cloud storage and the local scratch
is wiped on exit.

## Build

```bash
podman build -t ir-cloud:latest -f docker/Dockerfile .
# or: docker build -t ir-cloud:latest -f docker/Dockerfile .
```

## Configure

Copy the template and fill it in:

```bash
cp docker/ir-cloud.env.template docker/ir-cloud.env
$EDITOR docker/ir-cloud.env
```

All knobs are `IR_*` env vars (provider, target, IOCs, containment, disk snapshots,
evidence bucket + WORM retention). Credentials are passed at run time, never baked in.

## Run (ephemeral)

```bash
podman run --rm \
    --env-file docker/ir-cloud.env \
    --tmpfs /work \
    -v /path/to/gcp-sa.json:/secrets/gcp-sa.json:ro \   # GCP only
    ir-cloud:latest
```

- `--rm` + `--tmpfs /work` → nothing the investigation produces ever touches a real disk.
- The collection is uploaded to the WORM bucket from `terraform/<provider>/`
  (set `IR_PROVISION_EVIDENCE=1` to terraform-apply it first).
- After upload, `/work` is wiped (`IR_WIPE_WORKDIR=1`).

Preview the exact command without running it:

```bash
podman run --rm -e IR_DRY_RUN=1 --env-file docker/ir-cloud.env ir-cloud:latest
```

## Verification

`test/test_24_docker_entrypoint.py` validates the entrypoint arg-construction (dry-run),
required-var enforcement, the env template, and the Dockerfile posture (no baked secrets,
all CLIs + terraform installed). A real image build is validated with `podman build`.
