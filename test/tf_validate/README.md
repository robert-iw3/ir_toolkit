# Terraform/OpenTofu validate lab

A throwaway container that `terraform validate`s the IR evidence-storage modules
([`terraform/aws|azure|gcp`](../../terraform/)) with **OpenTofu** - so the modules can be
lint/diff-checked on CI or a responder machine without installing Terraform on the host (the
host here has neither). `init` runs with `-backend=false`, so no state, cloud account, or
credentials are ever touched.

```
test/tf_validate/
├── Dockerfile     alpine + OpenTofu; COPYs terraform/ + the runner; ENTRYPOINT = validate.sh
└── validate.sh    init -backend=false + validate for aws, azure, gcp; nonzero on any failure
```

## Run

```bash
# build context is the repo root (the image needs terraform/)
podman build -t ir-tf-validate -f test/tf_validate/Dockerfile .
podman run --rm ir-tf-validate
# -> "ALL MODULES VALID" and exit 0 when every module is clean
```

`validate.sh` is also runnable directly against a host-installed `tofu` or `terraform`:

```bash
TF=terraform ./test/tf_validate/validate.sh ./terraform   # if you have a host binary
```

## Tests

`test/test_41_tf_validate_docker.py` statically checks the lab is wired correctly (runs
anywhere) and, when a container runtime is present **and** `IR_RUN_TF_VALIDATE=1` is set,
builds the image and asserts every module validates. The static `terraform validate` is also
wired into `test/test_23_terraform_storage.py` for hosts that already have the binary.

## Note on the build context

The repo `.dockerignore` excludes `test/` from the cloud image, with a scoped
`!test/tf_validate` re-include so this lab's `Dockerfile` can `COPY` its runner. It does not
affect the cloud collection image's posture.
