# Throwaway image that terraform-`validate`s the IR evidence-storage modules with
# OpenTofu (a drop-in, license-clean Terraform). Gives CI / a responder machine a way to
# lint the AWS/Azure/GCP modules without installing Terraform on the host.
#
# Build (context = repo root):  podman build -t ir-tf-validate -f test/tf_validate/Dockerfile .
# Run:                          podman run --rm ir-tf-validate
FROM alpine:3.23

ARG TOFU_VERSION=1.9.0
RUN apk add --no-cache bash curl unzip ca-certificates \
 && curl -fsSL "https://github.com/opentofu/opentofu/releases/download/v${TOFU_VERSION}/tofu_${TOFU_VERSION}_linux_amd64.zip" -o /tmp/tofu.zip \
 && unzip /tmp/tofu.zip tofu -d /usr/local/bin \
 && rm /tmp/tofu.zip \
 && tofu version

WORKDIR /work
# The modules under validation + the runner (build context is the repo root).
COPY terraform/ /work/terraform/
COPY test/tf_validate/validate.sh /usr/local/bin/validate.sh
RUN chmod +x /usr/local/bin/validate.sh

ENTRYPOINT ["/usr/local/bin/validate.sh"]
