# Ephemeral cloud-IR collection container.
#
# The investigation runs INSIDE this throwaway container (run with --rm). The only
# persistent trace is the evidence uploaded to locked-down cloud storage — the host
# that launched the container keeps nothing. Credentials are passed at run time
# (env / mounted secret), never baked into the image.
#
# Build:  podman build -t ir-cloud:latest -f docker/Dockerfile .
# Run:    podman run --rm --env-file docker/ir-cloud.env --tmpfs /work ir-cloud:latest
#
# Base is pinned to alpine:3.23, which ships Python 3.12 (azure-cli + gcloud compatible).
# Literal alpine:edge currently ships Python 3.14, which azure-cli does not support yet.
ARG ALPINE_VERSION=3.23
FROM alpine:${ALPINE_VERSION}

# Core toolchain + AWS CLI (Alpine ships a musl-native aws-cli v2).
RUN apk add --no-cache \
        bash coreutils ca-certificates curl jq git tar gzip unzip openssl \
        python3 py3-pip \
        aws-cli

# Azure CLI via pip. cryptography/cffi need a build toolchain on musl; install it in a
# virtual package, build the wheels, then drop it so it never reaches the final image.
RUN apk add --no-cache --virtual .build-deps \
        gcc musl-dev python3-dev libffi-dev openssl-dev make cargo rust \
    && python3 -m pip install --no-cache-dir --break-system-packages azure-cli \
    && apk del .build-deps

# Terraform — Alpine community dropped the package (license), so install the official
# pinned binary for provisioning the locked-down evidence storage.
ARG TERRAFORM_VERSION=1.9.8
RUN curl -fsSL "https://releases.hashicorp.com/terraform/${TERRAFORM_VERSION}/terraform_${TERRAFORM_VERSION}_linux_amd64.zip" \
        -o /tmp/tf.zip \
    && unzip /tmp/tf.zip -d /usr/local/bin \
    && rm /tmp/tf.zip \
    && terraform version

# Google Cloud CLI — official tarball, musl-compatible, uses the system python3.
ARG GCLOUD_VERSION=496.0.0
RUN curl -fsSL "https://dl.google.com/dl/cloudsdk/channels/rapid/downloads/google-cloud-cli-${GCLOUD_VERSION}-linux-x86_64.tar.gz" \
        -o /tmp/gcloud.tar.gz \
    && tar -xzf /tmp/gcloud.tar.gz -C /opt \
    && rm /tmp/gcloud.tar.gz \
    && /opt/google-cloud-sdk/install.sh --quiet --path-update false --usage-reporting false \
    && ln -s /opt/google-cloud-sdk/bin/gcloud /usr/local/bin/gcloud \
    && ln -s /opt/google-cloud-sdk/bin/gsutil /usr/local/bin/gsutil
ENV PATH="/opt/google-cloud-sdk/bin:${PATH}"

# The toolkit.
WORKDIR /opt/ir-toolkit
COPY . /opt/ir-toolkit
RUN chmod +x docker/entrypoint.sh Invoke-IRCollection-Cloud.sh 2>/dev/null || true

# Ephemeral scratch — collections land here, ship to cloud storage, then vanish with
# the container. Mount as tmpfs (--tmpfs /work) so nothing ever touches a real disk.
ENV IR_WORKDIR=/work
RUN mkdir -p /work
VOLUME ["/work"]

ENTRYPOINT ["/opt/ir-toolkit/docker/entrypoint.sh"]
