# IR evidence storage (Terraform)

Secure, locked-down cloud storage for IR collections. Collections (logs, memory images,
flow logs) can be large; this provisions a **WORM, encrypted, private** bucket/container per
cloud so evidence can be uploaded off-host with integrity guarantees.

| Provider | Module | Hardening |
|---|---|---|
| AWS | [`aws/`](aws/) | S3 + Object Lock (COMPLIANCE WORM), versioning, SSE, full public-access block, TLS-only + encrypted-PUT-only bucket policy |
| Azure | [`azure/`](azure/) | Storage account, HTTPS-only + TLS1.2, no public blob access, network default-deny, blob versioning, container immutability (WORM) |
| GCP | [`gcp/`](gcp/) | GCS, uniform bucket-level access, public-access-prevention enforced, versioning, **locked** retention policy (WORM) |

## Usage

```bash
cd terraform/aws    # or azure / gcp
terraform init
terraform apply -var bucket_name=my-ir-evidence-bucket -var retention_days=365
```

Then upload a host collection:

```bash
aws s3 cp --recursive reports/<host>/ "$(terraform output -raw upload_uri)"         # AWS
gcloud storage cp -r reports/<host>/ "$(terraform output -raw upload_uri)"          # GCP
az storage blob upload-batch -d ir-evidence -s reports/<host>/ --account-name ...   # Azure
```

## Testing

`test/test_23_terraform_storage.py` verifies the lockdown posture of every module statically
(runs anywhere, no Terraform needed) and additionally runs `terraform validate` per module
**when the `terraform` binary is available** (CI / responder machine). For AWS this can be
extended to a LocalStack apply; Azure/GCP rely on `validate` as the diff/lint check.
