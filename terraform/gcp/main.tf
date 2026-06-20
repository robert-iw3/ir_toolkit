# Locked-down GCS bucket for IR collections.
# Security posture: uniform bucket-level access, public access prevention enforced,
# object versioning, and a LOCKED retention policy (WORM) for evidence integrity.

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    google = {
      source  = "hashicorp/google"
      version = ">= 5.0"
    }
  }
}

provider "google" {
  project = var.project_id
  region  = var.region
}

resource "google_storage_bucket" "evidence" {
  name     = var.bucket_name
  project  = var.project_id
  location = var.location

  # Lockdown.
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false

  versioning {
    enabled = true
  }

  # WORM: a locked retention policy is immutable and cannot be shortened/removed.
  retention_policy {
    retention_period = var.retention_days * 24 * 60 * 60
    is_locked        = true
  }

  # CMEK when supplied (else Google-managed encryption, always on at rest).
  dynamic "encryption" {
    for_each = var.kms_key_name == "" ? [] : [var.kms_key_name]
    content {
      default_kms_key_name = encryption.value
    }
  }

  labels = merge(var.labels, { purpose = "ir-evidence" })
}
