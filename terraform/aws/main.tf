# Locked-down S3 evidence bucket for IR collections.
# Security posture: private-only, encrypted at rest, versioned, Object Lock (WORM)
# for evidence integrity, TLS-only + encrypted-PUT-only bucket policy.

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

provider "aws" {
  region = var.region
}

# Object Lock must be enabled at creation time -> object_lock_enabled = true.
resource "aws_s3_bucket" "evidence" {
  bucket              = var.bucket_name
  object_lock_enabled = true
  force_destroy       = false

  tags = merge(var.tags, {
    Purpose = "ir-evidence"
    WORM    = "true"
  })
}

# Block ALL public access (the four switches that prevent any public exposure).
resource "aws_s3_bucket_public_access_block" "evidence" {
  bucket                  = aws_s3_bucket.evidence.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Versioning (required for Object Lock and to defeat tamper/overwrite).
resource "aws_s3_bucket_versioning" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Encryption at rest. KMS when a key is supplied, else SSE-S3 (AES256).
resource "aws_s3_bucket_server_side_encryption_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = var.kms_key_arn == "" ? "AES256" : "aws:kms"
      kms_master_key_id = var.kms_key_arn == "" ? null : var.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

# WORM retention: every object locked for var.retention_days in COMPLIANCE mode
# (no one, not even root, can delete/overwrite before expiry).
resource "aws_s3_bucket_object_lock_configuration" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  rule {
    default_retention {
      mode = var.object_lock_mode
      days = var.retention_days
    }
  }
}

# Deny plaintext (non-TLS) access and unencrypted uploads.
resource "aws_s3_bucket_policy" "evidence" {
  bucket = aws_s3_bucket.evidence.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.evidence.arn,
          "${aws_s3_bucket.evidence.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid       = "DenyUnencryptedObjectUploads"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.evidence.arn}/*"
        Condition = {
          StringNotEquals = {
            "s3:x-amz-server-side-encryption" = var.kms_key_arn == "" ? "AES256" : "aws:kms"
          }
        }
      }
    ]
  })
}
