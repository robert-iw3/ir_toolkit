variable "region" {
  description = "AWS region for the evidence bucket."
  type        = string
  default     = "us-east-1"
}

variable "bucket_name" {
  description = "Globally-unique S3 bucket name for IR evidence."
  type        = string
}

variable "retention_days" {
  description = "WORM retention window (days) applied to every object via Object Lock."
  type        = number
  default     = 365
}

variable "object_lock_mode" {
  description = "Object Lock mode: COMPLIANCE (immutable even to root) or GOVERNANCE."
  type        = string
  default     = "COMPLIANCE"
  validation {
    condition     = contains(["COMPLIANCE", "GOVERNANCE"], var.object_lock_mode)
    error_message = "object_lock_mode must be COMPLIANCE or GOVERNANCE."
  }
}

variable "kms_key_arn" {
  description = "Optional KMS key ARN. Empty string uses SSE-S3 (AES256)."
  type        = string
  default     = ""
}

variable "tags" {
  description = "Extra tags applied to the bucket."
  type        = map(string)
  default     = {}
}
