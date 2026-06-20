variable "project_id" {
  description = "GCP project ID."
  type        = string
}

variable "region" {
  description = "GCP region."
  type        = string
  default     = "us-central1"
}

variable "location" {
  description = "Bucket location (region or multi-region, e.g. US)."
  type        = string
  default     = "US"
}

variable "bucket_name" {
  description = "Globally-unique GCS bucket name for IR evidence."
  type        = string
}

variable "retention_days" {
  description = "Locked retention (WORM) window in days."
  type        = number
  default     = 365
}

variable "kms_key_name" {
  description = "Optional CMEK key resource name. Empty uses Google-managed encryption."
  type        = string
  default     = ""
}

variable "labels" {
  description = "Extra labels."
  type        = map(string)
  default     = {}
}
