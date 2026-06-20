variable "resource_group_name" {
  description = "Resource group to hold the evidence storage account."
  type        = string
  default     = "ir-evidence-rg"
}

variable "location" {
  description = "Azure region."
  type        = string
  default     = "eastus"
}

variable "storage_account_name" {
  description = "Globally-unique storage account name (3-24 lowercase alphanumerics)."
  type        = string
}

variable "container_name" {
  description = "Blob container for IR evidence."
  type        = string
  default     = "ir-evidence"
}

variable "retention_days" {
  description = "Immutability (WORM) + soft-delete retention window in days."
  type        = number
  default     = 365
}

variable "allowed_ip_rules" {
  description = "Public IPs/CIDRs permitted through the storage firewall (responder egress)."
  type        = list(string)
  default     = []
}

variable "tags" {
  description = "Extra tags."
  type        = map(string)
  default     = {}
}
