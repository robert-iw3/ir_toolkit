# Locked-down Azure Storage for IR collections.
# Security posture: HTTPS-only + TLS1.2 min, no public blob access, infrastructure
# encryption, blob versioning, and a container immutability (WORM) policy.

terraform {
  required_version = ">= 1.3.0"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = ">= 3.70"
    }
  }
}

provider "azurerm" {
  features {}
}

resource "azurerm_resource_group" "evidence" {
  name     = var.resource_group_name
  location = var.location
  tags     = merge(var.tags, { Purpose = "ir-evidence" })
}

resource "azurerm_storage_account" "evidence" {
  name                = var.storage_account_name
  resource_group_name = azurerm_resource_group.evidence.name
  location            = azurerm_resource_group.evidence.location

  account_tier             = "Standard"
  account_replication_type = "GRS"
  account_kind             = "StorageV2"

  # Lockdown.
  https_traffic_only_enabled        = true
  min_tls_version                   = "TLS1_2"
  allow_nested_items_to_be_public   = false
  public_network_access_enabled     = false
  shared_access_key_enabled         = true
  infrastructure_encryption_enabled = true

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = var.retention_days
    }
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
    ip_rules       = var.allowed_ip_rules
  }

  tags = merge(var.tags, { Purpose = "ir-evidence" })
}

resource "azurerm_storage_container" "evidence" {
  name                  = var.container_name
  storage_account_name  = azurerm_storage_account.evidence.name
  container_access_type = "private"
}

# WORM: time-based immutability policy on the evidence container.
resource "azurerm_storage_container_immutability_policy" "evidence" {
  storage_container_resource_manager_id = azurerm_storage_container.evidence.resource_manager_id
  immutability_period_in_days           = var.retention_days
  protected_append_writes_all_enabled   = true
}
