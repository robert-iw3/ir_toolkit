output "storage_account_name" {
  description = "Evidence storage account name."
  value       = azurerm_storage_account.evidence.name
}

output "container_name" {
  description = "Evidence container name."
  value       = azurerm_storage_container.evidence.name
}

output "blob_endpoint" {
  description = "Primary blob endpoint for uploading collections."
  value       = azurerm_storage_account.evidence.primary_blob_endpoint
}
