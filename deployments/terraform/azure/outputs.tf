output "workload_identity_client_id" {
  description = "Annotate the service account with azure.workload.identity/client-id = this value"
  value       = azurerm_user_assigned_identity.provenance.client_id
}

output "key_vault_uri" {
  description = "Key Vault holding the database URL and signing-key secrets"
  value       = azurerm_key_vault.provenance.vault_uri
}

output "archive_container" {
  description = "Immutable blob container for sealed batches and audit chains"
  value       = "${azurerm_storage_account.archive.name}/${azurerm_storage_container.archive.name}"
}
