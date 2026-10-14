output "service_account_role_arn" {
  description = "Annotate the service account with eks.amazonaws.com/role-arn = this value"
  value       = aws_iam_role.provenance.arn
}

output "database_url_secret_name" {
  description = "Secrets Manager secret synced to Kubernetes as DATABASE_URL"
  value       = aws_secretsmanager_secret.database_url.name
}

output "kms_key_arn" {
  description = "KMS key that encrypts the database, secrets and archive bucket; use it for signing-key secrets"
  value       = aws_kms_key.provenance.arn
}

output "archive_bucket" {
  description = "Object Lock (compliance mode) bucket; set provenance.archive.bucket to this value"
  value       = aws_s3_bucket.archive.bucket
}
