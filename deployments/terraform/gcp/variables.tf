variable "name" {
  description = "Resource name prefix"
  type        = string
  default     = "agent-action-provenance"
}

variable "project_id" {
  description = "GCP project"
  type        = string
}

variable "region" {
  description = "GCP region"
  type        = string
}

variable "network_id" {
  description = "VPC network self link with private services access configured"
  type        = string
}

variable "db_tier" {
  description = "Cloud SQL machine tier"
  type        = string
  default     = "db-custom-4-16384"
}

variable "namespace" {
  description = "Kubernetes namespace of the provenance"
  type        = string
  default     = "agent-provenance"
}

variable "service_account" {
  description = "Kubernetes service account of the provenance"
  type        = string
  default     = "agent-action-provenance"
}

variable "archive_retention_days" {
  description = "Bucket retention for sealed batches and audit chains"
  type        = number
  default     = 2555
}

variable "lock_archive_retention" {
  description = "Permanently lock the retention policy (irreversible)"
  type        = bool
  default     = false
}
