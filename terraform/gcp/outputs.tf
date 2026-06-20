output "bucket_name" {
  description = "Evidence bucket name."
  value       = google_storage_bucket.evidence.name
}

output "upload_uri" {
  description = "gs:// URI to upload a host collection into (e.g. with `gcloud storage cp -r`)."
  value       = "gs://${google_storage_bucket.evidence.name}/"
}
