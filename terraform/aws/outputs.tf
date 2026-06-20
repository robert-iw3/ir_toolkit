output "bucket_name" {
  description = "Name of the IR evidence bucket."
  value       = aws_s3_bucket.evidence.id
}

output "bucket_arn" {
  description = "ARN of the IR evidence bucket."
  value       = aws_s3_bucket.evidence.arn
}

output "upload_uri" {
  description = "S3 URI to upload a host collection into (e.g. with `aws s3 cp --recursive`)."
  value       = "s3://${aws_s3_bucket.evidence.id}/"
}
