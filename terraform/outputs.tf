output "production_vpc_id" {
  description = "Production VPC ID"
  value       = aws_vpc.production.id
}

output "development_vpc_id" {
  description = "Development VPC ID"
  value       = aws_vpc.development.id
}

output "production_security_groups" {
  description = "Production security group IDs"
  value = {
    database    = aws_security_group.prod_db.id
    application = aws_security_group.prod_app.id
    web         = aws_security_group.prod_web.id
  }
}

output "development_security_groups" {
  description = "Development security group IDs"
  value = {
    database    = aws_security_group.dev_db.id
    application = aws_security_group.dev_app.id
    web         = aws_security_group.dev_web.id
  }
}

