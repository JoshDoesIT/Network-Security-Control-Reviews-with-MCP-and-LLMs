terraform {
  required_version = ">= 1.0"
  
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

# Configure AWS provider
provider "aws" {
  region = var.aws_region
}

# Production VPC (Network-A)
resource "aws_vpc" "production" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name    = "Production-VPC"
    Network = "Network-A"
  }
}

# Development VPC (Network-B)
resource "aws_vpc" "development" {
  cidr_block           = "10.1.0.0/16"
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name    = "Development-VPC"
    Network = "Network-B"
  }
}

# Internet Gateways
resource "aws_internet_gateway" "production" {
  vpc_id = aws_vpc.production.id

  tags = {
    Name = "Production-IGW"
  }
}

resource "aws_internet_gateway" "development" {
  vpc_id = aws_vpc.development.id

  tags = {
    Name = "Development-IGW"
  }
}

# Public Subnets
resource "aws_subnet" "production_public" {
  vpc_id                  = aws_vpc.production.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "Production-Public"
  }
}

resource "aws_subnet" "development_public" {
  vpc_id                  = aws_vpc.development.id
  cidr_block              = "10.1.1.0/24"
  availability_zone       = "${var.aws_region}a"
  map_public_ip_on_launch = true

  tags = {
    Name = "Development-Public"
  }
}

# Production Security Groups
resource "aws_security_group" "prod_db" {
  name        = "Production-Database-SG"
  description = "Security group for production database servers"
  vpc_id      = aws_vpc.production.id

  tags = {
    Name        = "Production-Database-SG"
    Environment = "Production"
    Tier        = "Database"
    Network     = "Network-A"
  }
}

resource "aws_security_group" "prod_app" {
  name        = "Production-Application-SG"
  description = "Security group for production application servers"
  vpc_id      = aws_vpc.production.id

  tags = {
    Name        = "Production-Application-SG"
    Environment = "Production"
    Tier        = "Application"
    Network     = "Network-A"
  }
}

resource "aws_security_group" "prod_web" {
  name        = "Production-Web-SG"
  description = "Security group for production web servers"
  vpc_id      = aws_vpc.production.id

  tags = {
    Name        = "Production-Web-SG"
    Environment = "Production"
    Tier        = "Web"
    Network     = "Network-A"
  }
}

# Development Security Groups
resource "aws_security_group" "dev_db" {
  name        = "Dev-Database-SG"
  description = "Security group for development database servers"
  vpc_id      = aws_vpc.development.id

  tags = {
    Name        = "Dev-Database-SG"
    Environment = "Development"
    Tier        = "Database"
    Network     = "Network-B"
  }
}

resource "aws_security_group" "dev_app" {
  name        = "Dev-Application-SG"
  description = "Security group for development application servers"
  vpc_id      = aws_vpc.development.id

  tags = {
    Name        = "Dev-Application-SG"
    Environment = "Development"
    Tier        = "Application"
    Network     = "Network-B"
  }
}

resource "aws_security_group" "dev_web" {
  name        = "Dev-Web-SG"
  description = "Security group for development web servers"
  vpc_id      = aws_vpc.development.id

  tags = {
    Name        = "Dev-Web-SG"
    Environment = "Development"
    Tier        = "Web"
    Network     = "Network-B"
  }
}

# Production Security Group Rules

# Production DB: Allow MySQL from Application tier
resource "aws_security_group_rule" "prod_db_mysql" {
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.prod_app.id
  security_group_id        = aws_security_group.prod_db.id
  description              = "Allow MySQL from application tier"
}

# Production DB: Allow PostgreSQL from Application tier
resource "aws_security_group_rule" "prod_db_postgres" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.prod_app.id
  security_group_id        = aws_security_group.prod_db.id
  description              = "Allow PostgreSQL from application tier"
}

# Production App: Allow HTTPS from internal network
resource "aws_security_group_rule" "prod_app_https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["10.0.0.0/8"]
  security_group_id = aws_security_group.prod_app.id
  description       = "Allow HTTPS from internal network"
}

# Production Web: Allow HTTPS from internet
resource "aws_security_group_rule" "prod_web_https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.prod_web.id
  description       = "Allow HTTPS from internet"
}

# Development Security Group Rules

# Development DB: Allow MySQL from Application tier
resource "aws_security_group_rule" "dev_db_mysql" {
  type                     = "ingress"
  from_port                = 3306
  to_port                  = 3306
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.dev_app.id
  security_group_id        = aws_security_group.dev_db.id
  description              = "Allow MySQL from application tier"
}

# Development DB: Allow PostgreSQL from Application tier
resource "aws_security_group_rule" "dev_db_postgres" {
  type                     = "ingress"
  from_port                = 5432
  to_port                  = 5432
  protocol                 = "tcp"
  source_security_group_id = aws_security_group.dev_app.id
  security_group_id        = aws_security_group.dev_db.id
  description              = "Allow PostgreSQL from application tier"
}

# Development DB: Intentionally permissive SSH (for testing)
resource "aws_security_group_rule" "dev_db_ssh" {
  type              = "ingress"
  from_port         = 22
  to_port           = 22
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.dev_db.id
  description       = "WARNING: Overly permissive SSH access"
}

# Development App: Overly permissive HTTP (for testing)
resource "aws_security_group_rule" "dev_app_http" {
  type              = "ingress"
  from_port         = 80
  to_port           = 80
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.dev_app.id
  description       = "WARNING: Overly permissive HTTP access"
}

# Development Web: Allow HTTPS from internet
resource "aws_security_group_rule" "dev_web_https" {
  type              = "ingress"
  from_port         = 443
  to_port           = 443
  protocol          = "tcp"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.dev_web.id
  description       = "Allow HTTPS from internet"
}

# Default egress rules (allow all outbound traffic)
resource "aws_security_group_rule" "prod_db_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.prod_db.id
}

resource "aws_security_group_rule" "prod_app_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.prod_app.id
}

resource "aws_security_group_rule" "prod_web_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.prod_web.id
}

resource "aws_security_group_rule" "dev_db_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.dev_db.id
}

resource "aws_security_group_rule" "dev_app_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.dev_app.id
}

resource "aws_security_group_rule" "dev_web_egress" {
  type              = "egress"
  from_port         = 0
  to_port           = 0
  protocol          = "-1"
  cidr_blocks       = ["0.0.0.0/0"]
  security_group_id = aws_security_group.dev_web.id
}

# Network ACLs

# Production Network ACL
resource "aws_network_acl" "production" {
  vpc_id = aws_vpc.production.id

  tags = {
    Name        = "Production-NACL"
    Environment = "Production"
    Network     = "Network-A"
  }
}

# Production Network ACL Rules - Ingress
resource "aws_network_acl_rule" "production_ingress_https" {
  network_acl_id = aws_network_acl.production.id
  rule_number     = 100
  protocol        = "tcp"
  rule_action     = "allow"
  cidr_block      = "0.0.0.0/0"
  from_port       = 443
  to_port         = 443
}

resource "aws_network_acl_rule" "production_ingress_internal" {
  network_acl_id = aws_network_acl.production.id
  rule_number    = 200
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "10.0.0.0/16"
}

# Production Network ACL Rules - Egress
resource "aws_network_acl_rule" "production_egress_all" {
  network_acl_id = aws_network_acl.production.id
  rule_number    = 100
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  egress         = true
}

# Development Network ACL
resource "aws_network_acl" "development" {
  vpc_id = aws_vpc.development.id

  tags = {
    Name        = "Development-NACL"
    Environment = "Development"
    Network     = "Network-B"
  }
}

# Development Network ACL Rules - Ingress
resource "aws_network_acl_rule" "development_ingress_https" {
  network_acl_id = aws_network_acl.development.id
  rule_number    = 100
  protocol       = "tcp"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  from_port      = 443
  to_port        = 443
}

resource "aws_network_acl_rule" "development_ingress_internal" {
  network_acl_id = aws_network_acl.development.id
  rule_number    = 200
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "10.1.0.0/16"
}

# SEGMENTATION VIOLATION: Development NACL allows traffic from Production VPC
# This violates network segmentation by allowing cross-VPC traffic
resource "aws_network_acl_rule" "development_ingress_production_violation" {
  network_acl_id = aws_network_acl.development.id
  rule_number    = 150
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "10.0.0.0/16"
}

# Development Network ACL Rules - Egress
resource "aws_network_acl_rule" "development_egress_all" {
  network_acl_id = aws_network_acl.development.id
  rule_number    = 100
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "0.0.0.0/0"
  egress         = true
}

# SEGMENTATION VIOLATION: Development NACL egress allows traffic to Production VPC
# This violates network segmentation by allowing cross-VPC traffic
resource "aws_network_acl_rule" "development_egress_production_violation" {
  network_acl_id = aws_network_acl.development.id
  rule_number    = 150
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "10.0.0.0/16"
  egress         = true
}

# SEGMENTATION VIOLATION: Production NACL allows traffic from Development VPC
# This violates network segmentation by allowing cross-VPC traffic
resource "aws_network_acl_rule" "production_ingress_development_violation" {
  network_acl_id = aws_network_acl.production.id
  rule_number    = 150
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "10.1.0.0/16"
}

# SEGMENTATION VIOLATION: Production NACL egress allows traffic to Development VPC
# This violates network segmentation by allowing cross-VPC traffic
resource "aws_network_acl_rule" "production_egress_development_violation" {
  network_acl_id = aws_network_acl.production.id
  rule_number    = 150
  protocol       = "-1"
  rule_action    = "allow"
  cidr_block     = "10.1.0.0/16"
  egress         = true
}

# Associate Network ACLs with subnets
resource "aws_network_acl_association" "production_public" {
  network_acl_id = aws_network_acl.production.id
  subnet_id      = aws_subnet.production_public.id
}

resource "aws_network_acl_association" "development_public" {
  network_acl_id = aws_network_acl.development.id
  subnet_id      = aws_subnet.development_public.id
}

