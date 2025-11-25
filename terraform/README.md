# Terraform Configuration for Network Security Control (NSC) Review Lab

This Terraform configuration creates the AWS test environment for the Network Security Control (NSC) review lab. It includes AWS Security Groups and Network ACLs as examples of NSCs:

- **Production VPC** (Network-A) with Security Groups and Network ACLs (NSC examples) for database, application, and web tiers
- **Development VPC** (Network-B) with Security Groups and Network ACLs (NSC examples) for database, application, and web tiers
- NSC rules configured for testing segmentation and security reviews, including intentional violations for educational purposes

## Setup Instructions

For complete setup instructions including Terraform installation, AWS credential configuration, and deployment steps, see the [AWS Setup Guide](../docs/aws-setup.md).

## Quick Reference

**Deploy infrastructure:**
```bash
cd terraform
terraform init
terraform plan
terraform apply
```

**Get VPC IDs:**
```bash
terraform output -raw production_vpc_id
terraform output -raw development_vpc_id
```

**Change AWS region:**
Create `terraform.tfvars`:
```hcl
aws_region = "us-west-2"
```

**Cleanup:**
```bash
terraform destroy
```

## Outputs

After applying, Terraform outputs:
- `production_vpc_id` - VPC ID for production environment
- `development_vpc_id` - VPC ID for development environment
- `production_security_groups` - Map of production security group IDs
- `development_security_groups` - Map of development security group IDs

Use these VPC IDs with the MCP server `get_config` tool.

## NSC Rules Reference

This section provides a complete reference of all Security Group and Network ACL rules created by this Terraform configuration.

### Production Environment (Network-A)

#### Production Security Groups (Instance-level NSCs)

**Production-Database-SG** (`prod_db`)
- **Description**: Security group for production database servers
- **VPC**: Production VPC (10.0.0.0/16)
- **Ingress Rules**:
  - MySQL (TCP 3306) from `Production-Application-SG` - Allow MySQL from application tier
  - PostgreSQL (TCP 5432) from `Production-Application-SG` - Allow PostgreSQL from application tier
- **Egress Rules**:
  - All traffic (all protocols, all ports) to `0.0.0.0/0` - Default allow all outbound

**Production-Application-SG** (`prod_app`)
- **Description**: Security group for production application servers
- **VPC**: Production VPC (10.0.0.0/16)
- **Ingress Rules**:
  - ⚠️ **SEGMENTATION VIOLATION** - HTTPS (TCP 443) from `10.0.0.0/8` - Overly broad CIDR block includes both Production VPC (10.0.0.0/16) and Development VPC (10.1.0.0/16), allowing cross-VPC traffic if VPCs are peered
- **Egress Rules**:
  - All traffic (all protocols, all ports) to `0.0.0.0/0` - Default allow all outbound

**Production-Web-SG** (`prod_web`)
- **Description**: Security group for production web servers
- **VPC**: Production VPC (10.0.0.0/16)
- **Ingress Rules**:
  - HTTPS (TCP 443) from `0.0.0.0/0` - Allow HTTPS from internet
- **Egress Rules**:
  - All traffic (all protocols, all ports) to `0.0.0.0/0` - Default allow all outbound

#### Production Network ACL (Subnet-level NSC)

**Production-NACL** (`production`)
- **VPC**: Production VPC (10.0.0.0/16)
- **Associated Subnet**: Production-Public (10.0.1.0/24)
- **Ingress Rules** (evaluated in order):
  - Rule 100: Allow TCP 443 (HTTPS) from `0.0.0.0/0`
  - Rule 150: ⚠️ **SEGMENTATION VIOLATION** - Allow all protocols from `10.1.0.0/16` (Development VPC)
  - Rule 200: Allow all protocols from `10.0.0.0/16` (Production VPC internal)
- **Egress Rules** (evaluated in order):
  - Rule 100: Allow all protocols to `0.0.0.0/0`
  - Rule 150: ⚠️ **SEGMENTATION VIOLATION** - Allow all protocols to `10.1.0.0/16` (Development VPC)

### Development Environment (Network-B)

#### Development Security Groups (Instance-level NSCs)

**Dev-Database-SG** (`dev_db`)
- **Description**: Security group for development database servers
- **VPC**: Development VPC (10.1.0.0/16)
- **Ingress Rules**:
  - MySQL (TCP 3306) from `Dev-Application-SG` - Allow MySQL from application tier
  - PostgreSQL (TCP 5432) from `Dev-Application-SG` - Allow PostgreSQL from application tier
  - ⚠️ **SECURITY VIOLATION** - SSH (TCP 22) from `0.0.0.0/0` - WARNING: Overly permissive SSH access
- **Egress Rules**:
  - All traffic (all protocols, all ports) to `0.0.0.0/0` - Default allow all outbound

**Dev-Application-SG** (`dev_app`)
- **Description**: Security group for development application servers
- **VPC**: Development VPC (10.1.0.0/16)
- **Ingress Rules**:
  - ⚠️ **SECURITY VIOLATION** - HTTP (TCP 80) from `0.0.0.0/0` - WARNING: Overly permissive HTTP access
- **Egress Rules**:
  - All traffic (all protocols, all ports) to `0.0.0.0/0` - Default allow all outbound

**Dev-Web-SG** (`dev_web`)
- **Description**: Security group for development web servers
- **VPC**: Development VPC (10.1.0.0/16)
- **Ingress Rules**:
  - HTTPS (TCP 443) from `0.0.0.0/0` - Allow HTTPS from internet
- **Egress Rules**:
  - All traffic (all protocols, all ports) to `0.0.0.0/0` - Default allow all outbound

#### Development Network ACL (Subnet-level NSC)

**Development-NACL** (`development`)
- **VPC**: Development VPC (10.1.0.0/16)
- **Associated Subnet**: Development-Public (10.1.1.0/24)
- **Ingress Rules** (evaluated in order):
  - Rule 100: Allow TCP 443 (HTTPS) from `0.0.0.0/0`
  - Rule 150: ⚠️ **SEGMENTATION VIOLATION** - Allow all protocols from `10.0.0.0/16` (Production VPC)
  - Rule 200: Allow all protocols from `10.1.0.0/16` (Development VPC internal)
- **Egress Rules** (evaluated in order):
  - Rule 100: Allow all protocols to `0.0.0.0/0`
  - Rule 150: ⚠️ **SEGMENTATION VIOLATION** - Allow all protocols to `10.0.0.0/16` (Production VPC)

### Security Violations and Testing

This infrastructure intentionally includes security violations for educational and testing purposes:

**Security Group Violations:**
- `Dev-Database-SG`: Overly permissive SSH (TCP 22) access from internet (0.0.0.0/0)
- `Dev-Application-SG`: Overly permissive HTTP (TCP 80) access from internet (0.0.0.0/0)
- **All Security Groups**: Egress rules allow all traffic (protocol `-1`, all ports) to `0.0.0.0/0` - overly permissive outbound access

**Network ACL Violations:**
- **Overly Permissive Rules**: Both NACLs include rules allowing all protocols (`-1`):
  - Egress Rule 100: All protocols to `0.0.0.0/0` (both NACLs)
  - Ingress Rule 200: All protocols from internal VPC (both NACLs)

**Segmentation Violations Summary:**
- **Security Groups**: `Production-Application-SG` uses overly broad CIDR block (`10.0.0.0/8`) that includes both VPCs, allowing cross-VPC traffic if VPCs are peered
- **Network ACLs**: Both NACLs explicitly allow bidirectional cross-VPC traffic via dedicated rules

**Why These Violations Matter:**

**Segmentation Violations (Cross-VPC Traffic):**
- Break network isolation between production and development environments, allowing unauthorized access between security zones
- Violate the principle of network segmentation, which is fundamental to defense-in-depth security architectures
- Can enable lateral movement attacks if one environment is compromised, potentially exposing sensitive production data

**Overly Permissive Rules (Protocol `-1` / ALL/ANY):**
- Allow all protocols (TCP, UDP, ICMP, etc.) and all ports, violating the principle of least privilege
- Increase attack surface by permitting unnecessary protocols and services
- Make security auditing difficult by obscuring what traffic is actually permitted
- Represent common misconfigurations that security reviews should identify and remediate