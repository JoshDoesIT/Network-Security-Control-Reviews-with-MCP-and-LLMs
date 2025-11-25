# AWS Environment Setup Guide

This guide walks you through setting up the AWS environment for the Network Security Control (NSC) review lab using Terraform. This lab uses AWS Security Groups and Network ACLs as examples of NSCs. All commands are copy-paste ready for macOS.

## Prerequisites

- macOS
- Fresh AWS Account (free tier)
- Homebrew installed

## Step 1: Install AWS CLI and Terraform

### Install AWS CLI

**Important:** Homebrew may not have the latest AWS CLI version. Install AWS CLI v2 using the official AWS installer.

**Follow the official AWS CLI installation instructions for macOS:**
[AWS CLI Installation Guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html#getting-started-install-instructions)

After installation, verify you have AWS CLI v2:
```bash
aws --version
```

You should see `aws-cli/2.x.x` (version >=2.32.0).

### Install Terraform (Homebrew, recommended)

```bash
# If you don't already have it, install Homebrew
/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"

# Add HashiCorp tap
brew tap hashicorp/tap

# Install Terraform
brew install hashicorp/tap/terraform

# Verify installation
terraform version
```

## Step 2: Configure AWS Credentials

**⚠️ Security: Never hardcode credentials in code or configuration files.**
Credentials are managed via `aws login` or `aws configure` and are never stored in source code.

**Starting Point:** This lab assumes you have a fresh AWS account with root account access (email/password).

**Note on Root Account Usage:** While you should avoid using the root account for day-to-day operations, using root for initial account setup (like creating IAM users) is acceptable and common practice. For this lab, we'll use root credentials via `aws login` to create the lab IAM users, then switch to using those least-privilege users for all operations. This demonstrates IAM best practices while keeping the lab setup practical.

### Configure AWS CLI with Root Account

Use AWS CLI V2's `aws login` command for browser-based authentication. We'll use a profile called `root` to keep credentials organized:

```bash
aws login --profile root
```

**If prompted for AWS Region**, enter us-east-1 or your preferred region:
```
AWS Region [us-east-1]: us-east-1
```

When prompted, you can log in as **root** (your AWS account email/password). This will open your browser to authenticate. Follow the prompts to complete the login.

### Create Lab IAM Users

Create two separate IAM users with least-privilege permissions (using root profile):

```bash
# Create IAM user for Terraform
aws iam create-user --profile root --user-name nsc-lab-terraform-user

# Create access key for Terraform user
aws iam create-access-key --profile root --user-name nsc-lab-terraform-user
```

**Save the Terraform Access Key ID and Secret Access Key** from the output somewhere secure, like a password manager. **Never commit these to Git or share them.**

```bash
# Create IAM user for MCP server
aws iam create-user --profile root --user-name nsc-lab-mcp-user

# Create access key for MCP server user
aws iam create-access-key --profile root --user-name nsc-lab-mcp-user
```

**Save the MCP Server Access Key ID and Secret Access Key** from the output somewhere secure, like a password manager. **Again, never commit these to Git or share them.**

### Create Policies and Attach to Users

Create custom policies and attach them to the users:

```bash
# Create Terraform policy file
cat > /tmp/nsc-lab-terraform-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeSecurityGroupRules",
        "ec2:DescribeVpcs",
        "ec2:DescribeVpcAttribute",
        "ec2:DescribeSubnets",
        "ec2:DescribeNetworkInterfaces",
        "ec2:DescribeInternetGateways",
        "ec2:CreateVpc",
        "ec2:ModifyVpcAttribute",
        "ec2:CreateSubnet",
        "ec2:ModifySubnetAttribute",
        "ec2:CreateInternetGateway",
        "ec2:AttachInternetGateway",
        "ec2:CreateSecurityGroup",
        "ec2:AuthorizeSecurityGroupIngress",
        "ec2:AuthorizeSecurityGroupEgress",
        "ec2:CreateNetworkAcl",
        "ec2:CreateNetworkAclEntry",
        "ec2:ReplaceNetworkAclEntry",
        "ec2:ReplaceNetworkAclAssociation",
        "ec2:CreateTags",
        "ec2:DeleteVpc",
        "ec2:DeleteSubnet",
        "ec2:DetachInternetGateway",
        "ec2:DeleteInternetGateway",
        "ec2:DeleteSecurityGroup",
        "ec2:RevokeSecurityGroupIngress",
        "ec2:RevokeSecurityGroupEgress",
        "ec2:DeleteNetworkAcl",
        "ec2:DeleteNetworkAclEntry"
      ],
      "Resource": "*"
    }
  ]
}
EOF

# Create the Terraform policy
aws iam create-policy --profile root \
  --policy-name NSCLabTerraformPolicy \
  --policy-document file:///tmp/nsc-lab-terraform-policy.json

# Get your AWS account ID (needed for policy ARN)
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --profile root --query Account --output text)

# Attach Terraform policy to Terraform user
aws iam attach-user-policy --profile root \
  --user-name nsc-lab-terraform-user \
  --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/NSCLabTerraformPolicy

# Clean up temp file
rm /tmp/nsc-lab-terraform-policy.json

# Create MCP server policy file
cat > /tmp/nsc-lab-mcp-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:DescribeSecurityGroups",
        "ec2:DescribeVpcs",
        "ec2:DescribeNetworkAcls",
        "ec2:DescribeNetworkAclEntries",
        "ec2:DescribeSubnets"
      ],
      "Resource": "*"
    }
  ]
}
EOF

# Create the MCP server policy
aws iam create-policy --profile root \
  --policy-name NSCLabMCPPolicy \
  --policy-document file:///tmp/nsc-lab-mcp-policy.json

# Attach MCP server policy to MCP server user
aws iam attach-user-policy --profile root \
  --user-name nsc-lab-mcp-user \
  --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/NSCLabMCPPolicy

# Clean up temp file
rm /tmp/nsc-lab-mcp-policy.json
```

### Configure Terraform and MCP User Profiles

Now that the lab users are created and policies are attached, configure separate profiles for each user. This keeps credentials organized and allows you to easily switch between them:

**Configure Terraform user profile:**

```bash
# Configure AWS CLI with the Terraform user's credentials in a "terraform" profile
aws configure --profile terraform
```

Enter when prompted:
- **AWS AccessKeyId**: The Terraform AccessKeyId from above
- **AWS SecretAccessKey**: The Terraform SecretAccessKey from above
- **Default region**: `us-east-1` (or your preferred region)
- **Default output format**: `json`

**Configure MCP server user profile:**

```bash
# Configure AWS CLI with the MCP server user's credentials in an "mcp" profile
aws configure --profile mcp
```

Enter when prompted:
- **AWS AccessKeyId**: The MCP Server AccessKeyId from above
- **AWS SecretAccessKey**: The MCP Server SecretAccessKey from above
- **Default region**: `us-east-1` (or your preferred region)
- **Default output format**: `json`

**Set secure file permissions:**
```bash
# Restrict access to credential files (prevents other users from reading)
chmod 600 ~/.aws/credentials
chmod 600 ~/.aws/config

# Verify permissions
ls -la ~/.aws/
# Should show: -rw------- (600) for credentials and config files
```

**Note:** You now have three profiles configured:
- `root` - Root account (SSO via `aws login`)
- `terraform` - Terraform user (access keys) - Use for infrastructure management
- `mcp` - MCP server user (access keys) - Use for MCP server configuration

This separation follows least-privilege principles - Terraform has write permissions for infrastructure management, while the MCP server has read-only permissions for querying NSCs.

## Step 3: Clone the Repository

Clone or download the repository to your local machine:

```bash
# Clone the repository
git clone <repository-url>
cd Network-Security-Control-Reviews-with-MCP

# Or if you've already cloned it, navigate to the directory
cd /path/to/Network-Security-Control-Reviews-with-MCP
```

**Note:** Replace `<repository-url>` with the actual repository URL, or download the repository as a ZIP file and extract it.

**Verify credentials are excluded from Git (if using Git):**
```bash
# From within the project directory, verify .gitignore excludes credential files
git check-ignore .aws/credentials
# Should output: .aws/credentials
```

This confirms that AWS credential files won't be accidentally committed to version control.

## Step 4: Deploy Infrastructure

```bash
# Navigate to terraform directory
cd terraform

# Set AWS profile to use terraform credentials
export AWS_PROFILE=terraform

# Initialize Terraform
terraform init

# Review what will be created
terraform plan

# Deploy infrastructure (type 'yes' when prompted)
terraform apply
```

**Note:** The `AWS_PROFILE=terraform` environment variable tells Terraform to use the `terraform` profile credentials. You can also set this in your shell profile (e.g., `~/.zshrc` or `~/.bashrc`) to make it persistent.

**That's it!** Terraform will create:
- **Production VPC (Network-A)** with Security Groups, Network ACLs, subnets, and internet gateway
- **Development VPC (Network-B)** with Security Groups, Network ACLs, subnets, and internet gateway
- **Security Group rules** (instance-level NSC examples) for both environments
- **Network ACL rules** (subnet-level NSC examples) including intentional segmentation violations for testing

## Step 5: Verify Setup

```bash
# Get VPC IDs into variables (save these for MCP server)
PROD_VPC_ID=$(terraform output -raw production_vpc_id)
DEV_VPC_ID=$(terraform output -raw development_vpc_id)

# Verify production security groups
aws ec2 describe-security-groups --profile terraform \
  --filters "Name=vpc-id,Values=${PROD_VPC_ID}" \
  --query 'SecurityGroups[*].[GroupId,GroupName,Tags[?Key==`Network`].Value|[0]]' \
  --output table

# Verify development security groups
aws ec2 describe-security-groups --profile terraform \
  --filters "Name=vpc-id,Values=${DEV_VPC_ID}" \
  --query 'SecurityGroups[*].[GroupId,GroupName,Tags[?Key==`Network`].Value|[0]]' \
  --output table
```

## What Was Created

Terraform deploys a complete AWS test environment demonstrating NSCs at multiple layers. The infrastructure includes:

### Production Environment (Network-A)
- **VPC**: `10.0.0.0/16` with DNS support enabled
- **Internet Gateway**: `Production-IGW` attached to production VPC
- **Public Subnet**: `10.0.1.0/24` in availability zone `a`
- **Security Groups** (Instance-level NSC examples):
  - `Production-Database-SG` - Database tier (MySQL/PostgreSQL from app tier only)
  - `Production-Application-SG` - Application tier (HTTPS from internal network)
  - `Production-Web-SG` - Web tier (HTTPS from internet)
- **Network ACL** (Subnet-level NSC example):
  - `Production-NACL` - Custom Network ACL with ingress/egress rules
  - Includes intentional segmentation violations allowing bidirectional traffic to/from Development VPC (10.1.0.0/16) for testing

### Development Environment (Network-B)
- **VPC**: `10.1.0.0/16` with DNS support enabled
- **Internet Gateway**: `Development-IGW` attached to development VPC
- **Public Subnet**: `10.1.1.0/24` in availability zone `a`
- **Security Groups** (Instance-level NSC examples):
  - `Dev-Database-SG` - Database tier (MySQL/PostgreSQL from app tier, **intentionally permissive SSH from internet**)
  - `Dev-Application-SG` - Application tier (**intentionally permissive HTTP from internet**)
  - `Dev-Web-SG` - Web tier (HTTPS from internet)
- **Network ACL** (Subnet-level NSC example):
  - `Development-NACL` - Custom Network ACL with ingress/egress rules
  - Includes intentional segmentation violations allowing bidirectional traffic to/from Production VPC (10.0.0.0/16) for testing

**📋 For complete details of all Security Group and Network ACL rules**, including protocol, port, source/destination CIDR blocks, and rule numbers, see the [Terraform README](../terraform/README.md#network-security-control-nsc-rules-reference).

### Infrastructure Components

- 2 VPCs (production and development)
- 2 Internet Gateways (one per VPC)
- 2 Public Subnets (one per VPC)
- 6 Security Groups (3 per environment)
- 2 Network ACLs (1 per environment)
- Multiple Security Group rules (ingress and egress)
- Multiple Network ACL rules (ingress and egress, including violations)
- 2 Network ACL associations (linking ACLs to subnets)

## Cleanup

### Remove Infrastructure

```bash
cd terraform
export AWS_PROFILE=terraform
terraform destroy
```

When prompted, type `yes` to confirm destruction.

### Remove IAM Resources

**⚠️ Important:** These commands require root/admin credentials. Use the `root` or your admin profile:

```bash
AWS_ACCOUNT_ID=$(aws sts get-caller-identity --profile root --query Account --output text)

# Remove Terraform user and policy
aws iam detach-user-policy --profile root \
  --user-name nsc-lab-terraform-user \
  --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/NSCLabTerraformPolicy 2>/dev/null || true

TERRAFORM_ACCESS_KEYS=$(aws iam list-access-keys --profile root --user-name nsc-lab-terraform-user --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null)
if [ ! -z "$TERRAFORM_ACCESS_KEYS" ]; then
  for key in $TERRAFORM_ACCESS_KEYS; do
    aws iam delete-access-key --profile root --user-name nsc-lab-terraform-user --access-key-id $key 2>/dev/null || true
  done
fi

aws iam delete-user --profile root --user-name nsc-lab-terraform-user 2>/dev/null || true

# Delete all non-default policy versions before deleting the policy
TERRAFORM_POLICY_VERSIONS=$(aws iam list-policy-versions --profile root \
  --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/NSCLabTerraformPolicy \
  --query 'Versions[?IsDefaultVersion==`false`].VersionId' \
  --output text 2>/dev/null)

if [ ! -z "$TERRAFORM_POLICY_VERSIONS" ] && [ "$TERRAFORM_POLICY_VERSIONS" != "None" ]; then
  for version in $TERRAFORM_POLICY_VERSIONS; do
    case "$version" in
      v[0-9]*)
        aws iam delete-policy-version --profile root \
          --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/NSCLabTerraformPolicy \
          --version-id "$version" 2>/dev/null || true
        ;;
    esac
  done
fi

# Delete the policy itself
aws iam delete-policy --profile root \
  --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/NSCLabTerraformPolicy 2>/dev/null || true

# Remove MCP server user and policy
aws iam detach-user-policy --profile root \
  --user-name nsc-lab-mcp-user \
  --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/NSCLabMCPPolicy 2>/dev/null || true

MCP_ACCESS_KEYS=$(aws iam list-access-keys --profile root --user-name nsc-lab-mcp-user --query 'AccessKeyMetadata[].AccessKeyId' --output text 2>/dev/null)
if [ ! -z "$MCP_ACCESS_KEYS" ]; then
  for key in $MCP_ACCESS_KEYS; do
    aws iam delete-access-key --profile root --user-name nsc-lab-mcp-user --access-key-id $key 2>/dev/null || true
  done
fi

aws iam delete-user --profile root --user-name nsc-lab-mcp-user 2>/dev/null || true

# Delete all non-default policy versions before deleting the policy
MCP_POLICY_VERSIONS=$(aws iam list-policy-versions --profile root \
  --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/NSCLabMCPPolicy \
  --query 'Versions[?IsDefaultVersion==`false`].VersionId' \
  --output text 2>/dev/null)

if [ ! -z "$MCP_POLICY_VERSIONS" ] && [ "$MCP_POLICY_VERSIONS" != "None" ]; then
  for version in $MCP_POLICY_VERSIONS; do
    case "$version" in
      v[0-9]*)
        aws iam delete-policy-version --profile root \
          --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/NSCLabMCPPolicy \
          --version-id "$version" 2>/dev/null || true
        ;;
    esac
  done
fi

# Delete the policy itself
aws iam delete-policy --profile root \
  --policy-arn arn:aws:iam::${AWS_ACCOUNT_ID}:policy/NSCLabMCPPolicy 2>/dev/null || true
```

## Next Steps

- Review [MCP Setup Guide](mcp-setup.md) for MCP server installation
- See [LLM Usage Examples](llm-examples.md) for using the MCP server with AWS
- Check [Troubleshooting](troubleshooting.md) for common issues