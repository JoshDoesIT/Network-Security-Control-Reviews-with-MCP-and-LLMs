# Troubleshooting Guide

Common issues and solutions for the Network Security Control Reviews with MCP lab.

## AWS Credentials and Terraform Issues

### Terraform can't find AWS credentials

**Problem**: Terraform fails with credential errors

**Solution**:
```bash
# Verify credentials
aws sts get-caller-identity

# If that fails, reconfigure
aws configure
```

### Region not available

**Problem**: AWS region error when deploying Terraform

**Solution**:
```bash
# List available regions
aws ec2 describe-regions --query 'Regions[].RegionName' --output table

# Change region in terraform.tfvars
echo 'aws_region = "us-west-2"' > terraform/terraform.tfvars
cd terraform && terraform apply
```

### Resources already exist

**Problem**: Terraform reports resources already exist

**Solution**:
```bash
# Check what exists
cd terraform
terraform plan

# If resources exist, import them or delete manually first
# See Terraform import documentation for your specific resources
```

### AWS Credentials Not Configured

**Problem**: `NoCredentialsError` or credential-related errors

**Solutions**:

1. **Verify credentials are configured**:
   ```bash
   aws sts get-caller-identity
   ```

2. **If that fails, configure credentials**:
   ```bash
   aws configure
   ```
   See [AWS Setup Guide](aws-setup.md#step-2-configure-aws-credentials) for detailed instructions.

3. **Check file permissions**:
   ```bash
   chmod 600 ~/.aws/credentials
   chmod 600 ~/.aws/config
   ```

### Access Denied Errors

**Problem**: `AccessDenied` when calling AWS APIs

**Solutions**:

1. **For MCP server**: Verify the MCP server IAM user (`nsc-lab-mcp-user`) has appropriate permissions according to [AWS Setup Guide](aws-setup.md#step-2-configure-aws-credentials).

2. **For Terraform**: Verify the Terraform IAM user (`nsc-lab-terraform-user`) has appropriate permissions according to [AWS Setup Guide](aws-setup.md#step-2-configure-aws-credentials).

### Invalid Region

**Problem**: `InvalidRegion` error

**Solution**: Set `AWS_DEFAULT_REGION` or specify `aws_region` in tool calls:
```bash
export AWS_DEFAULT_REGION=us-east-1
```

## MCP Server Connection Issues

### Server Not Starting

**Problem**: MCP client cannot connect to the server

**Solutions**:

1. **Verify the path is correct**:
   ```bash
   # Test the server directly
   cd /path/to/Network-Security-Control-Reviews-with-MCP
   python mcp-server/server.py
   ```
   If this fails, check for Python errors.

2. **Use absolute paths** in MCP configuration:
   ```json
   {
     "args": [
       "/absolute/path/to/Network-Security-Control-Reviews-with-MCP/mcp-server/server.py"
     ]
   }
   ```

3. **Check Python executable**:
   ```json
   {
     "command": "/usr/bin/python3",  // Use full path to python
   }
   ```

### MCP Server Not Connecting

**Problem**: MCP client cannot establish connection

**Solutions**:
- Verify the path to `server.py` is correct
- Check that Python is in your PATH
- Ensure the virtual environment is activated if using one
- Check MCP client logs for connection issues

## Installation Issues

### Python Version

**Problem**: `python` command not found or wrong version

**Solution**:
```bash
# Check Python version
python3 --version  # Should be 3.11 or higher

# Use python3 explicitly
python3 -m venv venv
python3 -m pip install -r requirements.txt
```

### Import Errors

**Problem**: `ModuleNotFoundError` or `ImportError`

**Solutions**:

1. **"No module named 'mcp'"**:
   - Ensure you've activated your virtual environment
   - Run `pip install -r requirements.txt` again

2. **Ensure you're in the project root**:
   ```bash
   cd /path/to/Network-Security-Control-Reviews-with-MCP
   python mcp-server/server.py
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

## Configuration Issues

### Invalid VPC ID or Security Group ID

**Problem**: `get_config` tool returns "VPC not found" or "Security group not found"

**Solutions**:

1. **Verify VPC ID exists**:
   ```bash
   aws ec2 describe-vpcs --vpc-ids vpc-production-001
   ```

2. **List security groups in VPC**:
   ```bash
   aws ec2 describe-security-groups --filters "Name=vpc-id,Values=vpc-production-001"
   ```

3. **Check region**: Ensure you're using the correct AWS region where the VPC exists

4. **Verify permissions**: Ensure your IAM user/role has the correct permissions according to [AWS Setup Guide](aws-setup.md#step-2-configure-aws-credentials).

## LLM Integration Issues

### LLM Not Recognizing Tools

**Problem**: LLM doesn't use the MCP tools

**Solutions**:

1. **Restart your MCP client** after configuration changes

2. **Verify tools are listed**: Ask "What tools are available?" or look at tool listings in the LLM UI

3. **Be explicit**: Use tool names in your queries:
   ```
   Use the get_config tool to load security groups from VPC vpc-production-001
   ```

4. **Check MCP client logs** for connection issues

### LLM Misinterpreting Results

**Problem**: LLM provides incorrect analysis

**Solutions**:

1. **Provide context**: Explain what you're looking for
   ```
   Load security groups from the production VPC (vpc-production-001) and 
   check if it's properly isolated from the development environment.
   ```

2. **Break down complex queries**: Ask multiple simpler questions

3. **Ensure VPC IDs are correct**: Use actual VPC IDs from your AWS account

## Getting Additional Help

If you run into trouble and aren't able to find a solution here, feel free to reach out and I will try my best to help! 