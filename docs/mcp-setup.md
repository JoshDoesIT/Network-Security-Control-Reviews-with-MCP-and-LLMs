# Setup Guide

This guide will help you set up the AWS Network Security Control (NSC) Reviews MCP server to run **locally** on your machine and connect it to your LLM. This lab demonstrates NSC reviews using AWS Security Groups and Network ACLs as examples. The server securely accesses AWS APIs using your configured credentials. The architecture is extensible and can be extended to support other NSC types (e.g., Azure NSGs, GCP Firewall Rules, OCI Security Lists, on-premises firewalls).

## Prerequisites

- Python 3.11 or higher
- pip (Python package manager)
- AWS Account (free tier eligible)
- Access to an LLM that supports MCP (Model Context Protocol)
  - Claude Desktop (with MCP support)
  - Cursor IDE (with MCP support)
  - Other MCP-compatible clients

## Installation

### 1. Clone or Download the Repository

```bash
git clone <repository-url>
cd Network-Security-Control-Reviews-with-MCP
```

### 2. Create a Virtual Environment (Recommended)

```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

This installs:
- MCP SDK for server functionality
- boto3 for AWS API access
- netaddr for IP address handling
- Other supporting libraries

### 4. Configure AWS Credentials and Permissions for MCP Server

If you haven't already done this, return to [AWS Setup Guide - Step 2](aws-setup.md#step-2-configure-aws-credentials) to create the MCP server user and assign permissions.

**Note**: The MCP server IAM user (`nsc-lab-mcp-user`) created in the AWS Setup Guide has read-only permissions for querying NSCs (`ec2:DescribeSecurityGroups`, `ec2:DescribeVpcs`, `ec2:DescribeNetworkAcls`, `ec2:DescribeNetworkAclEntries`, `ec2:DescribeSubnets`). This follows least-privilege principles - the MCP server only has the minimum permissions needed to query NSC configurations, separate from Terraform's write permissions.

## MCP Server Configuration

The MCP server runs **locally** on your machine. Configure your LLM client to connect to the local server.

### For Claude Desktop

1. Locate your Claude Desktop configuration file: `~/Library/Application Support/Claude/claude_desktop_config.json`
2. Add the MCP server configuration:

```json
{
  "mcpServers": {
    "nsc-review": {
      "command": "/path/to/Network-Security-Control-Reviews-with-MCP/venv/bin/python3",
      "args": [
        "/path/to/Network-Security-Control-Reviews-with-MCP/mcp-server/server.py"
      ],
      "env": {
        "AWS_PROFILE": "mcp"
      }
    }
  }
}
```

**Notes**:
- **Use the full path to your virtual environment's Python** (`venv/bin/python3`) - this ensures all dependencies are available
- Replace `/path/to/Network-Security-Control-Reviews-with-MCP` with your actual project path
- The `env` section sets the AWS profile - you can also set `AWS_PROFILE` as an environment variable instead

3. Restart Claude Desktop

### For Cursor IDE

1. Open Cursor settings
2. Navigate to MCP settings
3. Add a new MCP server:

```json
{
  "name": "nsc-review",
  "command": "/path/to/Network-Security-Control-Reviews-with-MCP/venv/bin/python3",
  "args": ["/path/to/Network-Security-Control-Reviews-with-MCP/mcp-server/server.py"],
  "env": {
    "AWS_PROFILE": "mcp"
  }
}
```

**Note**: 
- **Use the full path to your virtual environment's Python** (`venv/bin/python3`) - this ensures all dependencies are available
- Replace `/path/to/Network-Security-Control-Reviews-with-MCP` with your actual project path
- The `env` section sets the AWS profile - you can also set `AWS_PROFILE` as an environment variable instead

### For Other MCP Clients

Refer to your client's documentation for adding MCP servers. The server uses stdio (standard input/output) for communication.

## Testing the Installation

### Test AWS Credentials

Before testing the MCP server, it is a good idea to verify AWS credentials are configured:

**Important:** Make sure your virtual environment is activated first (see Step 2 above).

```bash
# Activate virtual environment (if not already activated)
source venv/bin/activate

# Test AWS CLI access (using mcp profile)
aws ec2 describe-security-groups --profile mcp --max-items 1

# Test Python/boto3 access (explicitly using mcp profile and region)
python3 -c "import boto3; session = boto3.Session(profile_name='mcp', region_name='us-east-1'); client = session.client('ec2'); client.describe_security_groups(MaxResults=5); print('AWS credentials OK')"
```

**Common Credential Issues:**

- **"NoCredentialsError"**: Return to [AWS Setup Guide - Step 2](aws-setup.md#step-2-configure-aws-credentials) and run `aws configure --profile mcp`
- **"NoRegionError"**: The test command above specifies `us-east-1` as the region. If your profile uses a different region, update the `region_name` parameter in the test command, or ensure your `~/.aws/config` file has `region = us-east-1` (or your preferred region) under the `[profile mcp]` section.
- **"UnauthorizedOperation"** or **"AccessDenied"**: The test command uses `describe_security_groups` which matches the MCP user's permissions. If you see this error, verify the IAM user `nsc-lab-mcp-user` created in [AWS Setup Guide](aws-setup.md) has the `NSCLabMCPPolicy` attached with `ec2:DescribeSecurityGroups` permission.
- **"MissingDependencyException: botocore[crt]"**: This error occurs when boto3 tries to use AWS SSO/login credentials. Make sure you're using the `mcp` profile with access keys (not SSO). The test command above explicitly uses the `mcp` profile. If you still see this error, verify your `~/.aws/credentials` file has the `[mcp]` profile configured with access keys (not SSO).

### Manual MCP Server Test

You can test the MCP server manually:

```bash
# Make sure virtual environment is activated
source venv/bin/activate

cd mcp-server
python3 server.py
```

The server should start and wait for input via stdio. Press Ctrl+C to exit.

**Note**: The server will use AWS credentials from your environment (AWS_PROFILE, environment variables, or ~/.aws/credentials).

### Testing with AWS

1. Ensure your AWS test environment is set up (see [AWS Setup Guide](aws-setup.md))

2. In your LLM client, try loading a configuration from AWS:
   ```
   Load security groups from the production VPC
   ```

   The LLM will use the MCP server to connect to AWS, determine the production VPC ID, and load the security groups directly.

## Running Tests

The MCP server includes unit tests and optional integration tests.

### Unit Tests (Mocked)

Run unit tests that use mocked AWS API responses (no credentials required):

```bash
# From project root
# Make sure virtual environment is activated
source venv/bin/activate

python3 mcp-server/tests/test_parser.py
```

These tests verify:
- Parser functionality
- Rule querying logic
- Summary generation
- AWS API integration (mocked)

### Integration Tests (Real AWS)

Run integration tests that make real AWS API calls:

```bash
# From project root
# Make sure virtual environment is activated
source venv/bin/activate

python3 mcp-server/tests/test_integration.py
```

**Prerequisites for integration tests:**
- AWS credentials configured (see [AWS Setup Guide](aws-setup.md))
- AWS test environment deployed via Terraform
- Terraform outputs available (VPC IDs)

**What the integration tests verify:**
- Real AWS API connectivity
- Loading security groups from actual VPCs
- Rule querying with real data
- Segmentation analysis between environments

**Note:** Integration tests are automatically skipped if:
- AWS credentials are not configured
- Terraform infrastructure is not deployed
- VPC IDs are not available

The tests read VPC IDs from Terraform outputs automatically, or you can set them manually:
```bash
# Make sure virtual environment is activated
source venv/bin/activate

export TEST_PRODUCTION_VPC_ID=$(terraform output -raw production_vpc_id)
export TEST_DEVELOPMENT_VPC_ID=$(terraform output -raw development_vpc_id)
python3 mcp-server/tests/test_integration.py
```

## Verifying the Setup

Once connected, you should be able to:

1. **List available tools**: Ask your LLM "What tools are available for Network Security Control analysis?"
2. **Discover VPCs**: Use the `list_vpcs` tool to find VPC IDs before loading NSC configurations
3. **Load a configuration**: Use the `get_config` tool to load NSC configurations (Security Groups and Network ACLs as examples)
4. **Query rules**: Use the `query_rules` tool to query specific NSC rules

## Next Steps

- Review the [LLM Usage Examples](llm-examples.md) to see how to use the MCP server for NSC reviews
- Load sample NSC configurations and start analyzing NSC rules

## Local Execution Architecture

```
┌─────────────────┐
│  LLM Client     │  (Claude Desktop, Cursor, etc.)
│  (Local)        │
└────────┬────────┘
         │ MCP Protocol (stdio)
         │
┌────────▼────────┐
│  MCP Server     │  (Runs locally on your machine)
│  (Local)        │
└────────┬────────┘
         │ AWS API (HTTPS)
         │ Uses secure credentials
         │
┌────────▼────────┐
│  AWS Account    │  (Your AWS account)
│  (Cloud)        │
└─────────────────┘
```

**Key Points**:
- MCP server runs **locally** on your machine
- Credentials stored securely following AWS best practices
- Server makes API calls to AWS over HTTPS