# Network Security Control (NSC) Configuration Parsers

This directory contains parsers for Network Security Control (NSC) configurations. This lab uses AWS Security Groups and Network ACLs as examples of NSCs. The architecture is extensible and can be extended to support other NSC types from various cloud providers and traditional on-premises firewalls.

## AWS Security Groups Parser (Instance-level NSC Example)

**File:** `aws_security_groups.py`

AWS Security Groups are an example of instance-level NSCs. They are stateful firewalls that operate at the instance level.

### Classes

#### `SecurityGroupRule`
Represents a single AWS Security Group NSC rule (ingress or egress).

**Attributes:**
- `security_group_id`: ID of the security group this rule belongs to
- `security_group_name`: Name of the security group
- `ip_protocol`: IP protocol (tcp, udp, icmp, -1 for all)
- `from_port`: Starting port number
- `to_port`: Ending port number
- `cidr_ipv4`: IPv4 CIDR block (if applicable)
- `cidr_ipv6`: IPv6 CIDR block (if applicable)
- `group_id`: Referenced security group ID (if applicable)
- `description`: Rule description
- `is_egress`: Boolean indicating if this is an egress rule

**Methods:**
- `to_dict()`: Convert rule to dictionary
- `matches_source(source: str)`: Check if rule matches a source CIDR or security group
- `matches_port(port: int)`: Check if rule matches a port number

#### `SecurityGroup`
Represents a AWS Security Group NSC.

**Attributes:**
- `group_id`: Security group ID
- `group_name`: Security group name
- `description`: Security group description
- `vpc_id`: VPC ID this security group belongs to
- `tags`: Dictionary of tags (key-value pairs)
- `ip_permissions`: List of ingress rules
- `ip_permissions_egress`: List of egress rules

**Methods:**
- `to_dict()`: Convert security group to dictionary
- `get_all_rules()`: Get all rules (ingress + egress)

#### `AWSSecurityGroupsParser`
Main parser class for AWS Security Group NSCs (AWS Security Groups as example). Loads NSC configurations directly from AWS EC2 API.

**Methods:**
- `load_from_aws(vpc_id=None, security_group_ids=None)`: Load security groups directly from AWS
  - `vpc_id`: Load all security groups from a specific VPC
  - `security_group_ids`: Load specific security groups by their IDs
- `get_summary()`: Get high-level summary of loaded configuration
- `get_all_rules()`: Get all rules from all security groups
- `query_rules(...)`: Query rules by various criteria:
  - `source`: Filter by source CIDR or security group ID
  - `destination`: Filter by destination CIDR or security group ID
  - `port`: Filter by port number
  - `protocol`: Filter by IP protocol
  - `tag_key`: Filter by tag key
  - `tag_value`: Filter by tag value (requires tag_key)

### Usage Example

```python
from mcp_server.src.parsers import AWSSecurityGroupsParser

# Create parser instance with AWS region
parser = AWSSecurityGroupsParser(aws_region="us-east-1")

# Load security groups from AWS VPC
security_groups = parser.load_from_aws(vpc_id="vpc-production-001")

# Or load specific security groups by ID
security_groups = parser.load_from_aws(security_group_ids=["sg-prod-db-001", "sg-prod-app-001"])

# Get summary
summary = parser.get_summary()
print(f"Total security groups: {summary['total_security_groups']}")
print(f"Total rules: {summary['total_rules']}")
print(f"Source: {summary['aws_source']}")

# Query rules
permissive_rules = parser.query_rules(source="0.0.0.0/0")
production_rules = parser.query_rules(tag_key="Environment", tag_value="Production")
```

### AWS Credentials

The parser uses boto3's credential resolution chain:
1. Environment variables (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`)
2. AWS credentials file (`~/.aws/credentials`)
3. AWS config file (`~/.aws/config`)
4. IAM role (if running on AWS infrastructure)

See [MCP Setup Guide](../../docs/mcp-setup.md) for detailed credential configuration.

## Extending for Other Cloud Providers and On-Premises Firewalls

The parser architecture is designed to be extensible. You can add support for other cloud providers' NSCs or traditional on-premises firewalls by following the same pattern.

### Implementation Steps

To add support for a new format:

1. **Create a new parser file**: `azure_nsgs.py`, `gcp_firewall.py`, `palo_alto.py`, etc.
2. **Implement similar classes**:
   - Rule class (represents a single rule with source, destination, port, protocol)
   - Configuration class (represents the NSC config)
   - Parser class with methods:
     - `load_from_api()` or `load_from_file()` - Load configuration
     - `get_summary()` - Get high-level summary
     - `get_all_rules()` - Get all rules
     - `query_rules()` - Query rules by criteria
3. **Export from `__init__.py`**: Add the new parser to the package exports
4. **Update MCP tools**: Extend `nsc_tools.py` to support the new parser type
5. **Add tests**: Create unit and integration tests for the new parser

### Example: Azure NSGs (NSC Type)

```python
# azure_nsgs.py
class NSGRule:
    """Represents an Azure NSG rule (NSC rule example)"""
    def __init__(self, rule_data):
        self.name = rule_data['name']
        self.priority = rule_data['priority']
        self.source_address_prefix = rule_data.get('sourceAddressPrefix')
        self.destination_address_prefix = rule_data.get('destinationAddressPrefix')
        self.destination_port_range = rule_data.get('destinationPortRange')
        self.protocol = rule_data['protocol']
        self.access = rule_data['access']  # Allow or Deny
        self.direction = rule_data['direction']  # Inbound or Outbound

class AzureNSGParser:
    """Parser for Azure NSGs (NSC type)"""
    def load_from_azure(self, resource_group, nsg_name):
        # Use Azure SDK to fetch NSG rules
        pass
    
    def query_rules(self, source=None, destination=None, port=None):
        # Query NSC rules similar to AWS parser pattern
        pass
```

### Integration with MCP Tools

After creating a new NSC parser, update `mcp-server/src/tools/nsc_tools.py` to support it:

```python
# Add parser selection logic for different NSC types
if provider == "azure":
    from ..parsers.azure_nsgs import AzureNSGParser
    parser = AzureNSGParser()  # Azure NSC type
elif provider == "palo_alto":
    from ..parsers.palo_alto import PaloAltoParser
    parser = PaloAltoParser()  # On-premises NSC type
else:
    # Default to AWS NSC examples
    from ..parsers.aws_security_groups import AWSSecurityGroupsParser
    parser = AWSSecurityGroupsParser()  # AWS NSC example
```

This extensible architecture allows the MCP server to support multiple NSC types while maintaining a consistent interface for LLM interaction. While AWS Security Groups and Network ACLs are used as examples in this lab, the same patterns can be generally used for any NSC type.