"""
Parser for AWS Security Groups Configuration

This module provides classes and functions to parse and query AWS Security Groups
configurations as an example of Network Security Control (NSC) implementations.
AWS Security Groups are stateful, instance-level firewalls that act as NSCs.

Securtity Groups operate at the instance level, complementing Network ACLs which operate
at the subnet level. Both are examples of Network Security Controls (NSCs).

This parser demonstrates NSC parsing using AWS Security Groups as an example.
It can be extended or used as a reference for implementing parsers for other NSC types:
- Azure Network Security Groups (NSGs)
- Google Cloud Platform (GCP) Firewall Rules
- Oracle Cloud Infrastructure (OCI) Security Lists
- Traditional on-premises firewalls (Palo Alto, Check Point, Fortinet, etc.)

Classes:
    SecurityGroupRule: Represents a single NSC rule (AWS Security Group rule - ingress or egress)
    SecurityGroup: Represents an NSC (AWS Security Group) with its rules and metadata
    AWSSecurityGroupsParser: Main parser class for loading and querying NSC configurations

Key Features:
    - Direct AWS API integration via boto3
    - Support for CIDR blocks and security group references
    - Tag-based filtering for environment/network identification
    - Port and protocol matching
    - Read-only operations (no configuration modification)
"""

import json
from typing import Dict, List, Any, Optional
from pathlib import Path
from netaddr import IPNetwork, IPAddress

# Conditional import for AWS SDK
# Gracefully handles case where boto3 is not installed
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False


class SecurityGroupRule:
    """
    Represents a single security group rule (ingress or egress).
    
    A rule defines what traffic is allowed to/from a security group. Rules can specify:
    - CIDR blocks (IP address ranges)
    - Security group references (other security groups)
    - Port ranges
    - IP protocols
    
    Attributes:
        security_group_id: ID of the security group this rule belongs to
        security_group_name: Name of the security group
        ip_protocol: IP protocol ('tcp', 'udp', 'icmp', '-1' for all)
        from_port: Starting port number (None for ICMP or all protocols)
        to_port: Ending port number (None for ICMP or all protocols)
        cidr_ipv4: IPv4 CIDR block if rule uses IP ranges (e.g., '10.0.0.0/8')
        cidr_ipv6: IPv6 CIDR block if rule uses IPv6 ranges
        group_id: Referenced security group ID if rule references another security group
        user_id_group_pair: Full user/group pair data from AWS API
        description: Rule description from AWS
        is_egress: Boolean indicating if this is an egress (outbound) rule
    """
    
    def __init__(self, rule_data: Dict[str, Any], security_group_id: str, security_group_name: str, is_egress: bool = False):
        """
        Initialize a security group rule from AWS API data.
        
        Args:
            rule_data: Dictionary from AWS API containing rule information
            security_group_id: ID of the security group this rule belongs to
            security_group_name: Name of the security group
            is_egress: True if this is an egress rule, False for ingress
        """
        self.security_group_id = security_group_id
        self.security_group_name = security_group_name
        self.ip_protocol = rule_data.get('IpProtocol', '-1')
        self.from_port = rule_data.get('FromPort')
        self.to_port = rule_data.get('ToPort')
        self.is_egress = is_egress
        
        # Handle IpRanges (CIDR blocks) - AWS API format
        # IpRanges is a list, we take the first CIDR block if present
        ip_ranges = rule_data.get('IpRanges', [])
        self.cidr_ipv4 = ip_ranges[0].get('CidrIp') if ip_ranges and len(ip_ranges) > 0 else None
        
        # Handle IPv6 ranges
        ipv6_ranges = rule_data.get('Ipv6Ranges', [])
        self.cidr_ipv6 = ipv6_ranges[0].get('CidrIpv6') if ipv6_ranges and len(ipv6_ranges) > 0 else None
        
        # Handle UserIdGroupPairs (security group references)
        # These allow one security group to reference another
        user_id_group_pairs = rule_data.get('UserIdGroupPairs', [])
        self.group_id = user_id_group_pairs[0].get('GroupId') if user_id_group_pairs else None
        self.user_id_group_pair = user_id_group_pairs[0] if user_id_group_pairs else None
        
        # Extract description from IpRanges or UserIdGroupPairs
        # AWS stores descriptions in the range/group pair object
        if ip_ranges and ip_ranges[0].get('Description'):
            self.description = ip_ranges[0].get('Description', '')
        elif user_id_group_pairs and user_id_group_pairs[0].get('Description'):
            self.description = user_id_group_pairs[0].get('Description', '')
        else:
            self.description = ''
        
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert rule to dictionary for JSON serialization.
        
        Returns:
            Dictionary containing all rule attributes
            
        Used for:
            - Returning rule data to LLM via MCP tools
            - JSON serialization for API responses
        """
        return {
            'security_group_id': self.security_group_id,
            'security_group_name': self.security_group_name,
            'ip_protocol': self.ip_protocol,
            'from_port': self.from_port,
            'to_port': self.to_port,
            'cidr_ipv4': self.cidr_ipv4,
            'cidr_ipv6': self.cidr_ipv6,
            'group_id': self.group_id,
            'user_id_group_pair': self.user_id_group_pair,
            'description': self.description,
            'is_egress': self.is_egress,
        }
    
    def matches_source(self, source: str) -> bool:
        """
        Check if this rule matches a source CIDR block or security group ID.
        
        For CIDR blocks, checks if the source network overlaps with the rule's CIDR.
        For security group IDs, checks for exact match or reference.
        
        Args:
            source: CIDR block (e.g., '0.0.0.0/0', '10.0.0.0/8') or security group ID
            
        Returns:
            True if rule matches the source, False otherwise
            
        Example:
            Rule with CIDR '10.0.0.0/8' matches source '10.1.0.0/16' (subnet of larger network)
            Rule with group_id 'sg-app-001' matches source 'sg-app-001'
        """
        # Check CIDR block matching
        if self.cidr_ipv4:
            try:
                # Use netaddr for proper CIDR network comparison
                # Checks if source is contained in rule's network or vice versa
                source_net = IPNetwork(source)
                rule_net = IPNetwork(self.cidr_ipv4)
                return source_net in rule_net or rule_net in source_net
            except Exception:
                # Fallback to string comparison if IP parsing fails
                return self.cidr_ipv4 == source
        
        # Check security group reference matching
        if self.group_id and source:
            # Match if source is the referenced group or the rule's own group
            return self.group_id == source or self.security_group_id == source
        
        return False
    
    def matches_port(self, port: Optional[int]) -> bool:
        """
        Check if this rule matches a specific port number.
        
        Args:
            port: Port number to check (None means match any port)
            
        Returns:
            True if rule matches the port, False otherwise
            
        Logic:
            - If port is None, always matches (no port filter)
            - If protocol is '-1' or 'all', matches any port
            - Otherwise checks if port falls within from_port to to_port range
            
        Example:
            Rule: from_port=3306, to_port=3306, port=3306 -> True
            Rule: from_port=1024, to_port=65535, port=8080 -> True
            Rule: protocol='-1', port=22 -> True (all protocols match any port)
        """
        # No port filter specified - match all
        if port is None:
            return True
        
        # Protocol allows all traffic - match any port
        if self.ip_protocol == '-1' or self.ip_protocol == 'all':
            return True
        
        # Port range not specified - no match
        if self.from_port is None or self.to_port is None:
            return False
        
        # Check if port falls within the range
        return self.from_port <= port <= self.to_port


class SecurityGroup:
    """
    Represents an AWS Security Group.
    
    A security group acts as a virtual firewall for EC2 instances. It contains
    ingress (inbound) and egress (outbound) rules that control traffic.
    
    Attributes:
        group_id: AWS security group ID (e.g., 'sg-prod-db-001')
        group_name: Security group name
        description: Security group description
        vpc_id: VPC ID this security group belongs to
        tags: Dictionary of tags (key-value pairs) for filtering/identification
        ip_permissions: List of ingress (inbound) rules
        ip_permissions_egress: List of egress (outbound) rules
    """
    
    def __init__(self, sg_data: Dict[str, Any]):
        """
        Initialize security group from AWS API data.
        
        Args:
            sg_data: Dictionary from AWS describe_security_groups API response
        """
        self.group_id = sg_data.get('GroupId', '')
        self.group_name = sg_data.get('GroupName', '')
        self.description = sg_data.get('Description', '')
        self.vpc_id = sg_data.get('VpcId', '')
        
        # Convert AWS tag format [{'Key': 'k', 'Value': 'v'}] to dict {'k': 'v'}
        self.tags = {tag['Key']: tag['Value'] for tag in sg_data.get('Tags', [])}
        
        # Parse ingress rules (IpPermissions)
        self.ip_permissions = [
            SecurityGroupRule(rule, self.group_id, self.group_name, is_egress=False) 
            for rule in sg_data.get('IpPermissions', [])
        ]
        
        # Parse egress rules (IpPermissionsEgress)
        self.ip_permissions_egress = [
            SecurityGroupRule(rule, self.group_id, self.group_name, is_egress=True) 
            for rule in sg_data.get('IpPermissionsEgress', [])
        ]
    
    def to_dict(self) -> Dict[str, Any]:
        """
        Convert security group to dictionary for summary/serialization.
        
        Returns:
            Dictionary with security group metadata (not full rules)
            
        Used for:
            - Configuration summaries
            - High-level overviews
        """
        return {
            'group_id': self.group_id,
            'group_name': self.group_name,
            'description': self.description,
            'vpc_id': self.vpc_id,
            'tags': self.tags,
            'rule_count': len(self.ip_permissions) + len(self.ip_permissions_egress),
        }
    
    def get_all_rules(self) -> List[SecurityGroupRule]:
        """
        Get all rules (ingress and egress) from this security group.
        
        Returns:
            List of all SecurityGroupRule objects (ingress + egress)
            
        Used for:
            - Comprehensive rule analysis
            - Querying across all rule types
        """
        return self.ip_permissions + self.ip_permissions_egress


class AWSSecurityGroupsParser:
    """
    Main parser for AWS Security Groups configurations.
    
    Supports loading security groups directly from AWS API or from exported JSON files.
    Provides methods for querying and summarizing loaded configurations.
    
    The parser maintains state - once security groups are loaded, they can be queried
    multiple times without reloading.
    
    Usage:
        parser = AWSSecurityGroupsParser(aws_region='us-east-1')
        parser.load_from_aws(vpc_id='vpc-production-001')
        summary = parser.get_summary()
        rules = parser.query_rules(source='0.0.0.0/0')
    """
    
    def __init__(self, aws_region: Optional[str] = None, aws_profile: Optional[str] = None):
        """
        Initialize parser with AWS configuration.
        
        Args:
            aws_region: AWS region to use for API calls. If not provided, auto-detects from:
                - AWS_DEFAULT_REGION environment variable
                - AWS profile config (~/.aws/config)
                - Defaults to 'us-east-1' if none found
            aws_profile: AWS profile name to use for credentials (defaults to default profile)
            
        Security Note:
            **NEVER hardcode AWS credentials in this code.**
            Credentials are resolved securely in this order:
            1. Function parameters (aws_profile - profile name only, not credentials)
            2. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
            3. AWS credentials file (~/.aws/credentials) - managed via 'aws configure'
            4. IAM role (if running on AWS infrastructure)
            
            This ensures credentials are never stored in source code or committed to version control.
            See docs/SECURITY.md for security best practices.
        """
        # Dictionary of security groups keyed by group ID
        self.security_groups: Dict[str, SecurityGroup] = {}
        
        # Path to config file if loaded from file (None if loaded from AWS)
        self.config_path: Optional[Path] = None
        
        # Source tracking for AWS loads (e.g., "AWS VPC: vpc-production-001")
        self.aws_source: Optional[str] = None
        
        # AWS configuration - auto-detect region if not provided
        self.aws_profile = aws_profile
        if aws_region:
            self.aws_region = aws_region
        else:
            # Auto-detect region from environment or profile config
            self.aws_region = self._get_aws_region()
        
        # Lazy-loaded EC2 client (created on first AWS API call)
        self._ec2_client = None
    
    def _get_aws_region(self) -> str:
        """
        Auto-detect AWS region from environment variables or profile config.
        
        Returns:
            AWS region string (defaults to 'us-east-1' if not found)
        """
        import os
        
        # Check environment variable first
        region = os.environ.get('AWS_DEFAULT_REGION') or os.environ.get('AWS_REGION')
        if region:
            return region
        
        # Try to get region from AWS profile config
        if AWS_AVAILABLE:
            try:
                import boto3
                # Create a session with the profile (if specified) to get region
                session = boto3.Session(profile_name=self.aws_profile) if self.aws_profile else boto3.Session()
                region = session.region_name
                if region:
                    return region
            except Exception:
                # If we can't get region from session, fall through to default
                pass
        
        # Default fallback
        return 'us-east-1'
    
    def parse_file(self, file_path: str) -> Dict[str, SecurityGroup]:
        """
        Parse AWS Security Groups from exported JSON file.
        
        Supports multiple JSON formats:
        - Array of security groups: [{"GroupId": "...", ...}, ...]
        - Object with SecurityGroups key: {"SecurityGroups": [...]}
        - Single security group object: {"GroupId": "...", ...}
        
        Args:
            file_path: Path to JSON file containing security groups
            
        Returns:
            Dictionary of SecurityGroup objects keyed by group ID
            
        Raises:
            FileNotFoundError: If file doesn't exist
            ValueError: If JSON structure is invalid
            
        Note:
            This method is kept for backward compatibility but AWS API loading
            is preferred for real-time data.
        """
        path = Path(file_path)
        if not path.exists():
            raise FileNotFoundError(f"Configuration file not found: {file_path}")
        
        self.config_path = path
        
        # Load JSON from file
        with open(path, 'r') as f:
            data = json.load(f)
        
        # Handle different JSON structures from AWS exports
        if isinstance(data, list):
            # Direct array of security groups
            sg_list = data
        elif isinstance(data, dict):
            # Could be {'SecurityGroups': [...]} or single security group dict
            sg_list = data.get('SecurityGroups', [data] if 'GroupId' in data else [])
        else:
            raise ValueError(f"Invalid JSON structure in {file_path}")
        
        # Parse each security group
        self.security_groups = {}
        for sg_data in sg_list:
            sg = SecurityGroup(sg_data)
            self.security_groups[sg.group_id] = sg
        
        return self.security_groups
    
    def _get_ec2_client(self):
        """
        Get or create EC2 client with proper AWS credentials.
        
        Uses lazy initialization - client is created on first use and reused
        for subsequent API calls.
        
        Returns:
            boto3 EC2 client configured with specified region and profile
            
        Raises:
            ImportError: If boto3 is not installed
            
        Security Note:
            **NEVER hardcode AWS credentials in this code.**
            Credentials are resolved by boto3.Session in this order:
            1. Profile name (if specified)
            2. Environment variables
            3. AWS credentials file (~/.aws/credentials)
            4. IAM role (if on AWS infrastructure)
            
            This ensures credentials are never stored in source code or committed to version control.
        """
        if not AWS_AVAILABLE:
            raise ImportError(
                "boto3 is required for AWS API access. Install with: pip install boto3"
            )
        
        # Lazy initialization - create client only when needed
        if self._ec2_client is None:
            # Create boto3 session with specified profile and region
            # Session handles credential resolution automatically - NEVER pass credentials directly
            # SECURITY: boto3.Session() resolves credentials securely from environment/config files
            # Do NOT modify this to accept credentials as parameters or hardcode them
            session = boto3.Session(
                profile_name=self.aws_profile,
                region_name=self.aws_region
            )
            # Create EC2 client for API calls
            self._ec2_client = session.client('ec2')
        
        return self._ec2_client
    
    def load_from_aws(self, vpc_id: Optional[str] = None, security_group_ids: Optional[List[str]] = None) -> Dict[str, SecurityGroup]:
        """
        Load security groups directly from AWS via API.
        
        This is the primary method for loading configurations. It makes live API calls
        to AWS to fetch current security group configurations.
        
        Args:
            vpc_id: Optional VPC ID to filter security groups (loads all SGs in VPC)
            security_group_ids: Optional list of specific security group IDs to load
            
        Returns:
            Dictionary of SecurityGroup objects keyed by group ID
            
        Raises:
            ImportError: If boto3 is not installed
            ValueError: If AWS credentials not found or API errors occur
            
        Note:
            - If both vpc_id and security_group_ids are None, loads ALL security groups
            - This can be slow for accounts with many security groups
            - Prefer specifying vpc_id or security_group_ids for better performance
            
        Example:
            # Load all security groups in a VPC
            parser.load_from_aws(vpc_id='vpc-production-001')
            
            # Load specific security groups
            parser.load_from_aws(security_group_ids=['sg-prod-db-001', 'sg-prod-app-001'])
        """
        if not AWS_AVAILABLE:
            raise ImportError(
                "boto3 is required for AWS API access. Install with: pip install boto3"
            )
        
        try:
            # Get EC2 client (creates if needed)
            ec2 = self._get_ec2_client()
            
            # Build filters for VPC-based queries
            filters = []
            if vpc_id:
                filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
            
            # Call AWS API to describe security groups
            # Two modes: by specific IDs or by filters (VPC)
            if security_group_ids:
                # Load specific security groups by ID
                response = ec2.describe_security_groups(GroupIds=security_group_ids)
            else:
                # Load by filters (VPC or all if no filters)
                response = ec2.describe_security_groups(Filters=filters)
            
            # Extract security groups from API response
            sg_list = response.get('SecurityGroups', [])
            
            # Parse each security group into SecurityGroup objects
            self.security_groups = {}
            for sg_data in sg_list:
                sg = SecurityGroup(sg_data)
                self.security_groups[sg.group_id] = sg
            
            # Track source for summary/reporting
            if vpc_id:
                self.aws_source = f"AWS VPC: {vpc_id}"
            elif security_group_ids:
                self.aws_source = f"AWS Security Groups: {', '.join(security_group_ids)}"
            else:
                self.aws_source = "AWS Account (all security groups)"
            
            return self.security_groups
            
        except NoCredentialsError:
            # Provide helpful error message for missing credentials
            raise ValueError(
                "AWS credentials not found. Configure credentials using:\n"
                "  - AWS CLI: aws configure\n"
                "  - Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY\n"
                "  - IAM role (if running on EC2)\n"
                "  - AWS profile: set AWS_PROFILE environment variable"
            )
        except ClientError as e:
            # Extract error details from AWS API response
            error_code = e.response.get('Error', {}).get('Code', 'Unknown')
            error_message = e.response.get('Error', {}).get('Message', str(e))
            raise ValueError(f"AWS API error ({error_code}): {error_message}")
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get high-level summary of the loaded configuration.
        
        Provides overview statistics useful for understanding the scope of
        the configuration before detailed analysis.
        
        Returns:
            Dictionary containing:
                - total_security_groups: Count of security groups
                - total_rules: Total count of all rules (ingress + egress)
                - vpcs: List of unique VPC IDs
                - security_groups: List of security group summaries
                - config_path: File path if loaded from file (None if from AWS)
                - aws_source: Source description if loaded from AWS
                
        Example:
            {
                "total_security_groups": 3,
                "total_rules": 12,
                "vpcs": ["vpc-production-001"],
                "security_groups": [...],
                "aws_source": "AWS VPC: vpc-production-001"
            }
        """
        # Calculate total rules across all security groups
        total_rules = sum(len(sg.get_all_rules()) for sg in self.security_groups.values())
        
        # Extract unique VPC IDs
        vpcs = set(sg.vpc_id for sg in self.security_groups.values() if sg.vpc_id)
        
        return {
            'total_security_groups': len(self.security_groups),
            'total_rules': total_rules,
            'vpcs': list(vpcs),
            'security_groups': [sg.to_dict() for sg in self.security_groups.values()],
            'config_path': str(self.config_path) if self.config_path else None,
            'aws_source': self.aws_source,
        }
    
    def get_all_rules(self) -> List[Dict[str, Any]]:
        """
        Get all rules from all security groups as dictionaries.
        
        Returns:
            List of rule dictionaries (suitable for JSON serialization)
            
        Used for:
            - Comprehensive rule listing
            - Exporting all rules for analysis
        """
        all_rules = []
        for sg in self.security_groups.values():
            for rule in sg.get_all_rules():
                all_rules.append(rule.to_dict())
        return all_rules
    
    def query_rules(self, source: Optional[str] = None, destination: Optional[str] = None,
                   port: Optional[int] = None, protocol: Optional[str] = None,
                   tag_key: Optional[str] = None, tag_value: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Query rules based on multiple criteria.
        
        Filters rules using AND logic - all specified criteria must match.
        Useful for finding specific security issues like overly permissive rules
        or cross-network connections.
        
        Args:
            source: CIDR block or security group ID to filter by source
            destination: CIDR block or security group ID to filter by destination
            port: Port number to filter by (e.g., 22 for SSH, 443 for HTTPS)
            protocol: IP protocol to filter by ('tcp', 'udp', 'icmp', '-1' for all)
            tag_key: Security group tag key to filter by (e.g., 'Environment')
            tag_value: Tag value to match (requires tag_key, e.g., 'Production')
            
        Returns:
            List of rule dictionaries matching all specified criteria
            
        Note:
            - Filtering is done at security group level for tags, rule level for others
            - If tag_key is specified, only rules from matching security groups are considered
            - All other filters are applied to individual rules
            
        Example:
            # Find overly permissive rules
            query_rules(source='0.0.0.0/0')
            
            # Find SSH rules in production
            query_rules(port=22, protocol='tcp', tag_key='Environment', tag_value='Production')
            
            # Find rules allowing access to specific security group
            query_rules(source='sg-prod-db-001')
        """
        results = []
        
        # Iterate through all security groups
        for sg in self.security_groups.values():
            # Filter by tags if specified (security group level filter)
            if tag_key:
                # Skip security groups that don't have the tag
                if tag_key not in sg.tags:
                    continue
                # If tag_value specified, must match exactly
                if tag_value and sg.tags[tag_key] != tag_value:
                    continue
            
            # Check each rule in this security group
            for rule in sg.get_all_rules():
                # Filter by source (CIDR or security group ID)
                if source and not rule.matches_source(source):
                    continue
                
                # Filter by port number
                if port is not None and not rule.matches_port(port):
                    continue
                
                # Filter by protocol
                if protocol and rule.ip_protocol != protocol:
                    continue
                
                # Rule matches all criteria - add to results
                results.append(rule.to_dict())
        
        return results
