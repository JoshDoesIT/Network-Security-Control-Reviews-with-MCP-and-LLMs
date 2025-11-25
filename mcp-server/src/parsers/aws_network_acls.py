"""
Parser for AWS Network ACLs Configuration

This module provides classes and functions to parse and query AWS Network ACLs
configurations as an example of Network Security Control (NSC) implementations.
AWS Network ACLs are stateless, subnet-level firewalls that act as NSCs.

Network ACLs operate at the subnet level, complementing Security Groups which operate
at the instance level. Both are examples of Network Security Controls (NSCs).

This parser demonstrates NSC parsing using AWS Network ACLs as an example.
It can be extended or used as a reference for implementing parsers for other NSC types:
- Azure Network Security Groups (NSGs)
- Google Cloud Platform (GCP) Firewall Rules
- Oracle Cloud Infrastructure (OCI) Security Lists
- Traditional on-premises firewalls (Palo Alto, Check Point, Fortinet, etc.)

Classes:
    NetworkACLRule: Represents a single NSC rule (AWS Network ACL rule - ingress or egress)
    NetworkACL: Represents an NSC (AWS Network ACL) with its rules and metadata
    AWSNetworkACLParser: Main parser class for loading and querying NSC configurations

Key Features:
    - Direct AWS API integration via boto3
    - Support for CIDR blocks
    - Tag-based filtering for environment/network identification
    - Port and protocol matching
    - Read-only operations (no configuration modification)
"""

import json
from typing import Dict, List, Any, Optional
from netaddr import IPNetwork, IPAddress

# Conditional import for AWS SDK
try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False


class NetworkACLRule:
    """
    Represents a single Network ACL rule.
    
    Network ACL rules are stateless and operate at the subnet level.
    They control traffic flow in and out of subnets.
    """
    
    def __init__(self, rule_data: Dict[str, Any], acl_id: str, vpc_id: str, is_egress: bool = False):
        """
        Initialize a Network ACL rule from AWS API response.
        
        Args:
            rule_data: Dictionary from AWS describe_network_acls API response
            acl_id: Network ACL ID this rule belongs to
            vpc_id: VPC ID this rule belongs to
            is_egress: True if this is an egress rule, False for ingress
        """
        self.acl_id = acl_id
        self.vpc_id = vpc_id
        self.rule_number = rule_data.get('RuleNumber', 0)
        self.protocol = rule_data.get('Protocol', '-1')
        self.rule_action = rule_data.get('RuleAction', 'deny')  # 'allow' or 'deny'
        self.cidr_block = rule_data.get('CidrBlock', '')
        self.ipv6_cidr_block = rule_data.get('Ipv6CidrBlock', '')
        self.port_range = rule_data.get('PortRange', {})
        self.from_port = self.port_range.get('From') if self.port_range else None
        self.to_port = self.port_range.get('To') if self.port_range else None
        self.is_egress = is_egress
        self.icmp_type_code = rule_data.get('IcmpTypeCode', {})
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert rule to dictionary representation."""
        return {
            'acl_id': self.acl_id,
            'vpc_id': self.vpc_id,
            'rule_number': self.rule_number,
            'protocol': self.protocol,
            'rule_action': self.rule_action,
            'cidr_block': self.cidr_block,
            'ipv6_cidr_block': self.ipv6_cidr_block,
            'from_port': self.from_port,
            'to_port': self.to_port,
            'is_egress': self.is_egress,
        }
    
    def matches_cidr(self, cidr: str) -> bool:
        """Check if rule matches a CIDR block."""
        if not self.cidr_block:
            return False
        
        try:
            rule_network = IPNetwork(self.cidr_block)
            query_network = IPNetwork(cidr)
            return query_network in rule_network or rule_network in query_network
        except Exception:
            return False
    
    def matches_port(self, port: int) -> bool:
        """Check if rule matches a port number."""
        if self.from_port is None or self.to_port is None:
            return False
        return self.from_port <= port <= self.to_port


class NetworkACL:
    """
    Represents an AWS Network ACL.
    
    A Network ACL is a stateless firewall that operates at the subnet level.
    It contains ingress (inbound) and egress (outbound) rules.
    """
    
    def __init__(self, acl_data: Dict[str, Any]):
        """
        Initialize a Network ACL from AWS API response.
        
        Args:
            acl_data: Dictionary from AWS describe_network_acls API response
        """
        self.acl_id = acl_data['NetworkAclId']
        self.vpc_id = acl_data.get('VpcId', '')
        self.is_default = acl_data.get('IsDefault', False)
        self.associations = acl_data.get('Associations', [])
        self.tags = {tag['Key']: tag['Value'] for tag in acl_data.get('Tags', [])}
        
        # Parse ingress and egress rules
        self.ingress_rules = [
            NetworkACLRule(rule, self.acl_id, self.vpc_id, is_egress=False)
            for rule in acl_data.get('Entries', [])
            if not rule.get('Egress', False)
        ]
        
        self.egress_rules = [
            NetworkACLRule(rule, self.acl_id, self.vpc_id, is_egress=True)
            for rule in acl_data.get('Entries', [])
            if rule.get('Egress', False)
        ]
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert Network ACL to dictionary representation."""
        return {
            'acl_id': self.acl_id,
            'vpc_id': self.vpc_id,
            'is_default': self.is_default,
            'tags': self.tags,
            'associations': self.associations,
            'ingress_rules': [rule.to_dict() for rule in self.ingress_rules],
            'egress_rules': [rule.to_dict() for rule in self.egress_rules],
        }
    
    def get_all_rules(self) -> List[NetworkACLRule]:
        """Get all rules (ingress + egress)."""
        return self.ingress_rules + self.egress_rules


class AWSNetworkACLParser:
    """
    Parser for AWS Network ACLs configurations.
    
    Loads Network ACLs directly from AWS EC2 API and provides querying capabilities.
    """
    
    def __init__(self, aws_region: Optional[str] = None, aws_profile: Optional[str] = None):
        """
        Initialize parser with AWS credentials configuration.
        
        Args:
            aws_region: AWS region (defaults to AWS_DEFAULT_REGION or us-east-1)
            aws_profile: AWS profile name for credentials
        """
        if not AWS_AVAILABLE:
            raise ImportError("boto3 is required for AWS Network ACL parsing")
        
        self.aws_region = aws_region or self._get_default_region(aws_profile)
        self.aws_profile = aws_profile
        self.network_acls: Dict[str, NetworkACL] = {}
        self.aws_source: Optional[str] = None
    
    def _get_default_region(self, aws_profile: Optional[str] = None) -> str:
        """Get default AWS region from environment or config."""
        import os
        
        # Try environment variable first
        region = os.getenv('AWS_DEFAULT_REGION') or os.getenv('AWS_REGION')
        if region:
            return region
        
        # Try AWS config file
        try:
            import boto3
            session = boto3.Session(profile_name=aws_profile) if aws_profile else boto3.Session()
            if session.region_name:
                return session.region_name
        except Exception:
            pass
        
        # Default fallback
        return 'us-east-1'
    
    def _get_ec2_client(self):
        """Get boto3 EC2 client with configured credentials."""
        if not AWS_AVAILABLE:
            raise ImportError("boto3 is required for AWS Network ACL parsing")
        
        session_kwargs = {}
        if self.aws_profile:
            session_kwargs['profile_name'] = self.aws_profile
        
        session = boto3.Session(**session_kwargs)
        return session.client('ec2', region_name=self.aws_region)
    
    def load_from_aws(self, vpc_id: Optional[str] = None, network_acl_ids: Optional[List[str]] = None):
        """
        Load Network ACLs directly from AWS EC2 API.
        
        Args:
            vpc_id: Load all Network ACLs from a specific VPC
            network_acl_ids: Load specific Network ACLs by their IDs
            
        Raises:
            NoCredentialsError: If AWS credentials are not configured
            ClientError: If AWS API call fails
        """
        ec2_client = self._get_ec2_client()
        
        # Build filters
        filters = []
        if vpc_id:
            filters.append({'Name': 'vpc-id', 'Values': [vpc_id]})
        
        # Describe Network ACLs
        if network_acl_ids:
            response = ec2_client.describe_network_acls(NetworkAclIds=network_acl_ids)
        else:
            response = ec2_client.describe_network_acls(Filters=filters if filters else None)
        
        # Parse Network ACLs
        self.network_acls = {}
        for acl_data in response.get('NetworkAcls', []):
            acl = NetworkACL(acl_data)
            self.network_acls[acl.acl_id] = acl
        
        # Set source description
        if vpc_id:
            self.aws_source = f"AWS VPC: {vpc_id}"
        elif network_acl_ids:
            self.aws_source = f"AWS Network ACLs: {', '.join(network_acl_ids)}"
        else:
            self.aws_source = "AWS (all Network ACLs)"
    
    def get_summary(self) -> Dict[str, Any]:
        """
        Get high-level summary of loaded Network ACL configuration.
        
        Returns:
            Dictionary with summary information:
            - total_network_acls: Count of Network ACLs
            - total_rules: Count of all rules
            - vpcs: List of VPC IDs
            - network_acls: List of Network ACL summaries
            - aws_source: Source description
        """
        all_rules = []
        vpcs = set()
        acl_summaries = []
        
        for acl in self.network_acls.values():
            vpcs.add(acl.vpc_id)
            rules = acl.get_all_rules()
            all_rules.extend(rules)
            
            acl_summaries.append({
                'acl_id': acl.acl_id,
                'vpc_id': acl.vpc_id,
                'is_default': acl.is_default,
                'tags': acl.tags,
                'ingress_rule_count': len(acl.ingress_rules),
                'egress_rule_count': len(acl.egress_rules),
                'total_rules': len(rules),
            })
        
        return {
            'total_network_acls': len(self.network_acls),
            'total_rules': len(all_rules),
            'vpcs': sorted(list(vpcs)),
            'network_acls': acl_summaries,
            'aws_source': self.aws_source or 'Not loaded',
        }
    
    def get_all_rules(self) -> List[Dict[str, Any]]:
        """
        Get all rules from all Network ACLs.
        
        Returns:
            List of rule dictionaries
        """
        all_rules = []
        for acl in self.network_acls.values():
            all_rules.extend([rule.to_dict() for rule in acl.get_all_rules()])
        return all_rules
    
    def query_rules(
        self,
        cidr: Optional[str] = None,
        port: Optional[int] = None,
        protocol: Optional[str] = None,
        rule_action: Optional[str] = None,
        is_egress: Optional[bool] = None,
        tag_key: Optional[str] = None,
        tag_value: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """
        Query Network ACL rules by various criteria.
        
        Args:
            cidr: CIDR block to match
            port: Port number to match
            protocol: Protocol to match ('tcp', 'udp', 'icmp', '-1')
            rule_action: Rule action to match ('allow', 'deny')
            is_egress: Filter by egress (True) or ingress (False)
            tag_key: Network ACL tag key to filter by
            tag_value: Network ACL tag value to filter by (requires tag_key)
            
        Returns:
            List of matching rule dictionaries
        """
        results = []
        
        for acl in self.network_acls.values():
            # Filter by tags
            if tag_key:
                if tag_key not in acl.tags:
                    continue
                if tag_value and acl.tags[tag_key] != tag_value:
                    continue
            
            # Get rules to check
            rules_to_check = []
            if is_egress is None:
                rules_to_check = acl.get_all_rules()
            elif is_egress:
                rules_to_check = acl.egress_rules
            else:
                rules_to_check = acl.ingress_rules
            
            for rule in rules_to_check:
                # Filter by rule_action
                if rule_action and rule.rule_action != rule_action:
                    continue
                
                # Filter by protocol
                if protocol and rule.protocol != protocol:
                    continue
                
                # Filter by CIDR
                if cidr and not rule.matches_cidr(cidr):
                    continue
                
                # Filter by port
                if port is not None and not rule.matches_port(port):
                    continue
                
                # Rule matches all criteria
                rule_dict = rule.to_dict()
                rule_dict['acl_tags'] = acl.tags
                results.append(rule_dict)
        
        return results