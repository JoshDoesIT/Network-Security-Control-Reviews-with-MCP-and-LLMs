"""
Parsers for Network Security Control (NSC) Configurations

This package contains parsers for Network Security Control (NSC) configurations.
This lab uses AWS Security Groups and Network ACLs as examples of NSCs.

The architecture is extensible and can be extended to support other NSC types:
- Azure Network Security Groups (NSGs)
- Google Cloud Platform (GCP) Firewall Rules
- Oracle Cloud Infrastructure (OCI) Security Lists
- Traditional on-premises firewalls (Palo Alto, Check Point, Fortinet, etc.)

Exports:
    AWSSecurityGroupsParser - Parser for AWS Security Groups (instance-level NSC example)
    AWSNetworkACLParser - Parser for AWS Network ACLs (subnet-level NSC example)
    SecurityGroup - Represents an NSC (AWS Security Group)
    SecurityGroupRule - Represents a single NSC rule (AWS Security Group rule)
    NetworkACL - Represents an NSC (AWS Network ACL)
    NetworkACLRule - Represents a single NSC rule (AWS Network ACL rule)
"""

from .aws_security_groups import (
    AWSSecurityGroupsParser,
    SecurityGroup,
    SecurityGroupRule,
)
from .aws_network_acls import (
    AWSNetworkACLParser,
    NetworkACL,
    NetworkACLRule,
)

__all__ = [
    'AWSSecurityGroupsParser',
    'SecurityGroup',
    'SecurityGroupRule',
    'AWSNetworkACLParser',
    'NetworkACL',
    'NetworkACLRule',
]
