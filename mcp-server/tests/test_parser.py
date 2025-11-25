"""
Unit Tests for AWS Security Groups Parser

This module contains unit tests for the AWS Security Groups parser.
Tests verify AWS API integration, parsing functionality, rule querying, and summary generation.

Note:
    These tests use mocked AWS API responses to simulate real AWS behavior
    without requiring AWS credentials or making actual API calls.
"""

import json
import sys
from unittest.mock import Mock, patch, MagicMock
from pathlib import Path

# Add parent directory to Python path for imports
# Tests are in mcp-server/tests/, need to import from mcp-server/src/
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import parser module
from src.parsers.aws_security_groups import AWSSecurityGroupsParser


# Mock AWS API response data for production environment
MOCK_PRODUCTION_SGS = [
    {
        "GroupId": "sg-prod-db-001",
        "GroupName": "Production-Database-SG",
        "Description": "Security group for production database servers",
        "VpcId": "vpc-production-001",
        "Tags": [
            {"Key": "Environment", "Value": "Production"},
            {"Key": "Tier", "Value": "Database"},
            {"Key": "Network", "Value": "Network-A"}
        ],
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 3306,
                "ToPort": 3306,
                "UserIdGroupPairs": [
                    {
                        "GroupId": "sg-prod-app-001",
                        "Description": "Allow MySQL from application tier"
                    }
                ],
                "IpRanges": []
            }
        ],
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    },
    {
        "GroupId": "sg-prod-app-001",
        "GroupName": "Production-Application-SG",
        "Description": "Security group for production application servers",
        "VpcId": "vpc-production-001",
        "Tags": [
            {"Key": "Environment", "Value": "Production"},
            {"Key": "Tier", "Value": "Application"},
            {"Key": "Network", "Value": "Network-A"}
        ],
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [
                    {"CidrIp": "10.0.0.0/8", "Description": "Allow HTTPS from internal network"}
                ],
                "UserIdGroupPairs": []
            }
        ],
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    },
    {
        "GroupId": "sg-prod-web-001",
        "GroupName": "Production-Web-SG",
        "Description": "Security group for production web servers",
        "VpcId": "vpc-production-001",
        "Tags": [
            {"Key": "Environment", "Value": "Production"},
            {"Key": "Tier", "Value": "Web"},
            {"Key": "Network", "Value": "Network-A"}
        ],
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [
                    {"CidrIp": "0.0.0.0/0", "Description": "Allow HTTPS from internet"}
                ],
                "UserIdGroupPairs": []
            }
        ],
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    }
]

# Mock AWS API response data for development environment
MOCK_DEVELOPMENT_SGS = [
    {
        "GroupId": "sg-dev-db-001",
        "GroupName": "Dev-Database-SG",
        "Description": "Security group for development database servers",
        "VpcId": "vpc-dev-001",
        "Tags": [
            {"Key": "Environment", "Value": "Development"},
            {"Key": "Tier", "Value": "Database"},
            {"Key": "Network", "Value": "Network-B"}
        ],
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 3306,
                "ToPort": 3306,
                "UserIdGroupPairs": [
                    {
                        "GroupId": "sg-dev-app-001",
                        "Description": "Allow MySQL from application tier"
                    }
                ],
                "IpRanges": []
            },
            {
                "IpProtocol": "tcp",
                "FromPort": 22,
                "ToPort": 22,
                "IpRanges": [
                    {"CidrIp": "0.0.0.0/0", "Description": "WARNING: Overly permissive SSH access"}
                ],
                "UserIdGroupPairs": []
            }
        ],
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    },
    {
        "GroupId": "sg-dev-app-001",
        "GroupName": "Dev-Application-SG",
        "Description": "Security group for development application servers",
        "VpcId": "vpc-dev-001",
        "Tags": [
            {"Key": "Environment", "Value": "Development"},
            {"Key": "Tier", "Value": "Application"},
            {"Key": "Network", "Value": "Network-B"}
        ],
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 80,
                "ToPort": 80,
                "IpRanges": [
                    {"CidrIp": "0.0.0.0/0", "Description": "WARNING: Overly permissive HTTP access"}
                ],
                "UserIdGroupPairs": []
            }
        ],
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    },
    {
        "GroupId": "sg-dev-web-001",
        "GroupName": "Dev-Web-SG",
        "Description": "Security group for development web servers",
        "VpcId": "vpc-dev-001",
        "Tags": [
            {"Key": "Environment", "Value": "Development"},
            {"Key": "Tier", "Value": "Web"},
            {"Key": "Network", "Value": "Network-B"}
        ],
        "IpPermissions": [
            {
                "IpProtocol": "tcp",
                "FromPort": 443,
                "ToPort": 443,
                "IpRanges": [
                    {"CidrIp": "0.0.0.0/0", "Description": "Allow HTTPS from internet"}
                ],
                "UserIdGroupPairs": []
            }
        ],
        "IpPermissionsEgress": [
            {
                "IpProtocol": "-1",
                "IpRanges": [{"CidrIp": "0.0.0.0/0"}]
            }
        ]
    }
]


@patch('src.parsers.aws_security_groups.boto3')
def test_load_from_aws_production(mock_boto3):
    """
    Test loading production security groups from AWS API.
    
    Verifies:
        - AWS API client is created correctly
        - describe_security_groups is called with correct filters
        - Security groups are parsed correctly
        - Summary generation includes correct counts
        - VPC ID is correctly identified
        
    Uses mocked AWS API responses to simulate real AWS behavior.
    """
    # Create mock EC2 client
    mock_ec2_client = MagicMock()
    mock_session = MagicMock()
    mock_session.client.return_value = mock_ec2_client
    mock_boto3.Session.return_value = mock_session
    
    # Configure mock response for describe_security_groups
    mock_ec2_client.describe_security_groups.return_value = {
        'SecurityGroups': MOCK_PRODUCTION_SGS
    }
    
    # Create parser instance
    parser = AWSSecurityGroupsParser(aws_region="us-east-1")
    
    # Load from AWS (mocked)
    security_groups = parser.load_from_aws(vpc_id="vpc-production-001")
    
    # Verify AWS API was called correctly
    mock_session.client.assert_called_once_with('ec2')
    mock_ec2_client.describe_security_groups.assert_called_once_with(
        Filters=[{'Name': 'vpc-id', 'Values': ['vpc-production-001']}]
    )
    
    # Verify expected security groups are present
    assert len(security_groups) == 3, f"Expected 3 security groups, got {len(security_groups)}"
    assert "sg-prod-db-001" in security_groups
    assert "sg-prod-app-001" in security_groups
    assert "sg-prod-web-001" in security_groups
    
    # Test summary generation
    summary = parser.get_summary()
    assert summary["total_security_groups"] == 3
    assert summary["total_rules"] > 0
    assert "vpc-production-001" in summary["vpcs"]
    assert summary["aws_source"] == "AWS VPC: vpc-production-001"
    
    print("✓ Production config loading from AWS test passed")


@patch('src.parsers.aws_security_groups.boto3')
def test_query_rules(mock_boto3):
    """
    Test rule querying functionality with mocked AWS data.
    
    Verifies:
        - Querying by source CIDR works
        - Querying by tags works
        - Results are correctly filtered
        
    Uses mocked AWS API responses to simulate development environment.
    """
    # Create mock EC2 client
    mock_ec2_client = MagicMock()
    mock_session = MagicMock()
    mock_session.client.return_value = mock_ec2_client
    mock_boto3.Session.return_value = mock_session
    
    # Configure mock response for describe_security_groups
    mock_ec2_client.describe_security_groups.return_value = {
        'SecurityGroups': MOCK_DEVELOPMENT_SGS
    }
    
    # Create parser instance
    parser = AWSSecurityGroupsParser(aws_region="us-east-1")
    
    # Load from AWS (mocked)
    parser.load_from_aws(vpc_id="vpc-dev-001")
    
    # Query for overly permissive rules (0.0.0.0/0 = entire internet)
    permissive_rules = parser.query_rules(source="0.0.0.0/0")
    assert len(permissive_rules) > 0, "Should find overly permissive rules"
    
    # Verify we found the SSH rule from development database
    ssh_rules = [r for r in permissive_rules if r.get('from_port') == 22]
    assert len(ssh_rules) > 0, "Should find SSH rule from 0.0.0.0/0"
    
    # Query by tag to filter by environment
    dev_rules = parser.query_rules(tag_key="Environment", tag_value="Development")
    assert len(dev_rules) > 0, "Should find development environment rules"
    
    # Verify all returned rules are from development environment
    for rule in dev_rules:
        # Rules should be from development security groups
        assert rule['security_group_id'] in ['sg-dev-db-001', 'sg-dev-app-001', 'sg-dev-web-001']
    
    print("✓ Rule querying test passed")


@patch('src.parsers.aws_security_groups.boto3')
def test_load_by_security_group_ids(mock_boto3):
    """
    Test loading specific security groups by their IDs.
    
    Verifies:
        - describe_security_groups is called with GroupIds parameter
        - Only specified security groups are loaded
    """
    # Create mock EC2 client
    mock_ec2_client = MagicMock()
    mock_session = MagicMock()
    mock_session.client.return_value = mock_ec2_client
    mock_boto3.Session.return_value = mock_session
    
    # Configure mock response for describe_security_groups
    mock_ec2_client.describe_security_groups.return_value = {
        'SecurityGroups': [MOCK_PRODUCTION_SGS[0]]  # Only first security group
    }
    
    # Create parser instance
    parser = AWSSecurityGroupsParser(aws_region="us-east-1")
    
    # Load specific security groups by ID
    security_groups = parser.load_from_aws(security_group_ids=["sg-prod-db-001"])
    
    # Verify AWS API was called with GroupIds
    mock_ec2_client.describe_security_groups.assert_called_once_with(
        GroupIds=["sg-prod-db-001"]
    )
    
    # Verify only the specified security group was loaded
    assert len(security_groups) == 1
    assert "sg-prod-db-001" in security_groups
    
    print("✓ Load by security group IDs test passed")


if __name__ == "__main__":
    """
    Run all tests when executed directly.
    
    Usage:
        python mcp-server/tests/test_parser.py
        
    Note:
        These tests use mocked AWS API responses and do not require
        AWS credentials or actual AWS API calls.
    """
    test_load_from_aws_production()
    test_query_rules()
    test_load_by_security_group_ids()
    print("\nAll tests passed!")

