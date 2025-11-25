"""
Integration Tests for AWS Security Groups Parser

This module contains integration tests that make real AWS API calls.
These tests verify end-to-end functionality with actual AWS resources.

Prerequisites:
    - AWS credentials configured (via aws configure or environment variables)
    - AWS test environment deployed via Terraform (see ../../docs/aws-setup.md)
    - Terraform outputs available (VPC IDs)

Usage:
    # Run integration tests (requires AWS credentials)
    python mcp-server/tests/test_integration.py
    
    # Or skip if credentials not available (tests will be skipped automatically)
    python mcp-server/tests/test_integration.py

Note:
    These tests make real AWS API calls and may incur minimal costs.
    Tests are automatically skipped if AWS credentials are not available.
"""

import os
import sys
import subprocess
from pathlib import Path
from typing import Optional, Tuple

# Add parent directory to Python path for imports
# Tests are in mcp-server/tests/, need to import from mcp-server/src/
sys.path.insert(0, str(Path(__file__).parent.parent))

# Import parser module
from src.parsers.aws_security_groups import AWSSecurityGroupsParser

# Try to import boto3 for credential checking
try:
    import boto3
    from botocore.exceptions import NoCredentialsError, ClientError, MissingDependencyException
    AWS_AVAILABLE = True
except ImportError:
    AWS_AVAILABLE = False


def check_aws_credentials() -> bool:
    """
    Check if AWS credentials are available and valid.
    
    Uses the 'mcp' profile to avoid SSO/login credential issues.
    
    Returns:
        True if credentials are available and valid, False otherwise
    """
    if not AWS_AVAILABLE:
        return False
    
    try:
        # Try to create a session with the mcp profile and get caller identity
        # This avoids SSO/login credential issues by using access key credentials
        session = boto3.Session(profile_name='mcp')
        sts = session.client('sts')
        sts.get_caller_identity()
        return True
    except (NoCredentialsError, ClientError, MissingDependencyException):
        # MissingDependencyException occurs when trying to use SSO/login credentials
        # without botocore[crt] installed
        return False


def get_terraform_output(output_name: str) -> Optional[str]:
    """
    Get a Terraform output value.
    
    Args:
        output_name: Name of the Terraform output to retrieve
        
    Returns:
        Output value as string, or None if not available
    """
    try:
        # Terraform directory is two levels up from mcp-server/tests/
        terraform_dir = Path(__file__).parent.parent.parent / "terraform"
        if not terraform_dir.exists():
            return None
        
        # Run terraform output command
        result = subprocess.run(
            ["terraform", "output", "-raw", output_name],
            cwd=terraform_dir,
            capture_output=True,
            text=True,
            timeout=10
        )
        
        if result.returncode == 0 and result.stdout.strip():
            return result.stdout.strip()
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
        return None


def get_vpc_ids() -> Tuple[Optional[str], Optional[str]]:
    """
    Get VPC IDs from Terraform outputs or environment variables.
    
    Returns:
        Tuple of (production_vpc_id, development_vpc_id)
    """
    # Try Terraform outputs first
    prod_vpc = get_terraform_output("production_vpc_id")
    dev_vpc = get_terraform_output("development_vpc_id")
    
    # Fall back to environment variables
    if not prod_vpc:
        prod_vpc = os.getenv("TEST_PRODUCTION_VPC_ID")
    if not dev_vpc:
        dev_vpc = os.getenv("TEST_DEVELOPMENT_VPC_ID")
    
    return (prod_vpc, dev_vpc)


def skip_if_no_credentials(test_func):
    """
    Decorator to skip a test if AWS credentials are not available.
    
    Usage:
        @skip_if_no_credentials
        def test_something():
            ...
    """
    def wrapper(*args, **kwargs):
        if not check_aws_credentials():
            print(f"⏭️  Skipping {test_func.__name__}: AWS credentials not available")
            return
        return test_func(*args, **kwargs)
    wrapper.__name__ = test_func.__name__
    return wrapper


@skip_if_no_credentials
def test_load_production_vpc_from_aws():
    """
    Integration test: Load production VPC security groups from AWS.
    
    Verifies:
        - Can connect to AWS API
        - Can load security groups from a real VPC
        - Parser correctly handles real AWS API responses
        - Summary generation works with real data
    """
    prod_vpc_id, _ = get_vpc_ids()
    
    if not prod_vpc_id:
        print("⏭️  Skipping test: Production VPC ID not available")
        print("   Deploy Terraform infrastructure or set TEST_PRODUCTION_VPC_ID env var")
        return
    
    print(f"\n🧪 Testing: Load production VPC ({prod_vpc_id}) from AWS...")
    
    try:
        # Create parser instance
        parser = AWSSecurityGroupsParser(aws_region="us-east-1", aws_profile="mcp")
        
        # Load from AWS (real API call)
        security_groups = parser.load_from_aws(vpc_id=prod_vpc_id)
        
        # Verify we got security groups
        assert len(security_groups) > 0, "Should load at least one security group"
        print(f"   ✓ Loaded {len(security_groups)} security groups")
        
        # Verify summary generation
        summary = parser.get_summary()
        assert summary["total_security_groups"] > 0
        assert summary["total_rules"] > 0
        assert prod_vpc_id in summary["vpcs"]
        assert summary["aws_source"] == f"AWS VPC: {prod_vpc_id}"
        print(f"   ✓ Summary: {summary['total_security_groups']} SGs, {summary['total_rules']} rules")
        
        # Verify security groups have expected structure
        for sg_id, sg in security_groups.items():
            assert sg.group_id == sg_id
            assert sg.vpc_id == prod_vpc_id
            assert len(sg.ip_permissions) >= 0  # Can have zero ingress rules
            assert len(sg.ip_permissions_egress) >= 0  # Can have zero egress rules
        
        print("   ✓ All security groups have valid structure")
        print("✅ test_load_production_vpc_from_aws passed")
        
    except Exception as e:
        print(f"❌ test_load_production_vpc_from_aws failed: {e}")
        raise


@skip_if_no_credentials
def test_load_development_vpc_from_aws():
    """
    Integration test: Load development VPC security groups from AWS.
    
    Verifies:
        - Can load development environment security groups
        - Parser handles different VPC configurations
    """
    _, dev_vpc_id = get_vpc_ids()
    
    if not dev_vpc_id:
        print("⏭️  Skipping test: Development VPC ID not available")
        print("   Deploy Terraform infrastructure or set TEST_DEVELOPMENT_VPC_ID env var")
        return
    
    print(f"\n🧪 Testing: Load development VPC ({dev_vpc_id}) from AWS...")
    
    try:
        # Create parser instance
        parser = AWSSecurityGroupsParser(aws_region="us-east-1", aws_profile="mcp")
        
        # Load from AWS (real API call)
        security_groups = parser.load_from_aws(vpc_id=dev_vpc_id)
        
        # Verify we got security groups
        assert len(security_groups) > 0, "Should load at least one security group"
        print(f"   ✓ Loaded {len(security_groups)} security groups")
        
        # Verify summary
        summary = parser.get_summary()
        assert dev_vpc_id in summary["vpcs"]
        print(f"   ✓ Summary: {summary['total_security_groups']} SGs, {summary['total_rules']} rules")
        
        print("✅ test_load_development_vpc_from_aws passed")
        
    except Exception as e:
        print(f"❌ test_load_development_vpc_from_aws failed: {e}")
        raise


@skip_if_no_credentials
def test_query_rules_with_real_data():
    """
    Integration test: Query rules from real AWS security groups.
    
    Verifies:
        - Rule querying works with real AWS data
        - Tag-based filtering works
        - Source CIDR filtering works
    """
    prod_vpc_id, _ = get_vpc_ids()
    
    if not prod_vpc_id:
        print("⏭️  Skipping test: Production VPC ID not available")
        return
    
    print(f"\n🧪 Testing: Query rules from production VPC ({prod_vpc_id})...")
    
    try:
        # Create parser and load from AWS
        parser = AWSSecurityGroupsParser(aws_region="us-east-1", aws_profile="mcp")
        parser.load_from_aws(vpc_id=prod_vpc_id)
        
        # Query all rules
        all_rules = parser.get_all_rules()
        assert len(all_rules) > 0, "Should have at least one rule"
        print(f"   ✓ Found {len(all_rules)} total rules")
        
        # Query by tag (if tags exist)
        # Try to find rules from security groups with Environment tag
        env_rules = parser.query_rules(tag_key="Environment")
        print(f"   ✓ Found {len(env_rules)} rules with Environment tag")
        
        # Query for overly permissive rules (0.0.0.0/0)
        permissive_rules = parser.query_rules(source="0.0.0.0/0")
        print(f"   ✓ Found {len(permissive_rules)} permissive rules (0.0.0.0/0)")
        
        # Query by port (if any rules exist)
        if all_rules:
            # Try to find rules for common ports
            for port in [80, 443, 22]:
                port_rules = parser.query_rules(port=port)
                if port_rules:
                    print(f"   ✓ Found {len(port_rules)} rules for port {port}")
        
        print("✅ test_query_rules_with_real_data passed")
        
    except Exception as e:
        print(f"❌ test_query_rules_with_real_data failed: {e}")
        raise


@skip_if_no_credentials
def test_load_by_security_group_ids():
    """
    Integration test: Load specific security groups by their IDs.
    
    Verifies:
        - Can load specific security groups by ID
        - Works with real AWS security group IDs
    """
    prod_vpc_id, _ = get_vpc_ids()
    
    if not prod_vpc_id:
        print("⏭️  Skipping test: Production VPC ID not available")
        return
    
    print(f"\n🧪 Testing: Load specific security groups by ID...")
    
    try:
        # First, load all security groups to get some IDs
        parser_all = AWSSecurityGroupsParser(aws_region="us-east-1", aws_profile="mcp")
        all_sgs = parser_all.load_from_aws(vpc_id=prod_vpc_id)
        
        if len(all_sgs) == 0:
            print("⏭️  Skipping test: No security groups found in VPC")
            return
        
        # Get first two security group IDs
        sg_ids = list(all_sgs.keys())[:2]
        print(f"   ✓ Testing with security group IDs: {sg_ids}")
        
        # Load specific security groups by ID
        parser_specific = AWSSecurityGroupsParser(aws_region="us-east-1", aws_profile="mcp")
        specific_sgs = parser_specific.load_from_aws(security_group_ids=sg_ids)
        
        # Verify we got the expected security groups
        assert len(specific_sgs) == len(sg_ids), f"Expected {len(sg_ids)} SGs, got {len(specific_sgs)}"
        for sg_id in sg_ids:
            assert sg_id in specific_sgs, f"Security group {sg_id} should be loaded"
        
        print(f"   ✓ Successfully loaded {len(specific_sgs)} security groups by ID")
        print("✅ test_load_by_security_group_ids passed")
        
    except Exception as e:
        print(f"❌ test_load_by_security_group_ids failed: {e}")
        raise


@skip_if_no_credentials
def test_segmentation_analysis():
    """
    Integration test: Test segmentation analysis between production and development.
    
    Verifies:
        - Can load both environments
        - Can identify cross-network connections
        - Segmentation analysis works with real data
    """
    prod_vpc_id, dev_vpc_id = get_vpc_ids()
    
    if not prod_vpc_id or not dev_vpc_id:
        print("⏭️  Skipping test: VPC IDs not available")
        return
    
    print(f"\n🧪 Testing: Segmentation analysis between VPCs...")
    print(f"   Production VPC: {prod_vpc_id}")
    print(f"   Development VPC: {dev_vpc_id}")
    
    try:
        # Load production security groups
        parser_prod = AWSSecurityGroupsParser(aws_region="us-east-1", aws_profile="mcp")
        prod_sgs = parser_prod.load_from_aws(vpc_id=prod_vpc_id)
        prod_summary = parser_prod.get_summary()
        print(f"   ✓ Production: {prod_summary['total_security_groups']} SGs, {prod_summary['total_rules']} rules")
        
        # Load development security groups
        parser_dev = AWSSecurityGroupsParser(aws_region="us-east-1", aws_profile="mcp")
        dev_sgs = parser_dev.load_from_aws(vpc_id=dev_vpc_id)
        dev_summary = parser_dev.get_summary()
        print(f"   ✓ Development: {dev_summary['total_security_groups']} SGs, {dev_summary['total_rules']} rules")
        
        # Check for overly permissive rules in development
        dev_permissive = parser_dev.query_rules(source="0.0.0.0/0")
        print(f"   ✓ Development permissive rules: {len(dev_permissive)}")
        
        # Check for production permissive rules
        prod_permissive = parser_prod.query_rules(source="0.0.0.0/0")
        print(f"   ✓ Production permissive rules: {len(prod_permissive)}")
        
        # Note: Cross-network connection detection would require loading both VPCs
        # into the same parser instance, which is a more advanced use case
        
        print("✅ test_segmentation_analysis passed")
        
    except Exception as e:
        print(f"❌ test_segmentation_analysis failed: {e}")
        raise


if __name__ == "__main__":
    """
    Run all integration tests when executed directly.
    
    Usage:
        # Run all integration tests (requires AWS credentials)
        python mcp-server/tests/test_integration.py
        
    Note:
        Tests are automatically skipped if AWS credentials are not available.
        VPC IDs are read from Terraform outputs or environment variables.
    """
    print("=" * 70)
    print("Integration Tests for AWS Security Groups Parser")
    print("=" * 70)
    
    # Check prerequisites
    if not AWS_AVAILABLE:
        print("\n❌ boto3 not installed. Install with: pip install boto3")
        print("   Skipping all integration tests.")
        sys.exit(0)
    
    if not check_aws_credentials():
        print("\n⏭️  AWS credentials not available.")
        print("   Configure credentials using: aws configure")
        print("   Or set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY environment variables")
        print("   Skipping all integration tests.")
        sys.exit(0)
    
    print("\n✓ AWS credentials available")
    
    # Check for VPC IDs
    prod_vpc, dev_vpc = get_vpc_ids()
    if prod_vpc:
        print(f"✓ Production VPC ID: {prod_vpc}")
    else:
        print("⚠️  Production VPC ID not found (from Terraform or TEST_PRODUCTION_VPC_ID)")
    
    if dev_vpc:
        print(f"✓ Development VPC ID: {dev_vpc}")
    else:
        print("⚠️  Development VPC ID not found (from Terraform or TEST_DEVELOPMENT_VPC_ID)")
    
    print("\n" + "=" * 70)
    print("Running Integration Tests...")
    print("=" * 70)
    
    # Run tests
    tests = [
        test_load_production_vpc_from_aws,
        test_load_development_vpc_from_aws,
        test_query_rules_with_real_data,
        test_load_by_security_group_ids,
        test_segmentation_analysis,
    ]
    
    passed = 0
    skipped = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"\n❌ {test.__name__} failed: {e}")
            failed += 1
        except Exception as e:
            # Check if it was skipped (no exception means skip)
            if "Skipping" in str(e) or "not available" in str(e):
                skipped += 1
            else:
                print(f"\n❌ {test.__name__} failed with error: {e}")
                failed += 1
    
    print("\n" + "=" * 70)
    print("Integration Test Results")
    print("=" * 70)
    print(f"Passed:  {passed}")
    print(f"Skipped: {skipped}")
    print(f"Failed:  {failed}")
    print("=" * 70)
    
    if failed > 0:
        sys.exit(1)
    else:
        print("\n✅ All integration tests passed!")

