"""
MCP Tools for Network Security Control (NSC) Configuration Queries

This module defines the MCP tools (functions) that LLMs can call to interact with
NSC configurations. This lab uses AWS Security Groups and Network ACLs
as examples of NSCs.

Tools provide read-only access to NSC configurations. While this implementation focuses on
AWS Security Groups and Network ACLs, the architecture is extensible to support other NSC types:
- Azure Network Security Groups (NSGs)
- Google Cloud Platform (GCP) Firewall Rules
- Oracle Cloud Infrastructure (OCI) Security Lists
- Traditional on-premises firewalls (Palo Alto, Check Point, Fortinet, etc.)

Tools:
    - get_config: Load NSC configurations (AWS Security Groups and Network ACLs) from AWS, or get summary of already-loaded configuration
    - query_rules: Query NSC rules by various criteria (source, port, protocol, tags), or get all rules with no parameters
    - list_vpcs: List VPCs to discover NSC resources

Design Philosophy:
    - MCP server = Data access layer (parse, query, retrieve NSC configurations)
    - LLM = Analysis engine (performs all security and segmentation analysis)
    - Read-only: No configuration modification capabilities
"""

from typing import Optional, List, Dict, Any
from mcp.types import Tool, TextContent
import json
import os

from ..parsers.aws_security_groups import AWSSecurityGroupsParser
from ..parsers.aws_network_acls import AWSNetworkACLParser


# Global parser instances (in-memory storage)
# This maintains state between tool calls - once a configuration is loaded,
# subsequent queries operate on the same loaded data
_parser: Optional[AWSSecurityGroupsParser] = None
_nacl_parser: Optional[AWSNetworkACLParser] = None


def get_nsc_tools() -> List[Tool]:
    """
    Get list of MCP tools available for AWS Security Groups configuration queries.
    
    Returns the tool definitions that LLMs can discover and use. Each tool
    includes a name, description, and input schema defining required/optional parameters.
    
    Returns:
        List[Tool]: List of MCP tool definitions
        
    Note:
        Tool schemas follow JSON Schema format for parameter validation
        This function can be extended to return tools for other cloud providers
    """
    return [
        Tool(
            name="get_config",
            description=(
                "Load AWS Security Groups and Network ACLs configuration directly from AWS, or get summary of already-loaded configuration. "
                "Loads security groups and Network ACLs by VPC ID or specific resource IDs. "
                "Returns the parsed configuration summary with rule counts and VPC information. "
                "If called without vpc_id or security_group_ids and configuration is already loaded, returns the summary without reloading. "
                "AWS region is automatically detected from your AWS profile/config if not specified. "
                "Requires AWS credentials to be configured (see setup documentation)."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "vpc_id": {
                        "type": "string",
                        "description": "AWS VPC ID to load all security groups and Network ACLs from (e.g., 'vpc-production-001'). Either vpc_id or specific resource IDs must be provided."
                    },
                    "security_group_ids": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of specific security group IDs to load (e.g., ['sg-prod-db-001', 'sg-prod-app-001']). Either vpc_id or security_group_ids must be provided."
                    },
                    "load_network_acls": {
                        "type": "boolean",
                        "description": "Whether to load Network ACLs along with Security Groups (default: true if vpc_id is provided)"
                    },
                    "aws_region": {
                        "type": "string",
                        "description": "AWS region to use (optional - auto-detected from AWS profile/config if not specified, defaults to 'us-east-1')"
                    },
                    "aws_profile": {
                        "type": "string",
                        "description": "AWS profile name to use for credentials (defaults to default profile)"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="query_rules",
            description=(
                "Query AWS Security Group rules and Network ACL rules by source, destination, port/service, protocol, or tags. "
                "Returns matching rules that meet all specified criteria. "
                "If called with no parameters, returns all rules from the loaded configuration (both Security Groups and Network ACLs). "
                "Useful for finding overly permissive rules, cross-network connections, segmentation violations, or rules matching specific patterns. "
                "Must call get_config first to load a configuration."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "source": {
                        "type": "string",
                        "description": "Source CIDR block (e.g., '0.0.0.0/0') or security group ID (e.g., 'sg-prod-app-001') to filter by"
                    },
                    "destination": {
                        "type": "string",
                        "description": "Destination CIDR block or security group ID to filter by"
                    },
                    "port": {
                        "type": "integer",
                        "description": "Port number to filter by (e.g., 22 for SSH, 443 for HTTPS)"
                    },
                    "protocol": {
                        "type": "string",
                        "description": "IP protocol to filter by: 'tcp', 'udp', 'icmp', or '-1' for all protocols"
                    },
                    "tag_key": {
                        "type": "string",
                        "description": "Security group tag key to filter by (e.g., 'Environment', 'Network')"
                    },
                    "tag_value": {
                        "type": "string",
                        "description": "Security group tag value to filter by (requires tag_key, e.g., 'Production', 'Network-A')"
                    }
                },
                "required": []
            }
        ),
        Tool(
            name="list_vpcs",
            description=(
                "List all VPCs in the AWS account with their details. "
                "Returns VPC IDs, CIDR blocks, tags, and associated subnets. "
                "Useful for discovering VPC IDs before loading security groups. "
                "Can be filtered by tags to find specific environments or networks."
            ),
            inputSchema={
                "type": "object",
                "properties": {
                    "aws_region": {
                        "type": "string",
                        "description": "AWS region to use (optional - auto-detected from AWS profile/config if not specified, defaults to 'us-east-1')"
                    },
                    "aws_profile": {
                        "type": "string",
                        "description": "AWS profile name to use for credentials (defaults to default profile)"
                    },
                    "tag_key": {
                        "type": "string",
                        "description": "VPC tag key to filter by (e.g., 'Environment', 'Network')"
                    },
                    "tag_value": {
                        "type": "string",
                        "description": "VPC tag value to filter by (requires tag_key, e.g., 'Production', 'Development')"
                    }
                },
                "required": []
            }
        )
    ]


async def handle_get_config(arguments: Dict[str, Any]) -> List[TextContent]:
    """
    Handle get_config tool call - loads security groups and Network ACLs from AWS, or returns summary of already-loaded config.

    This is the primary tool for loading AWS Security Groups and Network ACLs configurations. 
    It loads security groups and optionally Network ACLs directly from AWS via the API. 
    Supports loading by VPC ID (all resources in a VPC) or by specific security group IDs.
    
    If called without vpc_id or security_group_ids and configuration is already loaded,
    returns the summary without making AWS API calls.
    
    Args:
        arguments: Dictionary containing tool arguments:
            - vpc_id (str, optional): VPC ID to load all security groups and Network ACLs from
            - security_group_ids (list[str], optional): Specific security group IDs to load
            - load_network_acls (bool, optional): Whether to load Network ACLs (default: true if vpc_id provided)
            - aws_region (str, optional): AWS region (defaults to AWS_DEFAULT_REGION)
            - aws_profile (str, optional): AWS profile name for credentials
            
    Returns:
        List[TextContent]: JSON response containing:
            - status: "success" or error information
            - message: Human-readable status message
            - summary: Configuration summary with counts and VPC information
            - network_acl_summary: Network ACL summary (if loaded)
            
    Raises:
        Returns error JSON if:
            - No source specified and no configuration already loaded
            - AWS credentials not found
            - AWS API errors (permissions, invalid VPC ID, etc.)
            
    Example:
        Load all security groups and Network ACLs from a VPC:
        {
            "vpc_id": "vpc-production-001",
            "aws_region": "us-east-1"
        }
        
        Load specific security groups:
        {
            "security_group_ids": ["sg-prod-db-001", "sg-prod-app-001"],
            "aws_region": "us-east-1"
        }
        
        Get summary of already-loaded configuration:
        {}
    """
    global _parser, _nacl_parser
    
    # Extract arguments
    vpc_id = arguments.get("vpc_id")
    security_group_ids = arguments.get("security_group_ids")
    load_network_acls = arguments.get("load_network_acls", vpc_id is not None)  # Default to True if vpc_id provided
    aws_region = arguments.get("aws_region")
    aws_profile = arguments.get("aws_profile")
    
    # If no source specified, check if config is already loaded and return summary
    if not vpc_id and not security_group_ids:
        if _parser is None:
            return [TextContent(
                type="text",
                text=json.dumps({
                    "error": "Either vpc_id or security_group_ids must be provided to load configuration, or configuration must already be loaded"
                }, indent=2)
            )]
        
        # Return summary of already-loaded configuration
        try:
            summary = _parser.get_summary()
            response_data = {
                "status": "success",
                "message": f"Summary of loaded configuration: {summary.get('aws_source', 'AWS')}",
                "summary": summary
            }
            
            # Add Network ACL summary if loaded
            if _nacl_parser is not None:
                nacl_summary = _nacl_parser.get_summary()
                response_data["network_acl_summary"] = nacl_summary
                response_data["message"] += f" (Network ACLs: {nacl_summary.get('total_network_acls', 0)} ACLs, {nacl_summary.get('total_rules', 0)} rules)"
            
            return [TextContent(
                type="text",
                text=json.dumps(response_data, indent=2)
            )]
        except Exception as e:
            return [TextContent(
                type="text",
                text=json.dumps({"error": str(e)}, indent=2)
            )]
    
    try:
        # Create parser instance with AWS credentials configuration
        _parser = AWSSecurityGroupsParser(aws_region=aws_region, aws_profile=aws_profile)
        
        # Load Security Groups from AWS API
        _parser.load_from_aws(vpc_id=vpc_id, security_group_ids=security_group_ids)
        
        # Get summary of loaded Security Groups configuration
        summary = _parser.get_summary()
        message = f"Configuration loaded from AWS: {summary.get('aws_source', 'AWS')}"
        
        response_data = {
            "status": "success",
            "message": message,
            "summary": summary
        }
        
        # Load Network ACLs if requested and vpc_id is provided
        if load_network_acls and vpc_id:
            try:
                _nacl_parser = AWSNetworkACLParser(aws_region=aws_region, aws_profile=aws_profile)
                _nacl_parser.load_from_aws(vpc_id=vpc_id)
                nacl_summary = _nacl_parser.get_summary()
                response_data["network_acl_summary"] = nacl_summary
                message += f" (Network ACLs: {nacl_summary.get('total_network_acls', 0)} ACLs, {nacl_summary.get('total_rules', 0)} rules)"
            except Exception as nacl_error:
                # Network ACL loading failed, but continue with Security Groups
                response_data["network_acl_error"] = f"Failed to load Network ACLs: {str(nacl_error)}"
        
        response_data["message"] = message
        
        return [TextContent(
            type="text",
            text=json.dumps(response_data, indent=2)
        )]
    except Exception as e:
        # Return error as JSON for LLM to handle
        return [TextContent(
            type="text",
            text=json.dumps({"error": str(e)}, indent=2)
        )]


async def handle_query_rules(arguments: Dict[str, Any]) -> List[TextContent]:
    """
    Handle query_rules tool call - queries Security Group and Network ACL rules by various criteria.
    
    Filters rules based on source, destination, port, protocol, or tags.
    All specified criteria must match (AND logic). Useful for finding specific
    security issues like overly permissive rules, cross-network connections, or segmentation violations.
    
    Args:
        arguments: Dictionary containing query filters:
            - source (str, optional): CIDR block or security group ID
            - destination (str, optional): CIDR block or security group ID
            - port (int, optional): Port number to match
            - protocol (str, optional): Protocol ('tcp', 'udp', 'icmp', '-1')
            - tag_key (str, optional): Tag key to filter by (for Security Groups or Network ACLs)
            - tag_value (str, optional): Tag value (requires tag_key)
            
    Returns:
        List[TextContent]: JSON response containing:
            - matches: Number of matching rules
            - security_group_rules: List of matching Security Group rule dictionaries
            - network_acl_rules: List of matching Network ACL rule dictionaries (if loaded)
            
    Raises:
        Returns error JSON if:
            - No configuration loaded
            - Query execution errors
            
    Example Queries:
        Find all overly permissive rules:
        {"source": "0.0.0.0/0"}
        
        Find SSH rules:
        {"port": 22, "protocol": "tcp"}
        
        Find production environment rules:
        {"tag_key": "Environment", "tag_value": "Production"}
        
        Find cross-VPC segmentation violations:
        {"source": "10.0.0.0/16"}  # Production VPC CIDR
    """
    global _parser, _nacl_parser
    
    # Check if configuration has been loaded
    if _parser is None:
        return [TextContent(
            type="text",
            text=json.dumps({
                "error": "No configuration loaded. Call get_config first."
            }, indent=2)
        )]
    
    try:
        # Extract query parameters
        source = arguments.get("source")
        destination = arguments.get("destination")
        port = arguments.get("port")
        protocol = arguments.get("protocol")
        tag_key = arguments.get("tag_key")
        tag_value = arguments.get("tag_value")
        
        # Query Security Group rules
        sg_results = _parser.query_rules(
            source=source,
            destination=destination,
            port=port,
            protocol=protocol,
            tag_key=tag_key,
            tag_value=tag_value
        )
        
        response_data = {
            "matches": len(sg_results),
            "security_group_rules": sg_results
        }
        
        # Query Network ACL rules if loaded
        if _nacl_parser is not None:
            # Map query parameters for Network ACL query
            nacl_cidr = source or destination
            nacl_results = _nacl_parser.query_rules(
                cidr=nacl_cidr,
                port=port,
                protocol=protocol,
                tag_key=tag_key,
                tag_value=tag_value
            )
            response_data["network_acl_rules"] = nacl_results
            response_data["matches"] = len(sg_results) + len(nacl_results)
            response_data["security_group_matches"] = len(sg_results)
            response_data["network_acl_matches"] = len(nacl_results)
        
        return [TextContent(
            type="text",
            text=json.dumps(response_data, indent=2)
        )]
    except Exception as e:
        return [TextContent(
            type="text",
            text=json.dumps({"error": str(e)}, indent=2)
        )]


async def handle_list_vpcs(arguments: Dict[str, Any]) -> List[TextContent]:
    """
    Handle list_vpcs tool call - lists all VPCs in AWS account.
    
    Returns VPC details including IDs, CIDR blocks, tags, and associated subnets.
    Useful for discovering VPC IDs before loading security groups.
    
    Args:
        arguments: Dictionary containing tool arguments:
            - aws_region (str, optional): AWS region (defaults to AWS_DEFAULT_REGION)
            - aws_profile (str, optional): AWS profile name for credentials
            - tag_key (str, optional): VPC tag key to filter by
            - tag_value (str, optional): VPC tag value to filter by (requires tag_key)
            
    Returns:
        List[TextContent]: JSON response containing:
            - vpcs: List of VPC dictionaries with details
            - total: Total number of VPCs found
            
    Raises:
        Returns error JSON if:
            - AWS credentials not found
            - AWS API errors (permissions, etc.)
            
    Example Response:
        {
            "total": 2,
            "vpcs": [
                {
                    "vpc_id": "vpc-production-001",
                    "cidr_block": "10.0.0.0/16",
                    "tags": {"Environment": "Production", "Network": "Network-A"},
                    "subnets": [...]
                },
                ...
            ]
        }
    """
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    
    aws_region = arguments.get("aws_region")
    aws_profile = arguments.get("aws_profile")
    tag_key = arguments.get("tag_key")
    tag_value = arguments.get("tag_value")
    
    try:
        # Create boto3 session with specified profile/region
        session_kwargs = {}
        if aws_profile:
            session_kwargs['profile_name'] = aws_profile
        
        session = boto3.Session(**session_kwargs)
        
        # Auto-detect region if not specified
        if not aws_region:
            aws_region = session.region_name or os.getenv('AWS_DEFAULT_REGION', 'us-east-1')
        
        # Create EC2 client
        ec2_client = session.client('ec2', region_name=aws_region)
        
        # Build filters for VPC query
        filters = []
        if tag_key:
            if tag_value:
                filters.append({
                    'Name': f'tag:{tag_key}',
                    'Values': [tag_value]
                })
            else:
                filters.append({
                    'Name': 'tag-key',
                    'Values': [tag_key]
                })
        
        # Describe VPCs
        # AWS API requires Filters to be a list (even if empty), not None
        response = ec2_client.describe_vpcs(Filters=filters)
        
        # Process VPCs and get subnet information
        vpcs = []
        for vpc in response.get('Vpcs', []):
            vpc_id = vpc['VpcId']
            cidr_block = vpc.get('CidrBlock', '')
            
            # Extract tags
            tags = {}
            for tag in vpc.get('Tags', []):
                tags[tag['Key']] = tag['Value']
            
            # Get subnets for this VPC
            subnets_response = ec2_client.describe_subnets(
                Filters=[{'Name': 'vpc-id', 'Values': [vpc_id]}]
            )
            subnets = []
            for subnet in subnets_response.get('Subnets', []):
                subnets.append({
                    'subnet_id': subnet['SubnetId'],
                    'cidr_block': subnet.get('CidrBlock', ''),
                    'availability_zone': subnet.get('AvailabilityZone', ''),
                    'tags': {tag['Key']: tag['Value'] for tag in subnet.get('Tags', [])}
                })
            
            vpcs.append({
                'vpc_id': vpc_id,
                'cidr_block': cidr_block,
                'state': vpc.get('State', ''),
                'tags': tags,
                'subnets': subnets,
                'subnet_count': len(subnets)
            })
        
        return [TextContent(
            type="text",
            text=json.dumps({
                "total": len(vpcs),
                "vpcs": vpcs
            }, indent=2)
        )]
    except NoCredentialsError:
        return [TextContent(
            type="text",
            text=json.dumps({
                "error": "AWS credentials not found. Please configure AWS credentials."
            }, indent=2)
        )]
    except ClientError as e:
        return [TextContent(
            type="text",
            text=json.dumps({
                "error": f"AWS API error: {str(e)}"
            }, indent=2)
        )]
    except Exception as e:
        return [TextContent(
            type="text",
            text=json.dumps({"error": str(e)}, indent=2)
        )]


async def handle_tool_call(tool_name: str, arguments: Dict[str, Any]) -> List[TextContent]:
    """
    Route tool calls to appropriate handler functions.
    
    This is the central dispatcher that routes incoming tool calls from the MCP server
    to the correct handler function based on the tool name.
    
    Args:
        tool_name: Name of the tool to execute (must match tool definitions)
        arguments: Dictionary of arguments for the tool call
        
    Returns:
        List[TextContent]: Response from the handler function
        
    Raises:
        Returns error JSON if:
            - Unknown tool name specified
            
    Example:
        tool_name="get_config", arguments={"vpc_id": "vpc-123"}
        -> Routes to handle_get_config()
    """
    # Map tool names to their handler functions
    handlers = {
        "get_config": handle_get_config,
        "query_rules": handle_query_rules,
        "list_vpcs": handle_list_vpcs,
    }
    
    # Get handler for the requested tool
    handler = handlers.get(tool_name)
    
    # Return error if tool name not recognized
    if not handler:
        return [TextContent(
            type="text",
            text=json.dumps({
                "error": f"Unknown tool: {tool_name}"
            }, indent=2)
        )]
    
    # Execute handler and return result
    return await handler(arguments)

