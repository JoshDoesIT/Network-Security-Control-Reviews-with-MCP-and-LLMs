"""
MCP Server Source Package for Network Security Control (NSC) Reviews

This package contains the core implementation of the Network Security Control (NSC) review MCP server.
This lab uses AWS Security Groups and Network ACLs as examples of Network Security Controls.

The architecture is extensible and can be extended to support other NSC types:
- Azure Network Security Groups (NSGs)
- Google Cloud Platform (GCP) Firewall Rules
- Oracle Cloud Infrastructure (OCI) Security Lists
- Traditional on-premises firewalls (Palo Alto, Check Point, Fortinet, etc.)

Package Structure:
    parsers/ - NSC configuration parsers (AWS Security Groups and Network ACLs as examples, extensible for other NSC types)
    tools/   - MCP tool definitions and handlers for NSC queries
"""

__version__ = "0.1.0"
