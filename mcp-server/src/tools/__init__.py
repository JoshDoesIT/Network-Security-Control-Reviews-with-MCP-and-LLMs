"""
MCP Tool Definitions for Network Security Control (NSC) Queries

This package contains the MCP tool definitions that enable LLMs to interact
with Network Security Control (NSC) configurations. This lab uses AWS Security Groups
and Network ACLs as examples of NSCs.

Tools are defined in nsc_tools.py and handle:
    - Loading NSC configurations from AWS (Security Groups and Network ACLs as examples)
    - Querying NSC rules by various criteria
    - Getting NSC configuration summaries
    - Listing VPCs to discover NSC resources
    - Extensible for other NSC types (Azure NSGs, GCP Firewall Rules, etc.)
"""
