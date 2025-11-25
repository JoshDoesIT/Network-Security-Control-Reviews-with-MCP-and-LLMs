"""
MCP Server for Network Security Control (NSC) Reviews

This module implements the main MCP (Model Context Protocol) server that provides
LLMs with tools to query and analyze Network Security Control (NSC) configurations.
This lab uses AWS Security Groups and Network ACLs as examples of Network Security Controls.

The server runs locally and communicates with LLM clients via stdio (standard input/output).
It provides read-only access to NSC configurations (AWS Security Groups and Network ACLs) loaded directly from AWS.

Architecture:
    LLM Client (stdio) <-> MCP Server <-> AWS API (HTTPS)

NSC Examples:
    - AWS Security Groups: Stateful, instance-level firewalls
    - AWS Network ACLs: Stateless, subnet-level firewalls

Extensibility:
    This server demonstrates NSC reviews using AWS as an example. Additional NSC parsers can be added for:
    - Azure Network Security Groups (NSGs)
    - Google Cloud Platform (GCP) Firewall Rules
    - Oracle Cloud Infrastructure (OCI) Security Lists
    - Traditional on-premises firewalls (Palo Alto, Check Point, Fortinet, etc.)

Usage:
    Run this module directly to start the MCP server:
        python mcp-server/server.py
    
    Or configure it in your MCP client (Claude Desktop, Cursor, etc.)
"""

import asyncio
import sys
import os
import traceback
from pathlib import Path

# Add the mcp-server directory to Python path so imports work correctly
# This ensures the server can find src.tools.nsc_tools regardless of where it's run from
_server_dir = Path(__file__).parent.absolute()
if str(_server_dir) not in sys.path:
    sys.path.insert(0, str(_server_dir))

from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

try:
    from src.tools.nsc_tools import get_nsc_tools, handle_tool_call
except Exception as e:
    print(f"Error importing nsc_tools: {e}", file=sys.stderr)
    print(f"Python path: {sys.path}", file=sys.stderr)
    print(f"Server directory: {_server_dir}", file=sys.stderr)
    traceback.print_exc(file=sys.stderr)
    sys.exit(1)


# Create MCP server instance with unique identifier
# This identifier is used by MCP clients to identify this server
server = Server("nsc-review-mcp")


@server.list_tools()
async def handle_list_tools() -> list[Tool]:
    """
    Handle tool listing requests from MCP clients.
    
    This handler is called when the LLM client requests the list of available tools.
    Returns the complete list of AWS Security Groups analysis tools.
    
    Returns:
        list[Tool]: List of available MCP tools for AWS Security Groups configuration queries
        
    Example:
        When an LLM asks "What tools are available?", this function returns
        the tool definitions for get_config, query_rules, list_vpcs, etc.
    """
    return get_nsc_tools()


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict) -> list[TextContent]:
    """
    Handle tool execution requests from MCP clients.
    
    This handler routes tool calls from the LLM to the appropriate handler function.
    All tool calls are asynchronous and return JSON-formatted responses.
    
    Args:
        name: Name of the tool to execute (e.g., "get_config", "query_rules")
        arguments: Dictionary of arguments for the tool call
        
    Returns:
        list[TextContent]: List of text content responses (typically one JSON response)
        
    Raises:
        Tool execution errors are caught and returned as error JSON responses
        
    Example:
        LLM calls: {"tool": "get_config", "arguments": {"vpc_id": "vpc-123"}}
        This function routes to handle_get_config() and returns the result.
    """
    return await handle_tool_call(name, arguments)


async def main():
    """
    Main entry point for the MCP server.
    
    Sets up stdio communication channels and runs the MCP server.
    The server communicates with LLM clients via standard input/output streams.
    
    Flow:
        1. Create stdio server (reads from stdin, writes to stdout)
        2. Initialize server with default options
        3. Run server loop (handles incoming requests)
        
    The server runs until the client disconnects or the process is terminated.
    """
    # stdio_server() creates async streams for stdin/stdout communication
    # This is the standard way MCP servers communicate with clients
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,      # Input stream from LLM client
            write_stream,     # Output stream to LLM client
            server.create_initialization_options()  # Server capabilities and metadata
        )


if __name__ == "__main__":
    # Run the async main function
    # asyncio.run() creates an event loop and runs the coroutine
    try:
        asyncio.run(main())
    except Exception as e:
        print(f"Error running MCP server: {e}", file=sys.stderr)
        traceback.print_exc(file=sys.stderr)
        sys.exit(1)
