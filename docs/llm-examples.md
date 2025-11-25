# LLM Usage Examples

This document provides comprehensive examples demonstrating how to use the MCP server with an LLM to perform Network Security Control (NSC) reviews and segmentation testing. The examples use AWS Security Groups and Network ACLs as practical demonstrations of NSC configurations.

## Prerequisites

- AWS credentials configured (see [MCP Setup Guide](mcp-setup.md))
- AWS test environment set up with production and development VPCs (see [AWS Setup Guide](aws-setup.md))
- MCP server installed and running

---

## Example 1: Security Review with Prompt Engineering

### Scenario

Generate a comprehensive, structured NSC security review report using prompt engineering techniques. This example demonstrates how to guide an LLM through multi-step analysis and produce professional, actionable security reports.

### User Query

**User Query:**
```
First, discover the production and development VPCs in this AWS account, then load their 
Network Security Control configurations and perform a comprehensive review. Generate a detailed 
report following this exact structure:

## Report Structure Requirements:

1. **Executive Summary**
   - Total counts by severity (Critical, High, Medium)
   - Overall security posture assessment

2. **Critical Issues** (Severity: Critical)
   - For each issue: title, affected resources, rule details, security risk, immediate remediation steps

3. **High-Risk Issues** (Severity: High)
   - Same format as Critical Issues

4. **Network Segmentation Analysis**
   - Cross-VPC connectivity assessment
   - Segmentation violations identified
   - Comparison of NSC types (instance-level vs subnet-level)

5. **Recommendations**
   - Prioritized remediation actions
   - Best practices recommendations

6. **Positive Findings**
   - Properly configured security controls

## Format Requirements:
- Use markdown formatting
- Use emoji indicators: 🚨 Critical, ⚠️ High, ℹ️ Medium, ✅ Positive
- Include specific resource IDs and rule details
- Provide actionable remediation steps
```

**LLM Process:**
1. **Discovers VPCs**: Calls `list_vpcs` to find production and development VPCs:
   - `{"tool": "list_vpcs", "arguments": {"tag_key": "Environment", "tag_value": "Production"}}`
   - `{"tool": "list_vpcs", "arguments": {"tag_key": "Environment", "tag_value": "Development"}}`
   - Or uses `{"tool": "list_vpcs", "arguments": {}}` and filters by tags in response

2. **Loads Configurations**: Uses discovered VPC IDs to load NSC configurations:
   - `{"tool": "get_config", "arguments": {"vpc_id": "<discovered-production-vpc-id>", "load_network_acls": true}}`
   - `{"tool": "get_config", "arguments": {"vpc_id": "<discovered-development-vpc-id>", "load_network_acls": true}}`

3. **Analyzes Rules**: Calls `query_rules` multiple times with strategic queries:
   - `{"source": "0.0.0.0/0"}` - Find overly permissive rules (finds SSH on Dev-Database-SG, HTTP on Dev-Application-SG, HTTPS on web tiers)
   - `{"source": "10.0.0.0/16"}` and `{"source": "10.1.0.0/16"}` - Find cross-VPC violations
   - `{"port": 22}` - Find SSH exposure
   - `{"port": 80}` - Find HTTP exposure
   - `{"tag_key": "Environment", "tag_value": "Development"}` - Environment-specific analysis

4. **Generates Report**: Analyzes all findings and generates structured report

### Key Prompt Engineering Techniques Demonstrated

1. **Structured Output**: Define exact report format upfront
2. **Severity Classification**: Guide LLM to categorize issues by risk level
3. **Multi-Step Analysis**: LLM breaks down complex review into focused queries
4. **Actionable Output**: Request specific remediation steps, not just findings
5. **Format Consistency**: Specify markdown and emoji usage for professional reports

### Example Output Excerpt

I ran this with Claude Desktop and received some rather impressive results:

[Example 1 Claude Results](llm-examples-1-claude.md)

---

## Example 2: Multi-Layer NSC Segmentation Analysis

### Scenario

Analyze network segmentation across multiple NSC layers (Security Groups and Network ACLs) to identify how different NSC types interact and detect violations that may exist at one layer but not another.

### User Query

**User Query:**
```
First, discover the production and development VPCs in this AWS account. Then analyze 
network segmentation between production (Network-A, 10.0.0.0/16) and development 
(Network-B, 10.1.0.0/16) environments across all NSC layers:

1. **Instance-Level Analysis** (Security Groups)
   - Check for cross-VPC security group references
   - Verify tier-based isolation within each VPC

2. **Subnet-Level Analysis** (Network ACLs)
   - Check for cross-VPC CIDR rules
   - Identify subnet-level violations

3. **Layer Interaction Analysis**
   - Compare findings between layers
   - Identify where one layer overrides another
   - Explain security implications

Report findings with clear layer separation and interaction analysis.
```

**LLM Process:**
1. **Discovers VPCs**: Calls `list_vpcs` to identify production and development VPCs:
   - Uses tag filtering: `{"tool": "list_vpcs", "arguments": {"tag_key": "Environment", "tag_value": "Production"}}`
   - Or discovers all VPCs and identifies by tags in response

2. **Loads Multi-Layer Configuration**: Uses discovered VPC IDs to load Security Groups and Network ACLs:
   - `{"tool": "get_config", "arguments": {"vpc_id": "<discovered-production-vpc-id>", "load_network_acls": true}}`
   - `{"tool": "get_config", "arguments": {"vpc_id": "<discovered-development-vpc-id>", "load_network_acls": true}}`

3. **Instance-Level Analysis (Security Groups)**: 
   - Queries by environment tags to analyze Security Group rules
   - Finds: ⚠️ Security Groups use CIDR blocks that could allow cross-VPC traffic if VPCs are peered:
     - Production-Application-SG allows HTTPS (port 443) from `10.0.0.0/8` CIDR block, which includes both Production VPC (10.0.0.0/16) and Development VPC (10.1.0.0/16)

4. **Subnet-Level Analysis (Network ACLs)**:
   - Queries for cross-VPC CIDR blocks: `{"source": "10.0.0.0/16"}` and `{"source": "10.1.0.0/16"}`
   - Finds: 🚨 Network ACL violations allowing bidirectional cross-VPC traffic:
     - Production NACL: ingress and egress rules allowing traffic to/from Development VPC (10.1.0.0/16)
     - Development NACL: ingress and egress rules allowing traffic to/from Production VPC (10.0.0.0/16)

5. **Layer Interaction Analysis**:
   - Compares findings: Security Groups enforce isolation, but Network ACLs override it

### Key Prompt Engineering Techniques

1. **Structured Layer Analysis**: Explicitly separate instance-level and subnet-level analysis
2. **Comparative Analysis**: Guide LLM to compare findings across layers
3. **Interaction Explanation**: Request explanation of how layers interact
4. **Clear Reporting**: Specify layer separation in output format

### Example Output Excerpt

I also ran this one with Claude Desktop. See results:

[Example 1 Claude Results](llm-examples-2-claude.md)

---

## Example 3: Advanced Query Patterns & Analysis Techniques

### Scenario

Demonstrate advanced prompt engineering techniques for iterative query refinement, comparative analysis, and multi-step reasoning to uncover complex security issues.

### Technique 1: Iterative Query Refinement

Start broad, then narrow down based on findings:

**Initial Query:**
```
Find all overly permissive rules in the development environment
```

**LLM Process:**
1. **Queries Development Environment**: `{"tag_key": "Environment", "tag_value": "Development"}`
2. **Identifies**: Multiple overly permissive rules
3. **Refinement Prompt**: "Focus on database tier rules specifically"
4. **Queries Database Tier**: `{"tag_key": "Tier", "tag_value": "Database"}`
5. **Further Refinement**: "Show only rules allowing SSH access"
6. **Queries SSH on Database**: `{"port": 22, "tag_key": "Tier", "tag_value": "Database"}`

**Key Technique**: Guide LLM to progressively narrow scope based on initial findings.

### Technique 2: Comparative Analysis

Compare configurations across environments:

**User Query:**
```
Discover the production and development VPCs, then compare the security posture of their 
database security groups. Identify differences in ingress rules, egress rules, and overall 
security configuration.
```

**LLM Process:**
1. **Discovers VPCs**: Calls `list_vpcs` to find production and development VPCs
2. **Loads Configurations**: Loads Security Groups and Network ACLs from discovered VPCs
3. **Queries Production Database**: `{"tag_key": "Environment", "tag_value": "Production", "tag_key": "Tier", "tag_value": "Database"}`
4. **Queries Development Database**: `{"tag_key": "Environment", "tag_value": "Development", "tag_key": "Tier", "tag_value": "Database"}`
5. **Compares Findings**: Side-by-side comparison highlighting differences and security implications


### Technique 3: Multi-Step Reasoning Chain

Guide LLM through logical analysis steps:

**User Query:**
```
Discover all VPCs in this account, then analyze the attack surface: Start by identifying 
all internet-facing services, then determine which ones have overly permissive rules, 
and finally assess the potential impact if these services were compromised.
```

**LLM Process:**
1. **Discovers VPCs**: Uses `list_vpcs` tool to find all VPCs
2. **Loads Configurations**: Loads NSC configurations from discovered VPCs
3. **Finds Internet-Facing Rules**: Queries `{"source": "0.0.0.0/0"}` to identify internet-facing services
4. **Analyzes Permissiveness**: Examines each finding for overly permissive ports and protocols
5. **Traces Attack Paths**: Determines what can be accessed from each compromised service
6. **Assesses Impact**: Evaluates data exposure and lateral movement potential


### Technique 4: Hypothesis-Driven Analysis

Form hypotheses and test them:

**User Query:**
```
Test this hypothesis: "The development environment has weaker security controls 
than production." Query the rules to find evidence supporting or refuting this claim.
```

**LLM Process:**
1. **Formulates Testable Queries**: Creates queries based on hypothesis (e.g., overly permissive rules, internet exposure)
2. **Queries Both Environments**: Uses same criteria for both production and development
3. **Compares Results**: Performs side-by-side comparison
4. **Provides Evidence-Based Conclusion**: Supports or refutes hypothesis with specific findings

### Advanced Prompt Patterns

**Pattern 1: Conditional Analysis**
```
If you find rules allowing SSH from 0.0.0.0/0, then analyze what other services 
those security groups protect and assess the blast radius of a compromise.
```

**Pattern 2: Prioritized Investigation**
```
Investigate in this order: 1) Critical services (databases), 2) Application tiers, 
3) Web tiers. For each, identify overly permissive rules first, then analyze 
egress rules.
```

**Pattern 3: Context-Aware Queries**
```
Given that this is a development environment, identify rules that would be 
acceptable in dev but unacceptable in production. Explain the security trade-offs.
```

---

## Key Learning Points

### Prompt Engineering Techniques

1. **Structured Output**: Define exact report format upfront for consistent results
2. **Multi-Step Analysis**: Break complex reviews into explicit reasoning steps
3. **Iterative Refinement**: Start broad, then narrow queries based on findings
4. **Comparative Analysis**: Compare configurations across environments or layers

### NSC Analysis Principles

- **Multi-Layer Review**: Check both Security Groups (instance-level) and Network ACLs (subnet-level)
- **Egress Analysis**: Don't overlook outbound rules, they're critical for security
- **Tag-Based Filtering**: Use tags to analyze by environment, tier, or network
- **Cross-VPC Detection**: Query for CIDR blocks from other VPCs to find segmentation violations

## Additional Possible Queries

Here are some additional LLM questions you could apply prompt engineering techniques to:

- **Risk Scoring**: "Calculate a risk score for each security group based on overly permissive rules, internet exposure, and egress restrictions"
- **Remediation Planning**: "Generate a prioritized remediation plan with specific steps, resource IDs, and estimated effort"
- **Compliance Analysis**: "Compare this configuration against AWS security best practices and identify compliance gaps"
- **Attack Surface Analysis**: "Identify all internet-facing services and trace potential attack paths from each"
- **Comparative Review**: "Compare production and development security postures and highlight differences"