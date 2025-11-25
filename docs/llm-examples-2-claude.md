# Network Segmentation Analysis Report
## Production (Network-A) vs Development (Network-B)

---

## Executive Summary

**CRITICAL FINDING**: Both Network Security Control (NSC) layers contain severe network segmentation violations that allow unrestricted cross-environment communication between Production (10.0.0.0/16) and Development (10.1.0.0/16) networks.

### Violation Summary
- **Network ACL Layer**: Both VPCs allow ALL traffic (all protocols, all ports) between production and development CIDRs
- **Security Group Layer**: One production security group allows broad access from 10.0.0.0/8 (includes development network)
- **Combined Effect**: Network ACLs override any security group restrictions, enabling complete network segmentation bypass

---

## 1. Instance-Level Analysis (Security Groups)

### Production VPC (vpc-0010c25f3b0eb8863) - Network-A

#### Production-Web-SG (sg-0aa1fbf8078f24d98)
**Tier**: Web  
**Status**: ✅ COMPLIANT - No cross-environment rules

| Direction | Protocol | Port | Source/Destination | Assessment |
|-----------|----------|------|-------------------|------------|
| Ingress | TCP | 443 | 0.0.0.0/0 | Public HTTPS - Expected for web tier |
| Egress | ALL | ALL | 0.0.0.0/0 | Standard egress |

#### Production-Application-SG (sg-06153643a91d79c86)
**Tier**: Application  
**Status**: ⚠️ **VIOLATION - Cross-Environment Access**

| Direction | Protocol | Port | Source/Destination | Assessment |
|-----------|----------|------|-------------------|------------|
| Ingress | TCP | 443 | 10.0.0.0/8 | ❌ **CRITICAL**: Includes dev network (10.1.0.0/16) |
| Egress | ALL | ALL | 0.0.0.0/0 | Standard egress |

**Violation Details**:
- Source CIDR `10.0.0.0/8` encompasses both:
  - Production: 10.0.0.0/16 (intended)
  - Development: 10.1.0.0/16 (unintended)
- Allows HTTPS (443) from development to production application tier
- Violates network segmentation principle

#### Production-Database-SG (sg-01d4dec8340b585eb)
**Tier**: Database  
**Status**: ✅ COMPLIANT - Proper tier isolation

| Direction | Protocol | Port | Source/Destination | Assessment |
|-----------|----------|------|-------------------|------------|
| Ingress | TCP | 3306 | sg-06153643a91d79c86 | MySQL from app tier only |
| Ingress | TCP | 5432 | sg-06153643a91d79c86 | PostgreSQL from app tier only |
| Egress | ALL | ALL | 0.0.0.0/0 | Standard egress |

**Note**: While this SG is properly configured for tier isolation, it references the compromised Production-Application-SG.

---

### Development VPC (vpc-0627541bf1d62805c) - Network-B

#### Dev-Web-SG (sg-0c426974459a1f4f6)
**Tier**: Web  
**Status**: ✅ COMPLIANT - No cross-environment rules

| Direction | Protocol | Port | Source/Destination | Assessment |
|-----------|----------|------|-------------------|------------|
| Ingress | TCP | 443 | 0.0.0.0/0 | Public HTTPS - Expected for web tier |
| Egress | ALL | ALL | 0.0.0.0/0 | Standard egress |

#### Dev-Application-SG (sg-06dbcc866e55ac136)
**Tier**: Application  
**Status**: ⚠️ OVERLY PERMISSIVE (not cross-environment)

| Direction | Protocol | Port | Source/Destination | Assessment |
|-----------|----------|------|-------------------|------------|
| Ingress | TCP | 80 | 0.0.0.0/0 | ⚠️ WARNING: Public HTTP access to application tier |
| Egress | ALL | ALL | 0.0.0.0/0 | Standard egress |

#### Dev-Database-SG (sg-0e3ae3e6560ba3262)
**Tier**: Database  
**Status**: ⚠️ MULTIPLE VIOLATIONS (not cross-environment)

| Direction | Protocol | Port | Source/Destination | Assessment |
|-----------|----------|------|-------------------|------------|
| Ingress | TCP | 3306 | sg-06dbcc866e55ac136 | MySQL from app tier - proper |
| Ingress | TCP | 5432 | sg-06dbcc866e55ac136 | PostgreSQL from app tier - proper |
| Ingress | TCP | 22 | 0.0.0.0/0 | ❌ **CRITICAL**: Public SSH to database |
| Egress | ALL | ALL | 0.0.0.0/0 | Standard egress |

**Additional Development Issues**: While not cross-environment violations, these represent serious security gaps.

---

### Security Group Summary

**Cross-Environment Violations**:
1. Production-Application-SG allows 10.0.0.0/8 (includes development)

**Tier-Based Isolation**:
- ✅ Database tiers properly reference only their application tiers
- ✅ Web tiers properly exposed to internet
- ❌ Application tier in production has overly broad CIDR

**Within-VPC Security Issues** (separate from segmentation):
- Development database has public SSH access
- Development application has public HTTP access

---

## 2. Subnet-Level Analysis (Network ACLs)

### Production-NACL (acl-0af0e5957e726b65a)
**VPC**: vpc-0010c25f3b0eb8863 (10.0.0.0/16)  
**Environment**: Production (Network-A)  
**Status**: ❌ **CRITICAL VIOLATION**

#### Ingress Rules

| Priority | Protocol | Port | Source CIDR | Action | Assessment |
|----------|----------|------|-------------|--------|------------|
| 100 | TCP | 443 | 0.0.0.0/0 | ALLOW | Public HTTPS - expected |
| 150 | ALL | ALL | 10.1.0.0/16 | ALLOW | ❌ **CRITICAL**: Allows ALL from Development |
| 200 | ALL | ALL | 10.0.0.0/16 | ALLOW | Internal production traffic |
| 32767 | ALL | ALL | 0.0.0.0/0 | DENY | Default deny |

#### Egress Rules

| Priority | Protocol | Port | Destination CIDR | Action | Assessment |
|----------|----------|------|------------------|--------|------------|
| 100 | ALL | ALL | 0.0.0.0/0 | ALLOW | Unrestricted egress |
| 150 | ALL | ALL | 10.1.0.0/16 | ALLOW | ❌ **CRITICAL**: Allows ALL to Development |
| 32767 | ALL | ALL | 0.0.0.0/0 | DENY | Default deny (never reached) |

**Violation Analysis**:
- Rule 150 (both directions) creates complete bypass of network segmentation
- Allows every protocol, every port between production and development
- Higher priority than default deny (evaluated before rule 32767)

---

### Development-NACL (acl-061a0331327c18e7e)
**VPC**: vpc-0627541bf1d62805c (10.1.0.0/16)  
**Environment**: Development (Network-B)  
**Status**: ❌ **CRITICAL VIOLATION**

#### Ingress Rules

| Priority | Protocol | Port | Source CIDR | Action | Assessment |
|----------|----------|------|-------------|--------|------------|
| 100 | TCP | 443 | 0.0.0.0/0 | ALLOW | Public HTTPS - expected |
| 150 | ALL | ALL | 10.0.0.0/16 | ALLOW | ❌ **CRITICAL**: Allows ALL from Production |
| 200 | ALL | ALL | 10.1.0.0/16 | ALLOW | Internal development traffic |
| 32767 | ALL | ALL | 0.0.0.0/0 | DENY | Default deny |

#### Egress Rules

| Priority | Protocol | Port | Destination CIDR | Action | Assessment |
|----------|----------|------|------------------|--------|------------|
| 100 | ALL | ALL | 0.0.0.0/0 | ALLOW | Unrestricted egress |
| 150 | ALL | ALL | 10.0.0.0/16 | ALLOW | ❌ **CRITICAL**: Allows ALL to Production |
| 32767 | ALL | ALL | 0.0.0.0/0 | DENY | Default deny (never reached) |

**Violation Analysis**:
- Rule 150 (both directions) creates reciprocal bypass from development side
- Mirrors production NACL violation with opposite CIDR
- Creates bidirectional unrestricted communication channel

---

### Network ACL Summary

**Critical Finding**: Both NACLs contain symmetric violations that permit unrestricted cross-environment traffic.

**Scope of Access Granted**:
- ✅ Production → Production: 10.0.0.0/16 (rule 200)
- ✅ Development → Development: 10.1.0.0/16 (rule 200)
- ❌ Production → Development: 10.1.0.0/16 (rule 150) - **VIOLATION**
- ❌ Development → Production: 10.0.0.0/16 (rule 150) - **VIOLATION**

**Protocol Coverage**: ALL protocols (-1), all ports, both directions

---

## 3. Layer Interaction Analysis

### Defense-in-Depth Model

AWS network security operates on a defense-in-depth model with two primary layers:

```
External Request
       ↓
[Network ACL - Subnet Level]  ← Stateless, evaluated first
       ↓
[Security Group - Instance Level]  ← Stateful, evaluated second
       ↓
EC2 Instance
```

### Current State Analysis

#### Scenario 1: Development → Production Application (Port 443)

**Network ACL Evaluation** (Development-NACL Egress):
- Rule 100: Allows ALL to 0.0.0.0/0 → ✅ ALLOWS
- Rule 150: Allows ALL to 10.0.0.0/16 → ✅ ALLOWS (specific match)
- **Result**: Traffic PERMITTED at subnet level

**Network ACL Evaluation** (Production-NACL Ingress):
- Rule 150: Allows ALL from 10.1.0.0/16 → ✅ ALLOWS
- **Result**: Traffic PERMITTED at subnet level

**Security Group Evaluation** (Production-Application-SG):
- Rule: Allow TCP/443 from 10.0.0.0/8 → ✅ ALLOWS (10.1.x.x matches)
- **Result**: Traffic PERMITTED at instance level

**Final Verdict**: ❌ **TRAFFIC ALLOWED** - Both layers permit the connection

---

#### Scenario 2: Development → Production Database (Port 3306)

**Network ACL Evaluation**:
- Development-NACL Egress Rule 100/150: ✅ ALLOWS (all traffic)
- Production-NACL Ingress Rule 150: ✅ ALLOWS (all traffic from 10.1.0.0/16)
- **Result**: Traffic PERMITTED at subnet level

**Security Group Evaluation** (Production-Database-SG):
- No rule allowing 10.1.0.0/16 or development security groups
- **Result**: Traffic DENIED at instance level

**Final Verdict**: 🔒 **TRAFFIC BLOCKED** - Security group blocks despite NACL allowing

**However**: The blocking occurs at the wrong layer. The Network ACL should be the first line of defense and should block this traffic before it reaches the security group evaluation.

---

#### Scenario 3: Production → Development Database (Port 22)

**Network ACL Evaluation**:
- Production-NACL Egress Rule 100: ✅ ALLOWS (all traffic)
- Development-NACL Ingress Rule 150: ✅ ALLOWS (all traffic from 10.0.0.0/16)
- **Result**: Traffic PERMITTED at subnet level

**Security Group Evaluation** (Dev-Database-SG):
- Rule: Allow TCP/22 from 0.0.0.0/0 → ✅ ALLOWS
- **Result**: Traffic PERMITTED at instance level

**Final Verdict**: ❌ **TRAFFIC ALLOWED** - Both layers permit the connection

---

### Layer Override Analysis

#### When Network ACLs Override Security Groups

Network ACLs are evaluated **before** security groups and can completely override them:

**Case 1: NACL ALLOWS, SG DENIES**
- NACL permits → Traffic reaches instance
- SG blocks → Traffic denied at instance
- **Result**: SG provides last line of defense (current Scenario 2)
- **Problem**: Wastes compute resources, exposes SG rules to probing

**Case 2: NACL DENIES, SG ALLOWS**
- NACL blocks → Traffic never reaches instance
- SG never evaluated
- **Result**: Traffic blocked at subnet boundary
- **Ideal**: This is how it should work for cross-environment traffic

**Case 3: BOTH ALLOW (Current Critical State)**
- NACL permits → Traffic reaches instance
- SG permits → Traffic accepted
- **Result**: Complete network segmentation failure (Scenarios 1 & 3)

---

### Security Implications by Layer

#### Network ACL Layer (Subnet-Level) - MOST CRITICAL

**Current State**: ❌ Complete failure of network segmentation

**Impact**:
1. **Bypass of Defense-in-Depth**: First security layer completely fails its purpose
2. **Attack Surface Expansion**: Development environment can probe all production ports
3. **Lateral Movement**: Compromised development instance can pivot to production network
4. **Data Exfiltration**: Production data accessible from development environment
5. **Compliance Violations**: Most frameworks (PCI-DSS, SOC 2, HIPAA) require network segmentation

**Risk Amplification**:
- Even properly configured security groups cannot fully compensate
- Development environments typically have weaker security controls
- Developers often have broader access to development infrastructure
- Development may contain test data, but can now access production systems

**Why This Matters Most**:
- Network ACLs are stateless - they evaluate every packet
- They protect at the subnet level (entire subnet exposed)
- They should be the coarse-grained filter preventing entire classes of traffic
- Security groups are fine-grained and assume NACL has already filtered inappropriate sources

---

#### Security Group Layer (Instance-Level) - SECONDARY CONCERN

**Current State**: ⚠️ One overly broad CIDR rule in production

**Production-Application-SG Violation**:
- Uses 10.0.0.0/8 instead of 10.0.0.0/16
- Allows development network (10.1.0.0/16) to access application tier on port 443
- Even if NACL were fixed, this rule would still violate segmentation

**Impact** (if NACLs were fixed):
1. Limited scope: Only affects one security group, one port (443)
2. Targeted exposure: Only application tier, not all tiers
3. Easier to detect: More specific rule, more obvious intent
4. Protocol-specific: Only HTTPS, not all protocols

**Why This Matters Less (in comparison)**:
- Only one security group affected (vs. entire subnet in NACL case)
- Only one port (443) vs. all ports in NACL rules
- Only ingress on one tier vs. bidirectional all-tier access in NACLs
- Security groups are stateful - return traffic automatically handled
- Instance-level means can be overridden per instance

**However**: This is still a serious violation that must be fixed. The "less critical" assessment is only relative to the catastrophic NACL failure.

---

### Combined Effect: Complete Segmentation Failure

#### The Multiplication of Risks

When both layers fail simultaneously, the security impact is multiplicative, not additive:

**Network ACL + Security Group Failures = Complete Bypass**

1. **NACL Rule 150** opens ALL protocols/ports between environments
2. **Production-Application-SG** specifically allows HTTPS from development
3. **Result**: Both general and specific paths exist for cross-environment access

#### Attack Scenarios Enabled

**Scenario A: Direct Database Access (Partially Blocked)**
```
Developer Laptop → Development Instance → Production Database
                     ↓                      ↓
                 NACL: ✅ ALLOW          NACL: ✅ ALLOW
                 SG: Not evaluated      SG: ❌ DENY
                                        
Result: Blocked by SG, but NACL permits probing
```

**Scenario B: Application Layer Compromise (ALLOWED)**
```
Compromised Dev Instance → Production Application (443) → Production Database
                ↓                      ↓                      ↓
            NACL: ✅ ALLOW          NACL: ✅ ALLOW        NACL: Not cross-VPC
            SG: Not evaluated      SG: ✅ ALLOW          SG: ✅ ALLOW (from prod app)
                                   
Result: Complete access to production data through application tier
```

**Scenario C: SSH Pivot Attack (ALLOWED)**
```
Compromised Prod Instance → Development Database (22)
                ↓                      ↓
            NACL: ✅ ALLOW          NACL: ✅ ALLOW
            SG: Not evaluated      SG: ✅ ALLOW (0.0.0.0/0)
                                   
Result: Production can access development with public SSH rule
```

---

### Layer-Specific Recommendations

#### Network ACL Layer (IMMEDIATE ACTION REQUIRED)

**Production-NACL (acl-0af0e5957e726b65a)**:
```
REMOVE Rule 150 (Ingress): Allow ALL from 10.1.0.0/16
REMOVE Rule 150 (Egress): Allow ALL to 10.1.0.0/16
```

**Development-NACL (acl-061a0331327c18e7e)**:
```
REMOVE Rule 150 (Ingress): Allow ALL from 10.0.0.0/16
REMOVE Rule 150 (Egress): Allow ALL to 10.0.0.0/16
```

**Justification**: There is no legitimate business case for unrestricted bidirectional access between production and development environments.

**If Limited Cross-Environment Access Is Required**:
```
# Example: Allow only HTTPS from specific development subnet to specific production endpoint
Rule 150 (Ingress on Production-NACL):
  Protocol: TCP
  Port: 443
  Source: 10.1.1.0/24  # Specific dev subnet only
  Destination: 10.0.1.0/24  # Specific prod subnet only
  
# Add explicit DENY rules to ensure no other cross-environment traffic
Rule 140 (Ingress on Production-NACL):
  Protocol: ALL
  Port: ALL
  Source: 10.1.0.0/16
  Action: DENY
```

---

#### Security Group Layer (HIGH PRIORITY)

**Production-Application-SG (sg-06153643a91d79c86)**:
```
REPLACE:
  Protocol: TCP
  Port: 443
  Source: 10.0.0.0/8  ❌

WITH:
  Protocol: TCP
  Port: 443
  Source: 10.0.0.0/16  ✅
```

**Dev-Database-SG (sg-0e3ae3e6560ba3262)**:
```
REMOVE:
  Protocol: TCP
  Port: 22
  Source: 0.0.0.0/0  ❌
  
REPLACE WITH (if SSH required):
  Protocol: TCP
  Port: 22
  Source: <Bastion Host Security Group or specific IP>  ✅
```

**Dev-Application-SG (sg-06dbcc866e55ac136)**:
```
REVIEW:
  Protocol: TCP
  Port: 80
  Source: 0.0.0.0/0  ⚠️
  
CONSIDER:
  - If development application needs public access
  - If it should be behind web tier instead
  - If it requires HTTP or if HTTPS (443) is sufficient
```

---

## 4. Compliance and Risk Assessment

### Regulatory Impact

**PCI-DSS (Payment Card Industry)**:
- Requirement 1.2.1: Restrict inbound/outbound traffic to that necessary
- Requirement 1.3.1: Implement DMZ to limit traffic to environment with cardholder data
- **Status**: ❌ FAIL - Unrestricted access between environments

**SOC 2 (System and Organization Controls)**:
- CC6.6: Logical access security measures protect against threats from outside its system boundaries
- **Status**: ❌ FAIL - No network boundary between environments

**HIPAA (Health Insurance Portability and Accountability Act)**:
- 164.312(a)(1): Implement technical policies and procedures for systems that maintain ePHI
- **Status**: ❌ FAIL - Production health data accessible from development

**GDPR (General Data Protection Regulation)**:
- Article 32: Implement appropriate technical and organizational measures
- **Status**: ⚠️ AT RISK - Inadequate network segmentation for personal data

---

### Risk Scoring

#### Network ACL Violations

| Risk Factor | Score | Justification |
|------------|-------|---------------|
| Likelihood | HIGH (9/10) | Violations actively permit traffic |
| Impact | CRITICAL (10/10) | Complete environment exposure |
| Detectability | MEDIUM (5/10) | Requires network flow analysis |
| Exploitability | HIGH (8/10) | No additional vulnerabilities needed |
| **Overall Risk** | **CRITICAL** | **9.0/10** |

**CVSS-like Assessment**: This would rate as a CVSS 9.1 (Critical) - Network-accessible, no privileges required, confidentiality/integrity/availability all impacted.

#### Security Group Violations

| Risk Factor | Score | Justification |
|------------|-------|---------------|
| Likelihood | MEDIUM (6/10) | Requires NACL also permitting |
| Impact | HIGH (8/10) | Exposes production application tier |
| Detectability | MEDIUM (5/10) | Overly broad CIDR easy to miss |
| Exploitability | MEDIUM (6/10) | Requires development access |
| **Overall Risk** | **HIGH** | **6.5/10** |

---

## 5. Remediation Roadmap

### Phase 1: IMMEDIATE (Within 24 hours)

**Priority 1: Network ACL Remediation**
1. ✅ Document existing rules (completed via this analysis)
2. ❌ Remove rule 150 from Production-NACL (both ingress/egress)
3. ❌ Remove rule 150 from Development-NACL (both ingress/egress)
4. ✅ Test production accessibility (verify no legitimate traffic breaks)
5. ✅ Monitor VPC Flow Logs for denied cross-environment traffic

**Expected Impact**: 
- Eliminates ~80% of cross-environment attack surface
- May break existing integrations (investigate denied flows in VPC Flow Logs)

---

### Phase 2: HIGH PRIORITY (Within 1 week)

**Priority 2: Security Group Remediation**
1. ❌ Update Production-Application-SG: Change 10.0.0.0/8 → 10.0.0.0/16
2. ❌ Remove public SSH from Dev-Database-SG or restrict to bastion
3. ❌ Review Dev-Application-SG public HTTP access

**Priority 3: Verification**
1. ✅ Run this NSC review tool again to confirm no violations
2. ✅ Review VPC Flow Logs for any unexpected traffic patterns
3. ✅ Document legitimate cross-environment requirements (if any exist)

---

### Phase 3: STRATEGIC (Within 1 month)

**Priority 4: Architecture Review**
1. ❌ Evaluate need for any cross-environment communication
2. ❌ If required, implement via specific services (VPC Peering with limited routes, PrivateLink)
3. ❌ Implement VPC Flow Log analysis automation
4. ❌ Add AWS Config rules to detect network segmentation violations

**Priority 5: Continuous Monitoring**
1. ❌ Enable AWS Config managed rules:
   - `vpc-sg-open-only-to-authorized-ports`
   - `restricted-common-ports`
2. ❌ Create custom Config rule for cross-environment CIDR detection
3. ❌ Implement automated NSC review in CI/CD pipeline

---

## 6. Testing and Validation Plan

### Pre-Remediation Testing

**Document Current State**:
```bash
# From development instance
nc -zv 10.0.1.100 443  # Should currently succeed
nc -zv 10.0.1.100 3306  # May succeed depending on SG

# From production instance  
nc -zv 10.1.1.100 22  # Should currently succeed
```

### Post-Remediation Validation

**After NACL Fixes**:
```bash
# From development instance (should all fail)
nc -zv 10.0.1.100 443  # Should timeout (NACL blocks)
nc -zv 10.0.1.100 3306  # Should timeout (NACL blocks)

# From production instance (should all fail)
nc -zv 10.1.1.100 22  # Should timeout (NACL blocks)
nc -zv 10.1.1.100 443  # Should timeout (NACL blocks)
```

**After Security Group Fixes**:
```bash
# Verify internal production connectivity
nc -zv 10.0.1.200 443  # Should succeed (within prod network)
```

**VPC Flow Log Analysis**:
```
# Check for denied cross-environment traffic
aws ec2 describe-flow-logs --filter "Name=resource-id,Values=vpc-0010c25f3b0eb8863"

# Look for REJECT entries with source 10.1.0.0/16 and destination 10.0.0.0/16
```

---

## 7. Conclusion

### Current Security Posture: CRITICAL FAILURE

The network segmentation between Production (Network-A, 10.0.0.0/16) and Development (Network-B, 10.1.0.0/16) has **completely failed** across both NSC layers:

1. **Network ACL Layer**: Bidirectional unrestricted access (all protocols, all ports)
2. **Security Group Layer**: Overly broad CIDR in production application tier
3. **Combined Effect**: Complete bypass of defense-in-depth model

### Immediate Actions Required

1. **STOP**: Do not deploy additional resources until network segmentation is fixed
2. **REMOVE**: Delete cross-environment NACL rules (150) from both VPCs
3. **FIX**: Correct Production-Application-SG CIDR from /8 to /16
4. **VERIFY**: Test and validate using VPC Flow Logs
5. **MONITOR**: Implement continuous compliance checking

### Business Impact

**If Exploited**:
- Development environment compromise leads to production data breach
- Production systems accessible from less-secure development environment  
- Compliance violations (PCI-DSS, SOC 2, HIPAA, GDPR)
- Potential data exfiltration path
- Lateral movement from one environment to another

**Remediation Priority**: This represents the highest-severity network security finding and should be addressed before any other network security improvements.

---

## Appendix: Quick Reference

### Violating Rules Summary

| Layer | Resource | Rule | Issue | Priority |
|-------|----------|------|-------|----------|
| NACL | Production (acl-0af0e5957e726b65a) | 150 Ingress | Allow ALL from 10.1.0.0/16 | CRITICAL |
| NACL | Production (acl-0af0e5957e726b65a) | 150 Egress | Allow ALL to 10.1.0.0/16 | CRITICAL |
| NACL | Development (acl-061a0331327c18e7e) | 150 Ingress | Allow ALL from 10.0.0.0/16 | CRITICAL |
| NACL | Development (acl-061a0331327c18e7e) | 150 Egress | Allow ALL to 10.0.0.0/16 | CRITICAL |
| SG | Production-Application-SG | HTTPS Ingress | Allow from 10.0.0.0/8 | HIGH |
| SG | Dev-Database-SG | SSH Ingress | Allow from 0.0.0.0/0 | HIGH |
| SG | Dev-Application-SG | HTTP Ingress | Allow from 0.0.0.0/0 | MEDIUM |

### AWS CLI Remediation Commands

```bash
# Remove Production NACL cross-environment rules
aws ec2 delete-network-acl-entry --network-acl-id acl-0af0e5957e726b65a --rule-number 150 --ingress
aws ec2 delete-network-acl-entry --network-acl-id acl-0af0e5957e726b65a --rule-number 150 --egress

# Remove Development NACL cross-environment rules  
aws ec2 delete-network-acl-entry --network-acl-id acl-061a0331327c18e7e --rule-number 150 --ingress
aws ec2 delete-network-acl-entry --network-acl-id acl-061a0331327c18e7e --rule-number 150 --egress

# Fix Production-Application-SG (requires identifying rule ID first)
aws ec2 describe-security-group-rules --filters "Name=group-id,Values=sg-06153643a91d79c86"
# Then revoke the overly broad rule and add correct one
aws ec2 revoke-security-group-ingress --group-id sg-06153643a91d79c86 --ip-permissions IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges='[{CidrIp=10.0.0.0/8}]'
aws ec2 authorize-security-group-ingress --group-id sg-06153643a91d79c86 --ip-permissions IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges='[{CidrIp=10.0.0.0/16,Description="Allow HTTPS from production network only"}]'
```

---

**Report Generated**: 2025-11-24  
**Analysis Tool**: NSC-Review  
**Analyst**: Network Security Assessment  
**Classification**: CONFIDENTIAL - Security Assessment