# 📖 Email Authentication Checker v1.3 - Detailed Instructions

## Table of Contents

1. [Installation & Setup](#installation--setup)
2. [Running the Script](#running-the-script)
3. [Analysis Modes](#analysis-modes)
4. [Understanding Results](#understanding-results)
5. [Enhanced Features (v1.3)](#enhanced-features-v13)
6. [Advanced Usage](#advanced-usage)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)
9. [Security Checks Reference](#security-checks-reference)

---

## 🆕 What's New in Version 1.3tication Checker v1.3 - Detailed Instructions

## Table of Contents

1. [Installation & Setup](#installation--setup)
2. [Running the Script](#running-the-script)
3. [Analysis Modes](#analysis-modes)
4. [Understanding Results](#understanding-results)
5. [Enhanced Features (v1.3)](#enhanced-features-v14)
6. [Advanced Usage](#advanced-usage)
7. [Troubleshooting](#troubleshooting)
8. [Best Practices](#best-practices)
9. [Security Checks Reference](#security-checks-reference)

---

## 🆕 What's New in Version 1.3

### Enhanced Microsoft Antispam Analysis
- **X-Microsoft-Antispam-Mailbox-Delivery Header Parsing**: Individual parameter extraction for UCF, JMR, Dest, and OFR
- **Protocol Card Visualization**: Interactive cards displaying Microsoft antispam parameters with distinctive icons
- **Enhanced Authentication-Results Processing**: Precise header targeting that excludes ARC-Authentication-Results headers
- **Advanced Unicode Handling**: Comprehensive character filtering to prevent encoding artifacts in HTML reports

### Key Improvements
- Refined regex patterns for better parsing accuracy
- Enhanced CSS styling for protocol cards with consistent design
- Fixed icon visibility issues and Unicode encoding problems
- Improved error handling for malformed email headers

---

## Installation & Setup

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| **PowerShell** | 5.1 | 7.0+ |
| **Operating System** | Windows 10/Server 2016 | Windows 11/Server 2022 |
| **Memory** | 512 MB | 1 GB |
| **Network** | Internet connection | High-speed internet |
| **Privileges** | Standard user | Administrator |

### Pre-execution Setup

#### 1. PowerShell Execution Policy

Check current execution policy:
```powershell
Get-ExecutionPolicy
```

If restricted, set to allow script execution:
```powershell
# For current user only (recommended)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# For all users (requires admin)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine
```

#### 2. Download and Verify Script

1. Download `EmailAuthChecker.ps1` to a dedicated folder
2. Verify the script integrity (check file size ~200KB)
3. Ensure the script file is not blocked:
   ```powershell
   Unblock-File -Path ".\EmailAuthChecker.ps1"
   ```

#### 3. Administrator Privileges (Recommended)

For optimal DNS performance and authoritative server queries:
- Right-click PowerShell → "Run as Administrator"
- Or use elevated prompt: `Start-Process PowerShell -Verb RunAs`

---

## Running the Script

### Basic Execution

Navigate to script directory and execute:
```powershell
cd "C:\path\to\script\directory"
.\EmailAuthChecker.ps1
```

### Command Examples

```powershell
# Standard execution
.\EmailAuthChecker.ps1

# With verbose output for debugging
$VerbosePreference = "Continue"
.\EmailAuthChecker.ps1

# Reset verbose preference after debugging
$VerbosePreference = "SilentlyContinue"
```

---

## Analysis Modes

### 🎯 Mode 1: Single Domain Analysis

**Purpose**: Analyze one domain for all email authentication protocols

**Usage**:
1. Select option `[1]` from menu
2. Enter domain name (e.g., `microsoft.com`)
3. Wait for analysis completion

**Input Format**:
```
Valid: microsoft.com
Valid: subdomain.example.com
Invalid: microsoft.com,contoso.com (use mode 2 for multiple)
Invalid: http://microsoft.com (no protocols)
```

**Example Output**:
```
Analyzing domain: microsoft.com
--------------------------------------------------
    Authoritative DNS servers found:
      - ns1-205.azure-dns.com (168.63.1.205)
      - ns2-205.azure-dns.net (168.63.1.206)

SPF Analysis: ✅ PASS (8/9 checks)
DKIM Analysis: ✅ PASS (4/5 checks)  
DMARC Analysis: ✅ PASS (5/5 checks)
```

### 🎯 Mode 2: Multiple Domain Analysis

**Purpose**: Batch analysis of multiple domains

**Usage**:
1. Select option `[2]` from menu
2. Enter comma-separated domains
3. Review consolidated report

**Input Format**:
```
Valid: microsoft.com,contoso.com,outlook.com
Valid: domain1.com, domain2.org, domain3.net (spaces ignored)
Invalid: domain1.com;domain2.com (semicolons not allowed)
Invalid: domain1.com\domain2.com (backslashes not allowed)
```

**Processing Order**:
- Domains processed sequentially
- Individual results displayed in real-time
- Consolidated HTML report generated at completion

### 🎯 Mode 3: File-based Domain Analysis

**Purpose**: Analyze domains from a text file

**Usage**:
1. Create text file with domains (one per line)
2. Select option `[3]` from menu
3. Provide full file path

**File Format** (`domains.txt`):
```
microsoft.com
contoso.com
outlook.com
github.com
stackoverflow.com
```

**File Requirements**:
- Text file with `.txt` extension
- One domain per line
- Empty lines ignored
- No commas or separators needed
- Comments not supported

**Example**:
```powershell
# Create domain file
@"
microsoft.com
contoso.com
outlook.com
"@ | Out-File -FilePath "C:\temp\domains.txt" -Encoding UTF8

# Run analysis
# Select [3] and enter: C:\temp\domains.txt
```

### 🎯 Mode 4: Email Header Analysis (Enhanced in v1.3)

**Purpose**: Extract and analyze domains from email headers for DMARC compliance with enhanced Microsoft antispam parameter analysis

**🆕 New Features in v1.3**:
- Enhanced X-Microsoft-Antispam-Mailbox-Delivery header parsing
- Individual parameter extraction: UCF, JMR, Dest, OFR
- Protocol card visualization for antispam metrics
- Improved Authentication-Results processing excluding ARC headers
- Advanced Unicode handling preventing encoding artifacts

**Usage**:
1. Save email headers to text file
2. Select option `[4]` from menu  
3. Provide header file path

**Enhanced Header File Format** (`headers.txt`):
```
Authentication-Results: mail.protection.outlook.com;
 spf=pass (sender IP is 40.107.236.10) smtp.mailfrom=sender.com;
 dkim=pass (signature was verified) header.d=sender.com;
 dmarc=pass action=none header.from=sender.com;
 reason=2.7.1
X-Microsoft-Antispam-Mailbox-Delivery: ucf:0; jmr:1; dest:I; OFR:TestRule;
ARC-Authentication-Results: i=1; mx.microsoft.com 1; spf=pass smtp.mailfrom=contoso.com;
Received: from mail.sender.com (mail.sender.com [40.107.236.10])
From: "Sender Name" <noreply@sender.com>
To: "Recipient Name" <recipient@recipient.com>
Subject: Test Email Authentication
Date: Wed, 24 Jul 2025 10:30:00 +0000
```

**🆕 Enhanced Information Extraction**:
- **SPF Result**: pass/fail/neutral/softfail
- **DKIM Result**: pass/fail/neutral
- **DMARC Result**: pass/fail/neutral  
- **Mail From (P1)**: smtp.mailfrom domain
- **From (P2)**: header.from domain
- **Header.d**: DKIM signing domain
- **UCF (Unified Content Filter)**: Content filtering parameter
- **JMR (Junk Mail Rule)**: Junk mail rule parameter 
- **Dest (Destination)**: Message routing destination
- **OFR (Organizational Filtering Rules)**: Org-specific filtering rules

**🔧 Improved Header Processing**:
- Smart exclusion of ARC-Authentication-Results headers
- Precise targeting of Authentication-Results headers with spf= start and reason= end
- Enhanced Unicode character filtering for clean HTML output
- Protocol card visualization for Microsoft antispam parameters

**DMARC Pass Validation**:
The script validates DMARC pass conditions:

**Condition 1**: `SPF=pass AND header.from matches smtp.mailfrom`
**Condition 2**: `DKIM=pass AND header.d matches smtp.mailfrom`

DMARC passes if **either** condition is met.

---

## Understanding Results

### Console Output Structure

#### 1. Domain Analysis Progress
```
Analyzing domain: microsoft.com
--------------------------------------------------
    Authoritative DNS servers found:
      - ns1-205.azure-dns.com (168.63.1.205)
      - ns2-205.azure-dns.net (168.63.1.206)
```

#### 2. Protocol Results Summary
```
SPF Analysis: ✅ PASS (8/9 checks passed)
  ✅ Record Found: v=spf1 include:spf.protection.outlook.com -all
  ✅ Syntax Valid
  ❌ TTL Optimization: 3600 seconds (consider increasing)
  
DKIM Analysis: ✅ PASS (4/5 checks passed)
  ✅ Selectors Found: selector1, selector2
  ✅ Keys Active: 2 active keys
  ❌ Key Strength: 1024-bit key detected (upgrade to 2048-bit)

DMARC Analysis: ✅ PASS (5/5 checks passed)
  ✅ Policy Found: v=DMARC1; p=quarantine; rua=mailto:reports@microsoft.com
  ✅ Strong Policy: quarantine
  ✅ Reporting Configured
```

#### 3. Security Score Display
```
Overall Security Score: 17/19 (89.5%) - GOOD
```

### HTML Report Components

#### Dashboard Section
- **Security score gauge** with color-coded status
- **Protocol summary cards** (SPF, DKIM, DMARC)
- **Quick action items** for immediate attention

#### Detailed Analysis Section
- **Individual check results** with pass/fail status
- **Technical details** (TTL values, record content)
- **Recommendations** with Microsoft documentation links

#### Charts and Visualizations
- **Donut charts** showing check completion rates
- **Progress bars** for security scores
- **Interactive tooltips** with additional information

### Status Indicators

| Symbol | Meaning | Action Required |
|--------|---------|----------------|
| ✅ | Check passed | None |
| ❌ | Check failed | Review recommendation |
| ⚠️ | Warning/attention needed | Consider improvement |
| ℹ️ | Informational | Optional enhancement |

---

## Advanced Usage

### Custom DNS Servers

For testing or specific environments:
```powershell
# Modify script variables if needed
$script:CustomDNSServers = @("8.8.8.8", "1.1.1.1")
```

### Batch Processing with PowerShell

Process large domain lists programmatically:
```powershell
# Create domain list
$domains = @("domain1.com", "domain2.com", "domain3.com")
$domains | Out-File -FilePath "batch_domains.txt"

# Run script in batch mode
# Select [3] and provide file path
```

### Automated Reporting

Schedule regular scans:
```powershell
# Create scheduled task for weekly scans
$trigger = New-ScheduledTaskTrigger -Weekly -At 9AM -DaysOfWeek Monday
$action = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument "-File C:\Scripts\EmailAuthChecker.ps1"
Register-ScheduledTask -TaskName "EmailAuthWeeklyScan" -Trigger $trigger -Action $action
```

### Integration with Other Tools

Export results for external processing:
```powershell
# Results are automatically saved as HTML
# Parse HTML for integration with other systems
# Or modify script to output JSON/CSV as needed
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Script Execution Errors

**Error**: `cannot be loaded because running scripts is disabled`
```powershell
Solution:
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

**Error**: `File cannot be loaded. The file is not digitally signed`
```powershell
Solution:
Unblock-File -Path ".\EmailAuthChecker.ps1"
```

#### 2. DNS Resolution Issues

**Error**: DNS timeouts or no results
```powershell
Solutions:
1. Run PowerShell as Administrator
2. Check internet connectivity: Test-NetConnection 8.8.8.8
3. Verify domain spelling
4. Try different DNS servers
```

**Error**: No authoritative servers found
```powershell
Solutions:
1. Verify domain is properly configured
2. Check domain registration status
3. Test with known working domain first
```

#### 3. Permission and Access Issues

**Error**: Access denied or permission errors
```powershell
Solutions:
1. Run PowerShell as Administrator
2. Check antivirus software blocking
3. Verify file permissions
4. Disable Windows Defender real-time protection temporarily
```

#### 4. Network and Firewall Issues

**Error**: Connection timeouts
```powershell
Solutions:
1. Check corporate firewall settings
2. Verify DNS port 53 access
3. Test with personal internet connection
4. Configure proxy settings if required
```

### Debug Mode

Enable detailed logging:
```powershell
$VerbosePreference = "Continue"
$DebugPreference = "Continue"
.\EmailAuthChecker.ps1
```

View PowerShell errors:
```powershell
$Error | Format-List -Force
```

### Performance Optimization

#### For Large Domain Lists

1. **Batch Size**: Process 10-20 domains at a time
2. **Time Limits**: Allow 2-3 minutes per domain
3. **Network**: Use wired connection for stability
4. **Resources**: Close unnecessary applications

#### DNS Performance

1. **Use Administrator Rights**: Enables direct authoritative queries
2. **Network Quality**: High-speed, stable internet connection
3. **DNS Servers**: Consider using fast public DNS (8.8.8.8, 1.1.1.1)

---

## Best Practices

### Domain Preparation

1. **Verify Domain Ownership**: Only analyze domains you own or have permission to test
2. **Backup Current Settings**: Document existing DNS records before changes
3. **Test Environment**: Use test domains for learning and experimentation

### Analysis Workflow

1. **Start Small**: Begin with single domain analysis
2. **Understand Results**: Review each protocol section thoroughly  
3. **Prioritize Issues**: Address critical failures before warnings
4. **Document Changes**: Keep records of modifications made

### Security Implementation

1. **Follow Microsoft Guidelines**: Use provided documentation links
2. **Gradual Deployment**: Implement DMARC with p=none first, then quarantine/reject
3. **Monitor Reports**: Set up DMARC reporting before enforcing policies
4. **Test Email Flow**: Verify legitimate email delivery after changes

### Reporting and Documentation

1. **Save Reports**: Archive HTML reports for compliance and tracking
2. **Track Progress**: Regular scans to measure improvement
3. **Share Results**: Distribute reports to relevant stakeholders
4. **Action Plans**: Create remediation plans based on recommendations

---

## Security Checks Reference

### SPF Protocol Checks (9 Total)

| Check | Purpose | Pass Criteria |
|-------|---------|---------------|
| **Record Presence** | Verify SPF record exists | TXT record with v=spf1 found |
| **Syntax Validation** | Check SPF record format | Valid mechanisms and syntax |
| **Single Record Compliance** | RFC 7208 compliance | Only one SPF record per domain |
| **DNS Lookup Count** | Performance optimization | ≤10 DNS lookups required |
| **Record Length** | DNS compatibility | ≤255 characters total |
| **TTL Analysis** | Caching efficiency | ≥3600 seconds recommended |
| **Enforcement Rule** | Security policy check | Proper 'all' mechanism (+all avoided) |
| **Macro Security** | Complex macro analysis | Safe macro usage patterns |
| **Sub-record TTL** | Referenced record TTL | A/MX records have adequate TTL |

### DMARC Protocol Checks (5 Total)

| Check | Purpose | Pass Criteria |
|-------|---------|---------------|
| **Record Presence** | Verify DMARC record exists | _dmarc.domain.com TXT record found |
| **Policy Assessment** | Security posture evaluation | Policy ≠ 'none' (quarantine/reject preferred) |
| **Reporting Configuration** | Monitoring setup | rua and/or ruf tags configured |
| **Alignment Modes** | Authentication alignment | Valid aspf/adkim settings |
| **TTL Validation** | DNS caching efficiency | ≥3600 seconds recommended |

### DKIM Protocol Checks (5 Total)

| Check | Purpose | Pass Criteria |
|-------|---------|---------------|
| **Selector Discovery** | Find DKIM selectors | Active DKIM selectors found |
| **Syntax Validation** | Record format verification | Valid DKIM record structure |
| **Key Status Analysis** | Key lifecycle management | Active keys present (not revoked) |
| **Strength Assessment** | Cryptographic security | ≥1024-bit keys (2048-bit preferred) |
| **TTL Validation** | DNS performance | ≥3600 seconds recommended |

### Security Scoring System

**Score Calculation**:
- Each check = 1 point
- Total possible = 19 points
- Percentage = (Passed Checks / Total Checks) × 100

**Score Interpretation**:
- **90-100%** (17-19 checks): Excellent ✅
- **80-89%** (15-16 checks): Good ⚠️
- **70-79%** (13-14 checks): Fair ⚠️
- **Below 70%** (<13 checks): Needs Improvement ❌

### Microsoft Documentation Integration

The script provides direct links to official Microsoft documentation for:

- **SPF Setup**: Complete configuration guide
- **SPF Syntax**: Technical specification and examples
- **SPF Prevention**: Anti-spoofing implementation
- **DMARC Setup**: Policy configuration guide
- **DMARC Policies**: Policy options and recommendations
- **DMARC Reports**: Monitoring and reporting setup
- **DKIM Setup**: Implementation walkthrough
- **DKIM Configuration**: Manual setup procedures
- **DKIM Best Practices**: Security recommendations

---

## Support and Resources

### Official Documentation
- [Microsoft 365 Email Security](https://docs.microsoft.com/microsoft-365/security/)
- [SPF Record Setup](https://docs.microsoft.com/microsoft-365/security/office-365-security/set-up-spf-in-office-365-to-help-prevent-spoofing)
- [DKIM Configuration](https://docs.microsoft.com/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email)
- [DMARC Implementation](https://docs.microsoft.com/microsoft-365/security/office-365-security/use-dmarc-to-validate-email)

### Community Resources
- PowerShell Gallery
- Microsoft Tech Community
- Email security forums
- DNS and email standards documentation

### Getting Help
1. **Check Documentation**: Review README.md and this instructions file
2. **Common Issues**: See troubleshooting section above
3. **Community Support**: Post questions in relevant forums
4. **Feature Requests**: Submit suggestions for improvements

---

*This completes the comprehensive instructions for the Email Authentication Checker. For quick setup, see [QUICKSTART.md](QUICKSTART.md).*
