# 🚀 Email Authentication Checker v1.3 - Quick Start Guide

## Prerequisites

- **PowerShell 5.1 or later** (Windows PowerShell or PowerShell Core)
- **Administrator privileges** (recommended for optimal DNS queries)
- **Internet connection** for DNS lookups

## 🆕 What's New in v1.3

- **Enhanced X-Microsoft-Antispam-Mailbox-Delivery Parsing** with UCF, JMR, Dest, OFR parameters
- **Improved Authentication-Results Header Processing** excluding ARC headers
- **Protocol Card Visualization** for Microsoft antispam metrics
- **Advanced Unicode Handling** preventing encoding artifacts

## Quick Setup

1. **Download** the script to your local machine
2. **Right-click** on PowerShell and select "Run as Administrator"
3. **Navigate** to the script directory:
   ```powershell
   cd "C:\path\to\script\directory"
   ```
4. **Run** the script:
   ```powershell
   .\EmailAuthChecker.ps1
   ```

## Quick Usage Examples

### 🎯 Single Domain Analysis
```powershell
# Select option [1] from the menu
# Enter: microsoft.com
```

### 🎯 Multiple Domains
```powershell
# Select option [2] from the menu  
# Enter: microsoft.com,contoso.com,outlook.com
```

### 🎯 Domain List from File
```powershell
# Create domains.txt with one domain per line:
# microsoft.com
# contoso.com
# outlook.com

# Select option [3] and provide file path
```

### 🎯 Email Header Analysis (Enhanced in v1.3)
```powershell
# Save email headers to headers.txt with Authentication-Results
# Example content:
# Authentication-Results: mail.domain.com;
#   spf=pass smtp.mailfrom=sender.com;
#   dkim=pass header.d=sender.com;
#   dmarc=pass header.from=sender.com;
#   reason=2.7.1
# X-Microsoft-Antispam-Mailbox-Delivery: ucf:0; jmr:1; dest:I; OFR:TestRule;

# Select option [4] and provide file path
# New: Enhanced parsing of Microsoft antispam parameters
# New: Protocol cards for UCF, JMR, Dest, OFR analysis
```

## ⚡ What You Get

- **Comprehensive SPF Analysis** (9 security checks)
- **Complete DKIM Validation** (5 security checks) 
- **Full DMARC Assessment** (5 security checks)
- **Enhanced Microsoft Antispam Analysis** (UCF, JMR, Dest, OFR parameters) 🆕
- **Professional HTML Report** with interactive charts and protocol cards 🆕
- **Microsoft Documentation Links** for remediation
- **Actionable Security Recommendations**
- **Enhanced Authentication-Results Processing** excluding ARC headers 🆕

## 🎯 Output

The script generates:
- **Console output** with real-time analysis
- **HTML report** (`EmailAuth_Report_[timestamp].html`)
- **Automatic browser opening** of the report

## ⚠️ Common Issues

| Issue | Solution |
|-------|----------|
| DNS timeout | Run as Administrator |
| Script won't execute | `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser` |
| No results | Check domain spelling and internet connection |
| Permission denied | Right-click PowerShell → "Run as Administrator" |

## 🔧 Execution Policy Fix

If you get execution policy errors:
```powershell
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

## 📋 Quick Reference

| Analysis Mode | Input Format | Example |
|---------------|--------------|---------|
| Single Domain | domain.com | `microsoft.com` |
| Multiple Domains | domain1,domain2,domain3 | `microsoft.com,contoso.com` |
| File Input | One domain per line | See domains.txt example |
| Email Headers | Raw email headers | See headers.txt example |

## ⏱️ Typical Runtime

- **Single domain**: 10-30 seconds
- **Multiple domains**: 30-60 seconds per domain
- **File with 10 domains**: 5-10 minutes

Ready to secure your email authentication? Run the script now! 🚀
