# 🚀 Quick Start Guide - Email Authentication Checker v1.0

Get running with the Email Authentication Checker in under 3 minutes! **Enhanced with authoritative DNS queries, comprehensive security analysis (21 checks), and professional HTML reporting.**

## ⚡ Prerequisites

- ✅ Windows PowerShell 5.1+ 
- ✅ Network connectivity
- ✅ Domain(s) to analyze
- ✅ Output directory path (e.g., C:\Reports)
- ✅ Administrator privileges (recommended)

## 🎯 5-Minute Setup

### Step 1: Download & Setup
```powershell
# Download EmailAuthChecker.ps1 to your directory
# Right-click PowerShell → "Run as Administrator"
cd C:\Tools
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser  # If needed
```

### Step 2: Run the Tool
```powershell
.\EmailAuthChecker.ps1
```

### Step 3: Follow Prompts
```
Enter domain(s) to check: example.com, contoso.com
Enter the full path to save reports: C:\Reports

# Analysis runs automatically...

============================================
              FINAL SUMMARY
============================================
Total domains analyzed: 2
Average security score: 85/100

Would you like to open the HTML report now? (y/n): y
Opening report in your default browser...

Thank you for using Email Authentication Checker with Microsoft Documentation!
============================================
```

## 📊 Understanding Results

### 🟢 Green Charts (SPF Protocol)
- **9 Checks**: Record presence, syntax, single record, DNS lookups (≤10), length (≤255), TTL (≥3600s), all mechanism, macro security, sub-record TTL

### 🔵 Blue Charts (DMARC Protocol) 
- **7 Checks**: Record presence, policy (none/quarantine/reject), reporting config, strong enforcement, subdomain policy, TTL, alignment modes

### 🟣 Purple Charts (DKIM Protocol)
- **5 Checks**: Record presence, syntax validation, key status (ACTIVE/TESTING/REVOKED), key strength (≥1024 bits), TTL validation

### ❌ Red Indicators
- **MISSING RECORDS**: No authentication configured (all related checks fail)
- **Low TTL**: Values under 3600 seconds (security weakness)
- **Weak Keys**: DKIM keys under 1024 bits
- **Multiple SPF**: RFC 7208 violation

## 📁 Output Files

**Format**: `Email-Auth-Report-YYYYMMDD-HHMMSS.html`

**Features**: Interactive charts, copy-to-clipboard buttons, responsive design, Microsoft documentation links

## 🔧 Quick Troubleshooting

### Execution Policy Error
```powershell
Set-ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### DNS Resolution Failed
- Check internet connectivity
- Verify domain spelling
- Try different output path

### Access Denied
- Run PowerShell as Administrator
- Choose accessible directory (e.g., C:\Temp)

## ⚡ Pro Tips

- **Batch Processing**: Use commas for multiple domains
- **Regular Monitoring**: Run monthly for security health
- **Microsoft Links**: Use embedded documentation for implementation
- **Copy Buttons**: One-click DNS record copying in reports

## 📋 Tool Summary

- **Version**: 1.0 (EmailAuthChecker.ps1)
- **Author**: Abdullah Zmaili
- **Total Validations**: 21 comprehensive checks (9 SPF + 7 DMARC + 5 DKIM)
- **Key Features**: Authoritative DNS queries, interactive HTML reports, copy-to-clipboard functionality
- **Platform**: Windows PowerShell 5.1+

---
*Created: July 16, 2025 | Enhanced email authentication analysis with Microsoft integration*
