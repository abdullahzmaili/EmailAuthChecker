# 🚀 Email Authentication Checker v1.4 - Quick Start Guide

## ✨ Enhanced DMARC Policy Strictness Edition

Get up and running with comprehensive email authentication analysis in just 5 minutes!

## Prerequisites

- **PowerShell 5.1 or later** (Windows PowerShell or PowerShell Core)
- **Administrator privileges** (recommended for optimal DNS queries)
- **Internet connection** for DNS lookups and authoritative server queries

## 🆕 What's New in v1.4

### Enhanced Security Features
- **🔒 Strict DMARC Policy Enforcement**: Only 'reject' policy achieves maximum security rating
- **🎯 Enhanced Security Scoring**: 'quarantine' and 'none' policies treated as security weaknesses
- **🚨 Critical Status Category**: New status for scores below 40 requiring immediate action
- **💪 Enhanced Security Recommendations**: More focused on protection effectiveness

### Code Quality Improvements
- **📋 Improved Code Organization**: All functions organized with #region/#endregion comments
- **🔧 Better Maintainability**: Enhanced code structure for easier navigation and updates
- **📚 Comprehensive Documentation**: Updated guides and troubleshooting resources

## 🚀 Quick Setup

### 1. Download and Prepare
```powershell
# Download the script to your preferred directory
# Example: C:\Scripts\EmailAuthChecker.ps1

# Set execution policy if needed (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 2. Launch PowerShell as Administrator
```powershell
# Right-click PowerShell and select "Run as Administrator"
# Navigate to script directory
cd "C:\Scripts"
```

### 3. Run the Script
```powershell
# Execute the email authentication checker
.\EmailAuthChecker.ps1
```

### 4. Select Analysis Mode
```
============================================
      Email Authentication Checker
============================================
[1] Single Domain Analysis
[2] Multiple Domain Analysis  
[3] Load Domains from File (.txt)
[4] Analyze Domains from Email Headers (.txt)

Please select an option (1, 2, 3, or 4):
```

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
---

## 🎯 Quick Usage Examples

### 🔍 Single Domain Analysis
```powershell
# Select option [1] from the menu
# Enter: microsoft.com

# Example output:
# Analyzing domain: microsoft.com
# --------------------------------------------------
# SPF Analysis: ✅ PASS (8/9 checks)
# DKIM Analysis: ✅ PASS (4/5 checks)  
# DMARC Analysis: ✅ PASS (5/5 checks)
# Security Score: 92/100 (Good) 🆕
```

### 📊 Multiple Domains
```powershell
# Select option [2] from the menu  
# Enter: microsoft.com,contoso.com,outlook.com

# Processes all domains sequentially
# Generates consolidated HTML report
```

### 📂 Domain List from File
```powershell
# Create domains.txt with one domain per line:
# microsoft.com
# contoso.com
# outlook.com

# Select option [3] and provide file path
# Example: C:\temp\domains.txt
```

### 📧 Email Header Analysis (Enhanced in v1.4)
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
# 🆕 Enhanced parsing of Microsoft antispam parameters
# 🆕 Protocol cards for UCF, JMR, Dest, OFR analysis
# 🆕 Improved DMARC pass validation
```

---

## ⚡ What You Get

### 🔒 Enhanced Security Analysis (v1.4)
- **Comprehensive SPF Analysis** (9 security checks)
- **Complete DKIM Validation** (5 security checks) 
- **Strict DMARC Assessment** (5 security checks with enhanced policy enforcement)
- **🆕 Critical Status Detection** for scores below 40
- **🆕 Enhanced Security Recommendations** focused on protection effectiveness

### 📊 Professional Reporting
- **Interactive HTML Report** with enhanced visualizations
- **🆕 Strict Security Scoring** (Excellent requires DMARC p=reject + 95+ score)
- **Microsoft Documentation Links** for remediation guidance
- **Real-time Console Output** with progress indicators

### 🔧 Enhanced Features (v1.4)
- **🆕 Enhanced Microsoft Antispam Analysis** (UCF, JMR, Dest, OFR parameters)
- **🆕 Protocol Card Visualization** for antispam metrics
- **🆕 Improved Authentication-Results Processing** excluding ARC headers
- **🆕 Advanced Unicode Handling** preventing encoding artifacts

---

## 🎯 Output Files

The script generates:
- **Console output** with real-time analysis and security scores
- **HTML report** (`Email-Auth-Report-[timestamp].html`) with enhanced visualizations
- **Automatic browser opening** option for immediate report viewing

---

## 📈 Security Score Interpretation (Enhanced in v1.4)

| Score Range | Status | DMARC Requirement | Action Required |
|-------------|---------|------------------|----------------|
| **95-100** | 🏆 Excellent | **p=reject required** | Maintain current security |
| **80-94** | ✅ Good | Any policy | Minor improvements |
| **60-79** | ⚠️ Fair | Any policy | Moderate improvements needed |
| **40-59** | ❌ Poor | Any policy | Significant vulnerabilities |
| **<40** | 🚨 Critical | Any policy | **Immediate action required** |

**🆕 Enhanced Scoring**: Only DMARC p=reject policy achieves maximum security rating in v1.4

---

## ⏱️ Typical Runtime

- **Single domain**: 10-30 seconds
- **Multiple domains**: 30-60 seconds per domain
- **File with 10 domains**: 5-10 minutes

---

## ⚠️ Common Issues & Quick Fixes

### DNS Resolution Issues
```powershell
# Try running as Administrator for better DNS access
# Ensure internet connectivity
# Check firewall settings for DNS queries
```

### Execution Policy Issues
```powershell
# Set execution policy for current user
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### File Path Issues
```powershell
# Use full paths with quotes
# Example: "C:\Users\Username\Documents\domains.txt"
```

---

## 🚀 Next Steps

1. **📋 Review generated HTML report** for detailed findings
2. **🔗 Follow Microsoft documentation links** for remediation steps  
3. **⚙️ Implement recommended security improvements**
4. **🔄 Re-run analysis** to verify improvements
5. **📚 Check INSTRUCTIONS.md** for advanced usage

---

**Ready to secure your email authentication? Run the script now! 🚀**

*For detailed instructions and troubleshooting, see [INSTRUCTIONS.md](INSTRUCTIONS.md)*

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
