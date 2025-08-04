# 📧 Email Authentication Checker v1.4

## ✨ Enhanced DMARC Policy Strictness Edition

A comprehensive PowerShell tool for analyzing SPF, DKIM, and DMARC email authentication protocols with Microsoft documentation integration and enhanced security analysis.

### 🆕 Version 1.4 Highlights
- **Enhanced Code Organization**: Complete function organization with #region/#endregion comments
- **Comprehensive Documentation Suite**: Complete guides for all usage scenarios
- **Improved Troubleshooting**: Comprehensive troubleshooting and example resources
- **Enhanced User Experience**: Refined error handling and user guidance
- **Maintained Security Standards**: All v1.4 security features and strict DMARC enforcement

---

## 🚀 Features

### 🔒 Security Analysis (19 Comprehensive Checks)

#### **SPF (Sender Policy Framework) - 9 Checks**
- ✅ **Record Presence** - Validates SPF record exists
- ✅ **Syntax Validation** - Comprehensive syntax checking  
- ✅ **Single Record Compliance** - RFC 7208 violation detection
- ✅ **DNS Lookup Optimization** - Prevents 10+ lookup limit issues
- ✅ **Length Validation** - 255 character limit compliance
- ✅ **TTL Analysis** - DNS caching optimization
- ✅ **SPF Enforcement Rule** - Policy mechanism analysis (+all/-all/~all/?all)
- ✅ **Macro Security Assessment** - Security vulnerability detection in SPF macros
- ✅ **Sub-Record TTL Validation** - A/MX/TXT records referenced in SPF

#### **DMARC (Domain-based Message Authentication) - 5 Checks**
- ✅ **Record Presence** - Validates DMARC record exists
- ✅ **Policy Assessment** - p=reject/quarantine/none analysis (v43: Only reject=secure)
- ✅ **Reporting Configuration** - rua/ruf setup validation
- ✅ **Alignment Modes** - aspf/adkim settings analysis
- ✅ **TTL Validation** - DNS performance optimization

#### **DKIM (DomainKeys Identified Mail) - 5 Checks**
- ✅ **Selector Discovery** - Common selector scanning (40+ patterns)
- ✅ **Syntax Validation** - DKIM record format verification
- ✅ **Key Status Analysis** - Active/revoked/testing status detection
- ✅ **Strength Assessment** - Key length and algorithm analysis (1024/2048/4096-bit)
- ✅ **TTL Validation** - DNS caching performance

---

## 🏗️ Architecture

### Enhanced Security Scoring System (v1.4)

**Total Points: 100**
- **SPF**: 40 points (Record Present=8pts, Other checks=4pts each)
- **DMARC**: 30 points (Each check=6pts, **STRICT**: only p=reject gets full points)
- **DKIM**: 30 points (Each check=6pts)

### Security Status Categories
- **🏆 Excellent** (95-100): Requires DMARC p=reject policy + high score
- **✅ Good** (80-94): Strong security posture
- **⚠️ Fair** (60-79): Needs improvement  
- **❌ Poor** (40-59): Significant vulnerabilities
- **🚨 Critical** (<40): Immediate action required

### Enhanced Email Header Analysis

- **Authentication-Results Parsing**: Precise extraction of SPF, DKIM, DMARC results with improved header targeting
- **ARC Header Exclusion**: Smart filtering to process only standard Authentication-Results headers  
- **X-Microsoft-Antispam-Mailbox-Delivery**: Individual parameter breakdown for comprehensive analysis
- **Protocol Card Visualization**: Interactive cards for UCF (Unified Content Filter), JMR (Junk Mail Rule), Dest (Destination), and OFR (Organizational Filtering Rules)

### Analysis Modes

1. **Single Domain Analysis** - Analyze one domain directly
2. **Multiple Domain Analysis** - Batch analysis with comma-separated input
3. **File-based Analysis** - Load domains from text file (one per line)
4. **Email Header Analysis** - Extract domains from email headers with enhanced antispam parameter parsing

---

## 📋 Input Formats

### Single Domain
```
microsoft.com
```

### Multiple Domains  
```
microsoft.com,contoso.com,outlook.com
```

### Domain File (domains.txt)
```
microsoft.com
contoso.com
outlook.com
github.com
```

### Email Headers (headers.txt)
```
Authentication-Results: mail.domain.com;
 spf=pass smtp.mailfrom=sender.com;
 dkim=pass header.d=sender.com;
 dmarc=pass header.from=sender.com
From: sender@sender.com
To: recipient@recipient.com
Subject: Test Email
```

---

## 📊 Output & Reports

### Console Output
- Real-time analysis progress
- Security check results
- DNS server information
- Error handling and warnings

### HTML Report Features
- **Interactive dashboard** with security scores
- **Detailed findings** for each protocol
- **Visual charts** showing check status
- **Actionable recommendations** with Microsoft docs links
- **Professional formatting** for sharing and reporting

### Report Contents
- Executive summary with overall security score
- Protocol-specific analysis (SPF, DKIM, DMARC)
- DNS infrastructure assessment
- Security recommendations with remediation links
- Technical details and TTL analysis

---

## 🛠️ Requirements

### System Requirements
- **PowerShell**: 5.1 or later
- **Operating System**: Windows 10/11, Windows Server 2016+
- **Network**: Internet connectivity for DNS queries
- **Permissions**: Administrator rights recommended for optimal DNS performance

### DNS Requirements
- Access to public DNS servers (8.8.8.8, 1.1.1.1, etc.)
- Ability to query authoritative name servers
- No restrictive firewall blocking DNS queries

---

## 🚀 Quick Start

### 1. Download and Setup
```powershell
# Download the script
# Save as EmailAuthChecker.ps1

# Set execution policy (if needed)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

### 2. Run Analysis
```powershell
# Navigate to script directory
cd "C:\Scripts"

# Run the script
.\EmailAuthChecker.ps1
```

### 3. Select Analysis Mode
```
============================================
      Email Authentication Checker
============================================
[1] Single Domain Analysis
[2] Multiple Domain Analysis  
[3] Load Domains from File (.txt)
[4] Analyze Domains from Email Headers (.txt)

Please select an option (1, 2, 3, or 4): 1
```

### 4. Enter Domain
```
Enter the domain name to analyze (e.g., example.com): microsoft.com
```

### 5. Review Results
- Monitor real-time console output
- Review generated HTML report
- Implement recommended security improvements

---

## 🔍 Advanced Features

### Microsoft Documentation Integration
Direct links to official Microsoft documentation for:
- SPF setup and configuration
- DKIM implementation guides  
- DMARC policy recommendations
- Best practices and troubleshooting

### Email Header Analysis
- Parse authentication results from email headers
- Validate DMARC pass conditions
- Extract and analyze smtp.mailfrom and header.from domains
- Compliance verification for received emails

### Service Provider Detection
Automatic detection of email service providers based on DKIM selectors:
- Microsoft/Office 365
- Google/Gmail
- Amazon SES
- SendGrid, Mailchimp, and 30+ other providers

## 📈 Performance

### Optimization Features
- Parallel DNS queries where possible
- Authoritative server queries for accuracy
- Intelligent caching and retry logic
- Efficient batch processing for multiple domains

### Typical Performance
- **Single domain**: 10-30 seconds
- **10 domains**: 5-10 minutes  
- **100 domains**: 45-60 minutes

---

## 📚 Documentation

### Available Guides
- **[📋 QUICKSTART.md](QUICKSTART.md)** - Get started in 5 minutes
- **[📖 INSTRUCTIONS.md](INSTRUCTIONS.md)** - Comprehensive usage guide
- **[🔧 TROUBLESHOOTING.md](TROUBLESHOOTING.md)** - Common issues and solutions

### Online Resources
- [Microsoft SPF Documentation](https://docs.microsoft.com/microsoft-365/security/office-365-security/set-up-spf-in-office-365-to-help-prevent-spoofing)
- [Microsoft DKIM Documentation](https://docs.microsoft.com/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email)
- [Microsoft DMARC Documentation](https://docs.microsoft.com/microsoft-365/security/office-365-security/use-dmarc-to-validate-email)

---

## 🔧 Technical Details

### Architecture Highlights
- **Modular Design**: Each protocol analyzed independently
- **Authoritative DNS Queries**: Direct queries to authoritative servers for accuracy
- **Error Handling**: Comprehensive error handling and fallback mechanisms
- **Security Focus**: Emphasis on real-world security implications

### Enhanced Security Checks
- SPF macro vulnerability detection
- DKIM key strength analysis (1024/2048/4096-bit)
- DMARC policy enforcement validation
- DNS TTL optimization recommendations
- Multi-record compliance checking

---

## 📄 License & Disclaimer

### Disclaimer
This script has been thoroughly tested across various environments and scenarios, and all tests have passed successfully. However, by using this script, you acknowledge and agree that:

1. You are responsible for how you use the script and any outcomes resulting from its execution
2. The entire risk arising out of the use or performance of the script remains with you
3. The author and contributors are not liable for any damages, including data loss, business interruption, or other losses, even if warned of the risks

### Usage Rights
- ✅ Use for personal and commercial purposes
- ✅ Modify and distribute (with attribution)
- ✅ Include in security assessments and audits
- ❌ Claim authorship or remove attribution

---

## 👨‍💻 Author & Credits

**Author**: Abdullah Zmaili  
**Version**: 1.4
**Date**: July 2025  

### Acknowledgments
- Microsoft Security Team for documentation and best practices
- PowerShell community for DNS query techniques
- Security researchers for vulnerability identification methods

---

## 🔄 Version History

### Version 1.4 (July 2025) - Enhanced DMARC Policy Strictness
- Enhanced DMARC policy strictness: Only 'reject' policy is considered secure
- DMARC 'quarantine' and 'none' policies now treated as security weaknesses  
- Revised scoring: reject=40pts, quarantine=20pts, none=5pts (vs. previous 40/30/15)
- Updated status thresholds: Excellent requires 95+ score AND DMARC reject policy
- Added 'Critical' status category for scores below 40
- Enhanced security-focused recommendations and warnings
- Improved code organization with #region/#endregion comments for all functions

### Version 1.2 (Previous)
- Email header analysis enhancements
- Microsoft antispam parameter parsing
- Protocol card visualization improvements

### Version 1.1 (Previous)  
- Multiple analysis modes
- Enhanced DNS query optimization
- Service provider detection

### Version 1.0 (Previous)
- Initial release with core SPF, DKIM, DMARC analysis
- Basic HTML reporting
- Microsoft documentation integration

---

*📧 Secure your email authentication today with the Email Authentication Checker v1.4!*
- **Protocol Card Visualization**: Interactive cards for UCF (Unified Content Filter), JMR (Junk Mail Rule), Dest (Destination), and OFR (Organizational Filtering Rules)

### Analysis Modes

1. **Single Domain Analysis** - Analyze one domain directly
2. **Multiple Domain Analysis** - Batch analysis with comma-separated input
3. **File-based Analysis** - Load domains from text file (one per line)
4. **Email Header Analysis** - Extract domains from email headers with enhanced antispam parameter parsing

## 🚀 Quick Start

### Prerequisites

- PowerShell 5.1 or later
- Administrator privileges (recommended)
- Internet connection for DNS lookups

### Installation & Usage

1. **Download** the script to your local machine
2. **Open PowerShell as Administrator**
3. **Navigate** to script directory
4. **Execute** the script:
   ```powershell
   .\EmailAuthChecker.ps1
   ```
5. **Select analysis mode** from the interactive menu
6. **Review** the generated HTML report

> 📖 **See [QUICKSTART.md](QUICKSTART.md) for detailed setup instructions**

## 📋 Input Formats

### Single Domain
```
microsoft.com
```

### Multiple Domains  
```
microsoft.com,contoso.com,outlook.com
```

### Domain File (domains.txt)
```
microsoft.com
contoso.com
outlook.com
github.com
```

### Email Headers (headers.txt)
```
Authentication-Results: mail.domain.com;
 spf=pass smtp.mailfrom=sender.com;
 dkim=pass header.d=sender.com;
 dmarc=pass header.from=sender.com
From: sender@sender.com
To: recipient@recipient.com
Subject: Test Email
```

## 📊 Output & Reports

### Console Output
- Real-time analysis progress
- Security check results
- DNS server information
- Error handling and warnings

### HTML Report Features
- **Interactive dashboard** with security scores
- **Detailed findings** for each protocol
- **Visual charts** showing check status
- **Actionable recommendations** with Microsoft docs links
- **Professional formatting** for sharing and reporting

### Report Contents
- Executive summary with overall security score
- Protocol-specific analysis (SPF, DKIM, DMARC)
- DNS infrastructure assessment
- Security recommendations with remediation links
- Technical details and TTL analysis

## 🔧 Technical Details

### DNS Resolution
- Uses authoritative DNS servers for accurate queries
- Fallback to regular DNS resolution if needed
- TTL validation across all record types
- Multi-server redundancy for reliability

### Security Validations

#### SPF Checks
- ✅ Record presence and syntax validation
- ✅ Single record compliance (RFC 7208)
- ✅ DNS lookup count optimization (max 10)
- ✅ Record length validation (255 char limit)
- ✅ TTL analysis for caching efficiency
- ✅ Enforcement rule assessment (+all, -all, ~all, ?all)
- ✅ Macro security analysis
- ✅ Sub-record TTL validation

#### DMARC Checks  
- ✅ Policy configuration assessment
- ✅ Reporting setup validation (rua/ruf)
- ✅ Alignment mode verification
- ✅ Subdomain policy evaluation
- ✅ TTL optimization recommendations

#### DKIM Checks
- ✅ Selector discovery and validation
- ✅ Syntax and format verification  
- ✅ Key status analysis (active/revoked/testing)
- ✅ Cryptographic strength assessment
- ✅ Service provider detection

#### Enhanced Microsoft Antispam Analysis (NEW in v1.4)
- ✅ **X-Microsoft-Antispam-Mailbox-Delivery** header parsing
- ✅ **UCF (Unified Content Filter)** parameter extraction and analysis
- ✅ **JMR (Junk Mail Rule)** parameter identification with scoring
- ✅ **Dest (Destination)** routing analysis for message delivery
- ✅ **OFR (Organizational Filtering Rules)** parameter assessment
- ✅ **Protocol Card Visualization** with interactive antispam metrics
- ✅ **Enhanced Authentication-Results Parsing** excluding ARC headers
- ✅ **Unicode Encoding Cleanup** preventing HTML display artifacts

### Supported Platforms
- **Windows** (PowerShell 5.1+, PowerShell Core)
- **Linux** (PowerShell Core 6.0+)
- **macOS** (PowerShell Core 6.0+)

## 🎯 Use Cases

### IT Security Teams
- Domain security audits
- Compliance assessments  
- Email authentication validation
- Security posture reporting

### Email Administrators
- SPF/DKIM/DMARC configuration validation
- Troubleshooting email delivery issues
- Monitoring authentication health
- Implementation guidance

### Compliance Officers
- Regulatory compliance checking
- Security control validation
- Risk assessment reporting
- Documentation for audits

### Security Consultants
- Client domain assessments
- Security recommendations
- Professional reporting
- Implementation verification

## 🔍 Advanced Features

### Microsoft Documentation Integration
Direct links to official Microsoft documentation for:
- SPF setup and configuration
- DKIM implementation guides  
- DMARC policy recommendations
- Best practices and troubleshooting

### Email Header Analysis
- Parse authentication results from email headers
- Validate DMARC pass conditions
- Extract and analyze smtp.mailfrom and header.from domains
- Compliance verification for received emails

### Service Provider Detection
Automatic detection of email service providers based on DKIM selectors:
- Microsoft/Office 365
- Google/Gmail
- Amazon SES
- SendGrid, Mailchimp, and 30+ other providers

## 📈 Performance

### Optimization Features
- Parallel DNS queries where possible
- Authoritative server queries for accuracy
- Intelligent caching and retry logic
- Efficient batch processing for multiple domains

### Typical Performance
- **Single domain**: 10-30 seconds
- **10 domains**: 5-10 minutes  
- **100 domains**: 45-60 minutes

## � Changelog

### Version 1.4 (2025-07-28) - Enhanced Antispam Analysis & DMARC Policy Strictness
**🆕 New Features:**
- **Enhanced X-Microsoft-Antispam-Mailbox-Delivery Parsing**: Individual parameter extraction for UCF, JMR, Dest, and OFR
- **Protocol Card Visualization**: Interactive cards for Microsoft antispam parameters with distinctive icons
- **Improved Authentication-Results Processing**: Precise header targeting excluding ARC headers
- **Advanced Unicode Handling**: Comprehensive character filtering to prevent encoding artifacts

**🔧 Improvements:**
- Refined regex patterns for better header parsing accuracy
- Enhanced CSS styling for protocol cards with consistent design
- Fixed icon visibility issues with proper font styling
- Improved error handling for malformed headers
- Enhanced DMARC policy strictness: Only 'reject' policy considered secure
- DMARC 'quarantine' and 'none' policies treated as security weaknesses  
- Revised scoring: reject=40pts, quarantine=20pts, none=5pts
- Updated status thresholds: Excellent requires 95+ score AND DMARC reject policy
- Added 'Critical' status category for scores below 40
- Enhanced security-focused recommendations and warnings

**🐛 Bug Fixes:**
- Resolved em dash character parsing errors in explanatory text
- Fixed Unicode encoding artifacts (`â€ƒâ€"`) in HTML output
- Corrected Authentication-Results vs ARC-Authentication-Results parsing specificity
- Enhanced character cleaning with `[^\x20-\x7E]` regex pattern

### Version 1.3 (2025-07-28) - Enhanced DMARC Policy Strictness
- Enhanced DMARC policy strictness: Only 'reject' policy considered secure
- DMARC 'quarantine' and 'none' policies treated as security weaknesses  
- Revised scoring: reject=40pts, quarantine=20pts, none=5pts
- Updated status thresholds: Excellent requires 95+ score AND DMARC reject policy
- Added 'Critical' status category for scores below 40
- Enhanced security-focused recommendations and warnings

## �🛠️ Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| Script won't run | Execution policy | `Set-ExecutionPolicy RemoteSigned` |
| DNS timeouts | Network/firewall | Run as Administrator |
| No authoritative servers | DNS configuration | Check domain configuration |
| Permission errors | User privileges | Run PowerShell as Administrator |

### Debug Mode
Enable verbose output for troubleshooting:
```powershell
$VerbosePreference = "Continue"
.\EmailAuthChecker.ps1
```

## 📝 Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
1. Fork the repository
2. Create a feature branch
3. Test your changes thoroughly
4. Submit a pull request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 👤 Author

**Abdullah Zmaili**
- LinkedIn: [Abdullah Zmaili](https://linkedin.com/in/abdullah-zmaili)

## 🆘 Support

- 📖 **Documentation**: See [INSTRUCTIONS.md](INSTRUCTIONS.md) for detailed usage
- 🚀 **Quick Start**: See [QUICKSTART.md](QUICKSTART.md) for immediate setup
- 🐛 **Issues**: Report bugs and feature requests via GitHub issues
- 💬 **Discussions**: Join community discussions for help and tips

## 🎖️ Acknowledgments

- Microsoft Security Team for comprehensive documentation
- PowerShell Community for best practices
- DNS and email security standards communities
- Security researchers and practitioners

---

**⭐ Star this repository if you find it helpful!**

*Made with ❤️ for email security professionals*

