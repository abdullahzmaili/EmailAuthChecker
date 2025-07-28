# 📧 Email Authentication Checker v1.3

![Email Security](https://img.shields.io/badge/Email%20Security-SPF%20%7C%20DKIM%20%7C%20DMARC-blue)
![PowerShell](https://img.shields.io/badge/PowerShell-5.1%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Windows%20%7C%20Linux%20%7C%20macOS-green)
![License](https://img.shields.io/badge/License-MIT-green)
![X-Microsoft-Antispam](https://img.shields.io/badge/X--Microsoft--Antispam-Enhanced-orange)
![Authentication Results](https://img.shields.io/badge/Authentication--Results-Improved-green)

> **Comprehensive email authentication analysis tool with Microsoft documentation integration, enhanced antispam header parsing, and advanced security analysis.**

## 🌟 Overview

The **Email Authentication Checker** is a professional PowerShell script that performs comprehensive security validation of SPF, DKIM, and DMARC records for domains. It generates detailed HTML reports with interactive visualizations and provides actionable recommendations with direct links to Microsoft's official documentation.

**🆕 Version 1.3 Enhancements:**
- **Enhanced X-Microsoft-Antispam-Mailbox-Delivery Header Parsing** with individual parameter extraction (UCF, JMR, Dest, OFR)
- **Improved Authentication-Results Header Processing** with precise parsing logic to exclude ARC headers
- **Advanced Protocol Cards** for Microsoft antispam parameters with visual indicators
- **Enhanced Unicode Handling** to prevent encoding artifacts in HTML reports
- **Refined Header Targeting** ensuring only correct Authentication-Results headers are processed

### ✨ Key Features

- **🔍 19 Comprehensive Security Checks** across all email authentication protocols
- **📊 Interactive HTML Reports** with professional visualizations  
- **🔗 Microsoft Documentation Integration** for remediation guidance
- **⚡ Authoritative DNS Queries** for accurate TTL and record validation
- **🎯 Multiple Analysis Modes** including email header analysis
- **🚀 DMARC Pass Validation** for email authentication compliance
- **📈 Real-time Security Scoring** with visual dashboards
- **🛡️ Enhanced Antispam Analysis** with UCF, JMR, Dest, and OFR parameter breakdown
- **🎨 Protocol Card Visualization** for Microsoft-specific email security metrics

## 🏗️ Architecture

### Security Check Breakdown

| Protocol | Checks | Focus Areas |
|----------|--------|-------------|
| **SPF** | 9 checks | Record presence, syntax, DNS lookups, TTL, enforcement rules, macro security |
| **DMARC** | 5 checks | Policy assessment, reporting config, alignment modes, subdomain policies |  
| **DKIM** | 5 checks | Selector discovery, syntax validation, key strength, status analysis |
| **Microsoft Antispam** | 4+ params | UCF, JMR, Dest, OFR parameter analysis with visual indicators |

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

### Version 1.3 (2025-07-28) - Enhanced Antispam Analysis & DMARC Policy Strictness
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
- Email: [abdullah.zmaili@example.com](mailto:abdullah.zmaili@example.com)
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
