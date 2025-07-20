# Email Authentication Checker v1.0

Comprehensive PowerShell script for analyzing SPF, DKIM, and DMARC records with Microsoft documentation integration, professional HTML reporting, and enhanced DNS server queries.

![PowerShell](https://img.shields.io/badge/PowerShell-5.1+-blue.svg)
![License](https://img.shields.io/badge/License-MIT-green.svg)
![Platform](https://img.shields.io/badge/Platform-Windows-lightgrey.svg)
![Microsoft](https://img.shields.io/badge/Microsoft-Integration-blue.svg)

## 🔍 Overview

Analyzes email authentication configurations for domains with detailed validation, actionable recommendations, and direct links to Microsoft documentation. **Version 1.0 features enhanced authoritative DNS server queries, comprehensive security analysis with 21 checks, and professional HTML reporting with interactive charts.**

## ✨ Key Features

### 🔧 **Enhanced DNS Resolution**
- Authoritative DNS server queries for accurate TTL validation
- Fallback DNS resolution with detailed server information
- Comprehensive TTL analysis across all protocols

### 📧 **Email Authentication Analysis**
- **SPF (9 checks)**: Record presence, syntax, single record compliance, DNS lookups (≤10), length (≤255), TTL (≥3600s), SPF enforcement rule validation, macro security, sub-record TTL
- **DKIM (5 checks)**: 10 selector discovery, comprehensive syntax validation, key status (ACTIVE/TESTING/REVOKED), strength analysis (≥1024 bits), TTL validation
- **DMARC (5 checks)**: Record presence, policy assessment, reporting config, alignment modes, TTL validation

### 📊 **Professional Reporting**
- Interactive HTML reports with responsive design
- Copy-to-clipboard functionality for DNS records
- Segmented donut charts (SPF=Green, DMARC=Blue, DKIM=Purple)
- Final summary with domain count and average scores
- Auto-open generated reports option
- Scoring system: Excellent (90+), Good (70-89), Fair (50-69), Poor (<50)

### 🔧 **Advanced Security Features**
- SPF macro security vulnerability assessment
- Multiple SPF record detection (RFC 7208 compliance)
- DNS lookup optimization warnings
- Key length analysis with upgrade recommendations
- DMARC failure options analysis (fo= tag)
- Authoritative DNS queries with fallback support

### 📚 **Microsoft Integration**
- Direct links to Microsoft 365 setup guides
- Official documentation references in action items
- Best practices from Microsoft security teams

## 🚀 Quick Start

1. Download `EmailAuthChecker.ps1`
2. Run PowerShell as Administrator: `.\EmailAuthChecker.ps1`
3. Enter domain(s): `example.com` or `domain1.com, domain2.com`
4. Specify output directory: `C:\Reports`
5. Review generated HTML report with interactive features

## 📋 Analysis Summary

| Protocol | Checks | Key Validations |
|----------|--------|----------------|
| SPF | 9 | Syntax, lookups, TTL, macros, sub-records, enforcement rule |
| DMARC | 5 | Policy, reporting, alignment, TTL validation |
| DKIM | 5 | Keys, syntax, strength, status, TTL |

**Total Checks**: 19 comprehensive validations across all email authentication protocols

## 📊 New Features in v1.0

### SPF Enforcement Rule
- Renamed from "All Mechanism" for better clarity
- Detailed analysis of ?all, ~all, -all, +all mechanisms
- Security impact assessment and recommendations

### DMARC Failure Options
- NEW: Analysis of fo= tag (failure reporting options)
- Supports values: 0 (default), 1, d, s
- Detailed descriptions for each option:
  - `0`: Generate report only if both SPF and DKIM fail to align
  - `1`: Generate report if either SPF or DKIM fails to align  
  - `d`: Generate report if DKIM fails to align (regardless of SPF)
  - `s`: Generate report if SPF fails to align (regardless of DKIM)

## 📁 Output

- **Format**: `Email-Auth-Report-YYYYMMDD-HHMMSS.html`
- **Features**: Interactive charts, copy buttons, responsive design
- **Content**: Detailed analysis, Microsoft documentation links, recommendations

## 🛠️ Requirements

- Windows PowerShell 5.1+
- Internet connectivity
- Administrator privileges (recommended)

## 👨‍💻 Author

**Abdullah Zmaili** 
- Email Authentication Checker v1.0
- Enhanced DNS queries and comprehensive security validation
- Enterprise-ready HTML reporting with Microsoft integration

### Version Information
- **Current Version**: 1.0
- **Author**: Abdullah Zmaili 
- **Date Created**: July 16, 2025
- **Last Updated**: July 20, 2025
- **Total Checks**: 19 comprehensive validations
- **Features**: Enhanced DNS resolution, security analysis, interactive reporting, DMARC failure options analysis

---
*For support or questions, please open an issue on GitHub.*
