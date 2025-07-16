# Email Authentication Checker Tool Instructions

## Overview
Comprehensive PowerShell tool for analyzing SPF, DKIM, and DMARC records with Microsoft documentation integration and enhanced DNS server queries.

## Features
- SPF validation (9 checks): syntax, lookups, TTL, macros, sub-records
- DKIM analysis (5 checks): syntax, key strength, status, TTL validation  
- DMARC verification (7 checks): policy, reporting, alignment, subdomain
- Interactive HTML reports with copy-to-clipboard functionality
- Authoritative DNS queries for accurate TTL validation

## Requirements
- PowerShell 5.1+
- Internet connectivity
- Administrator privileges (recommended)

## Quick Usage

1. **Run**: `.\EmailAuthChecker.ps1`
2. **Input**: Enter domain(s) - single or comma-separated
3. **Output**: Specify directory for HTML report
4. **Review**: Generated report with interactive features and Microsoft documentation links

## Analysis Details

**SPF (9 checks)**: Record presence, syntax, single record compliance, DNS lookups (≤10), length (≤255 chars), TTL (≥3600s), all mechanism, macro security, sub-record TTL

**DMARC (7 checks)**: Record presence, policy strength, reporting config, strong enforcement, subdomain policy, TTL, alignment modes

**DKIM (5 checks)**: Key discovery (10 selectors), syntax validation, key status, strength analysis (≥1024 bits), TTL validation

## Scoring
- **90-100**: Excellent - All properly configured
- **70-89**: Good - Minor improvements needed  
- **50-69**: Fair - Some security gaps
- **0-49**: Poor - Significant vulnerabilities

## Troubleshooting
- DNS issues: Check connectivity and domain spelling
- Access errors: Run as Administrator
- Performance: Verify DNS resolver responsiveness

## Support
- Author: Abdullah Zmaili
- Version: 1.0 | July 16, 2025
- PowerShell: 5.1+ required
- Total Checks: 21 comprehensive validations

## Disclaimer
Use at your own risk. Author not liable for any outcomes.
