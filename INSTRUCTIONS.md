# Email Authentication Checker Tool Instructions

## Overview
Comprehensive PowerShell tool for analyzing SPF, DKIM, and DMARC records with Microsoft documentation integration and enhanced DNS server queries. Features 22 security validations across all email authentication protocols.

## Features
- SPF validation (9 checks): syntax, lookups, TTL, macros, sub-records, enforcement rule
- DKIM analysis (5 checks): syntax, key strength, status, TTL validation  
- DMARC verification (5 checks): policy, reporting, alignment, TTL validation
- Interactive HTML reports with copy-to-clipboard functionality
- Authoritative DNS queries for accurate TTL validation
- Service provider detection for DKIM configurations

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

**SPF (9 checks)**: Record presence, syntax, single record compliance, DNS lookups (≤10), length (≤255 chars), TTL (≥3600s), SPF enforcement rule (?all, ~all, -all, +all), macro security, sub-record TTL

**DMARC (5 checks)**: Record presence, policy strength, reporting config, alignment modes, TTL validation

**DKIM (5 checks)**: Key discovery (10 selectors), syntax validation, key status, strength analysis (≥1024 bits), TTL validation

## New Features

### SPF Enforcement Rule Analysis
- Renamed from "All Mechanism" for better user understanding
- Comprehensive analysis of enforcement actions:
  - `?all`: WEAK - Neutral (Pass or fail, no specific action)
  - `~all`: GOOD - Soft Fail (Emails marked but accepted)
  - `-all`: STRICT - Hard Fail (Only authorized senders accepted)
  - `+all`: CRITICAL - Allows any server (major security risk)

### DMARC Failure Options
- NEW: Complete analysis of fo= tag values
- Supported values and descriptions:
  - `0` (Default): Generate report only if both SPF and DKIM fail to align
  - `1`: Generate report if either SPF or DKIM fails to align
  - `d`: Generate report if DKIM fails to align (regardless of SPF)
  - `s`: Generate report if SPF fails to align (regardless of DKIM)

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
- Version: 1.0 | July 16, 2025 | Updated: July 20, 2025
- PowerShell: 5.1+ required
- Total Checks: 19 comprehensive validations

## Disclaimer
This tool is provided for educational and diagnostic purposes only. The author makes no warranties regarding accuracy, completeness, or fitness for any particular purpose. Users should verify all findings independently and consult with email security professionals before making production changes. The tool performs read-only DNS queries and does not modify any domain configurations. Use at your own risk. Author not liable for any outcomes.
