<#
.SYNOPSIS
    Comprehensive email authentication analysis tool for SPF, DKIM, and DMARC records with Microsoft documentation integration.

.DISCLAIMER
    This script has been thoroughly tested across various environments and scenarios, and all tests have passed successfully. However, by using this script, you acknowledge and agree that:
    1. You are responsible for how you use the script and any outcomes resulting from its execution.
    2. The entire risk arising out of the use or performance of the script remains with you.
    3. The author and contributors are not liable for any damages, including data loss, business interruption, or other losses, even if warned of the risks.

.DESCRIPTION
    The Email Authentication Checker analyzes email authentication configurations for domains, providing detailed validation of SPF, DKIM, and DMARC records. 
    The tool performs comprehensive security checks including DNS lookup validation, TTL analysis, macro security assessment, and syntax validation.
    It generates professional HTML reports with interactive visualizations and provides actionable recommendations with direct links to Microsoft's 
    official documentation. Enhanced with authoritative DNS server queries for accurate TTL validation and record retrieval.

.NOTES
    File Name      : EmailAuthChecker_V1.0.ps1
    Author         : Abdullah Zmaili
    Version        : 1.0
    Date Created   : 2025-June-16
    Prerequisite   : PowerShell 5.1 or later, Administrator privileges for some checks
#>

# Email Authentication Checker with Microsoft Documentation Integration
# Author: Abdullah Zmaili
# Checks SPF, DKIM, and DMARC records for domains and generates an HTML report with Microsoft official documentation links
# Enhanced with authoritative DNS server queries for accurate TTL and record validation

# Microsoft Documentation URLs - Constants to avoid repetition
$script:MSURLs = @{
    SPFSetup = "https://docs.microsoft.com/microsoft-365/security/office-365-security/set-up-spf-in-office-365-to-help-prevent-spoofing"
    SPFSyntax = "https://docs.microsoft.com/microsoft-365/security/office-365-security/set-up-spf-in-office-365-to-help-prevent-spoofing#spf-record-syntax"
    SPFPrevention = "https://docs.microsoft.com/microsoft-365/security/office-365-security/how-office-365-uses-spf-to-prevent-spoofing"
    SPFRequirements = "https://docs.microsoft.com/microsoft-365/security/office-365-security/how-office-365-uses-spf-to-prevent-spoofing#spf-record-requirements"
    DMARCSetup = "https://docs.microsoft.com/microsoft-365/security/office-365-security/use-dmarc-to-validate-email"
    DMARCPolicies = "https://docs.microsoft.com/microsoft-365/security/office-365-security/use-dmarc-to-validate-email#dmarc-policy-options"
    DMARCReports = "https://docs.microsoft.com/microsoft-365/security/office-365-security/use-dmarc-to-validate-email#optional-dmarc-policy-settings"
    DMARCImplementation = "https://docs.microsoft.com/microsoft-365/security/office-365-security/use-dmarc-to-validate-email#set-up-dmarc-for-outbound-mail"
    DKIMSetup = "https://docs.microsoft.com/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email"
    DKIMConfiguration = "https://docs.microsoft.com/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email#steps-to-manually-set-up-dkim"
    DKIMBestPractices = "https://docs.microsoft.com/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email#dkim-key-sizes"
}

# Enhanced UI Functions
function Show-Banner {
    Clear-Host
    $banner = @"
+===============================================================================+
|                                                                               |
|    #######  #     #    #     ####  #       #     #   # ####### #     #        |
|    #        ##   ##   # #     ##   #      # #    #   #    #    #     #        |
|    #####    # # # #  #   #    ##   #     #   #   #   #    #    #######        |
|    #        #  #  # #######   ##   #    #######  #   #    #    #     #        |
|    #######  #     # #     #  ####  ### #       # #####    #    #     #        |
|                                                                               |
|                 [EMAIL] Email Authentication Security Analyzer                |
|                        [SECURE] SPF + DKIM + DMARC Validator                  |
|                                                                               |
|    +------------------------------------------------------------------+       |
|    |  [ENHANCED] Enhanced with Microsoft Documentation Integration   |        |
|    |  [FAST] Authoritative DNS Server Queries for Accuracy           |        |
|    |  [REPORTS] Professional HTML Reports with Interactive Charts    |        |
|    |  [SECURITY] Comprehensive Security Assessment & Recommendations |        |
|    +------------------------------------------------------------------+       |
|                                                                               |
|                              Version 1.0 Enhanced                             |
|                          By Abdullah Zmaili - 2025                            |
+===============================================================================+
"@
    Write-Host $banner -ForegroundColor Cyan
    Write-Host ""
}

# Helper function to parse DKIM records into key-value pairs
function ConvertFrom-DKIMRecord {
    param([string]$dkimRecord)
    
    $tags = @{}
    if ([string]::IsNullOrWhiteSpace($dkimRecord)) {
        return $tags
    }
    
    $parts = $dkimRecord -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    
    foreach ($part in $parts) {
        if ($part -match '^([a-z]+)=(.*)$') {
            $tagName = $matches[1].Trim()
            $tagValue = $matches[2].Trim()
            $tags[$tagName] = $tagValue
        }
    }
    
    return $tags
}

# Helper function to generate recommendations based on issue patterns
function Get-Recommendation {
    param([string]$Issue, [string]$Protocol)
    
    # Simplified approach - just return a generic recommendation for now
    switch ($Protocol) {
        "SPF" {
            if ($Issue -like "*+all*") {
                return "Fix SPF '+all' mechanism - Microsoft Guide: $($script:MSURLs.SPFSetup)"
            } elseif ($Issue -like "*?all*") {
                return "Strengthen SPF '?all' to '~all' or '-all' - Microsoft SPF Setup: $($script:MSURLs.SPFPrevention)"
            } elseif ($Issue -like "*all mechanism*") {
                return "Add proper 'all' mechanism to SPF record - Microsoft Documentation: $($script:MSURLs.SPFSetup)"
            } elseif ($Issue -like "*too long*" -or $Issue -like "*exceeds*") {
                return "Reduce SPF record length (max 255 chars) - Microsoft Best Practices: $($script:MSURLs.SPFSyntax)"
            } elseif ($Issue -like "*approaching*") {
                return "Consider optimizing SPF record length to avoid 255 character limit - Microsoft SPF Best Practices: $($script:MSURLs.SPFSyntax)"
            } elseif ($Issue -like "*DNS lookup limit*") {
                return "Optimize SPF record to reduce DNS lookups (max 10) - Consider flattening includes or using IP addresses - Microsoft SPF Optimization: $($script:MSURLs.SPFSyntax)"
            } elseif ($Issue -like "*Near DNS lookup limit*") {
                return "Consider optimizing SPF record to avoid DNS lookup limit - Microsoft SPF Best Practices: $($script:MSURLs.SPFSyntax)"
            } elseif ($Issue -like "*Syntax:*") {
                return "Fix SPF syntax errors - Microsoft SPF Syntax Guide: $($script:MSURLs.SPFPrevention)#spf-record-syntax"
            } elseif ($Issue -like "*Low TTL*") {
                return "Increase SPF record TTL to at least 3600 seconds (1 hour) for better DNS caching and stability - Microsoft DNS Best Practices: $($script:MSURLs.SPFSyntax)"
            } elseif ($Issue -like "*Multiple SPF records*") {
                return "Remove duplicate SPF records - Only one SPF record is allowed per domain (RFC 7208) - Microsoft SPF Requirements: $($script:MSURLs.SPFRequirements)"
            } elseif ($Issue -like "*Macro Security:*") {
                return "Review SPF macro usage for security risks - Avoid complex macros that may expose infrastructure or create attack vectors - Microsoft SPF Best Practices: $($script:MSURLs.SPFSyntax)"
            } elseif ($Issue -like "*TTL Sub-Records:*") {
                return "Increase TTL for A/MX records referenced in SPF to at least 3600 seconds (1 hour) - Low TTL values can impact SPF validation performance and reliability - Microsoft DNS Best Practices: $($script:MSURLs.SPFSyntax)"
            } else {
                return "Review SPF configuration - Microsoft SPF Guide: $($script:MSURLs.SPFSetup)"
            }
        }
        "DMARC" {
            if ($Issue -like "*monitoring only*") {
                return "Change DMARC policy from 'none' to enforce protection - Microsoft DMARC Policies: $($script:MSURLs.DMARCPolicies)"
            } elseif ($Issue -like "*reporting email*") {
                return "Configure DMARC reporting (rua/ruf) - Microsoft DMARC Reports: $($script:MSURLs.DMARCReports)"
            } elseif ($Issue -like "*subdomain policy*weaker*") {
                return "Strengthen subdomain policy to match or exceed main policy - Weak subdomain policies can be exploited - Microsoft DMARC Best Practices: $($script:MSURLs.DMARCPolicies)"
            } elseif ($Issue -like "*Both SPF and DKIM use relaxed alignment*") {
                return "Consider implementing strict alignment (aspf=s or adkim=s) for enhanced security - Strict alignment provides better protection against spoofing - Microsoft DMARC Implementation: $($script:MSURLs.DMARCImplementation)"
            } elseif ($Issue -like "*Invalid*alignment*") {
                return "Fix DMARC alignment mode syntax - Valid values are 'r' (relaxed) or 's' (strict) - Microsoft DMARC Configuration: $($script:MSURLs.DMARCSetup)"
            } elseif ($Issue -like "*Invalid subdomain policy*") {
                return "Fix DMARC subdomain policy - Valid values are 'none', 'quarantine', or 'reject' - Microsoft DMARC Policies: $($script:MSURLs.DMARCPolicies)"
            } elseif ($Issue -like "*Low TTL*") {
                return "Increase DMARC record TTL to at least 3600 seconds (1 hour) for better DNS caching and stability - Microsoft DNS Best Practices: $($script:MSURLs.DMARCSetup)"
            } else {
                return "Review DMARC configuration - Microsoft DMARC Documentation: $($script:MSURLs.DMARCSetup)"
            }
        }
        "DKIM" {
            return "Fix DKIM syntax errors - Microsoft DKIM Configuration Guide: $($script:MSURLs.DKIMConfiguration)"
        }
        default {
            return "Review email authentication configuration - Microsoft Documentation"
        }
    }
}

# Function to count DNS lookups in SPF record
function Get-SPFDNSLookupCount {
    param([string]$spfRecord)
    
    $lookupCount = 0
    
    # Split SPF record into mechanisms
    $mechanisms = $spfRecord -split '\s+' | Where-Object { $_ -ne '' }
    
    foreach ($mechanism in $mechanisms) {
        # Count mechanisms that require DNS lookups
        if ($mechanism -match '^(include:|a:|mx:|exists:|redirect=)') {
            $lookupCount++
        }
        # Count a mechanism without domain (uses current domain)
        elseif ($mechanism -eq 'a' -or $mechanism -eq 'mx') {
            $lookupCount++
        }
        # Count a/mx mechanisms with CIDR but no domain
        elseif ($mechanism -match '^(a|mx)/\d+$') {
            $lookupCount++
        }
    }
    
    return $lookupCount
}

# Function to validate SPF record syntax
function Test-SPFSyntax {
    param([string]$spfRecord)
    
    $syntaxIssues = @()
    
    # Check if record starts with v=spf1
    if (-not ($spfRecord -match '^v=spf1\b')) {
        $syntaxIssues += "Must start with 'v=spf1'"
        return $syntaxIssues  # If this fails, other checks may not be meaningful
    }
    
    # Split record into mechanisms and modifiers
    $mechanisms = $spfRecord -split '\s+' | Where-Object { $_ -ne '' -and $_ -ne 'v=spf1' }
    
    # Check for multiple 'all' mechanisms
    $allCount = ($mechanisms | Where-Object { $_ -match '^[+\-~?]?all$' }).Count
    if ($allCount -gt 1) {
        $syntaxIssues += "Multiple 'all' mechanisms found (only one allowed)"
    }
    
    # Validate each mechanism
    foreach ($mechanism in $mechanisms) {
        # Skip modifiers (contain '=')
        if ($mechanism -match '=' -and $mechanism -notmatch '^(include:|a:|mx:|ptr:|exists:|redirect=)') {
            # Check for unknown modifiers/mechanisms
            if ($mechanism -notmatch '^(exp=|redirect=)') {
                $syntaxIssues += "Unknown modifier or mechanism: '$mechanism'"
            }
            continue
        }
        
        # Validate mechanism syntax
        if ($mechanism -match '^[+\-~?]?(all|include:|a|mx|ptr|exists:|ip4:|ip6:)') {
            # Valid mechanism types, check specific syntax
            if ($mechanism -match '^[+\-~?]?ip4:') {
                # Validate IPv4 address/CIDR
                $ipPart = $mechanism -replace '^[+\-~?]?ip4:', ''
                if (-not ($ipPart -match '^(\d{1,3}\.){3}\d{1,3}(/\d{1,2})?$')) {
                    $syntaxIssues += "Invalid IPv4 syntax: '$mechanism'"
                }
            }
            elseif ($mechanism -match '^[+\-~?]?ip6:') {
                # Basic IPv6 validation (simplified)
                $ipPart = $mechanism -replace '^[+\-~?]?ip6:', ''
                if (-not ($ipPart -match '^[0-9a-fA-F:]+(/\d{1,3})?$')) {
                    $syntaxIssues += "Invalid IPv6 syntax: '$mechanism'"
                }
            }
            elseif ($mechanism -match '^[+\-~?]?include:') {
                # Validate include domain
                $domain = $mechanism -replace '^[+\-~?]?include:', ''
                if ([string]::IsNullOrEmpty($domain) -or $domain -match '\s') {
                    $syntaxIssues += "Invalid include syntax: '$mechanism'"
                }
            }
            elseif ($mechanism -match '^[+\-~?]?exists:') {
                # Validate exists domain
                $domain = $mechanism -replace '^[+\-~?]?exists:', ''
                if ([string]::IsNullOrEmpty($domain) -or $domain -match '\s') {
                    $syntaxIssues += "Invalid exists syntax: '$mechanism'"
                }
            }
        }
        else {
            # Unknown mechanism
            $syntaxIssues += "Unknown or invalid mechanism: '$mechanism'"
        }
    }
    
    # Check for 'all' mechanism (should be present)
    $hasAll = $mechanisms | Where-Object { $_ -match '^[+\-~?]?all$' }
    if (-not $hasAll) {
        $syntaxIssues += "Missing 'all' mechanism (recommended as last mechanism)"
    }
    
    # Check if 'all' is the last mechanism (best practice)
    if ($hasAll -and $mechanisms.Count -gt 1) {
        $lastMechanism = $mechanisms[-1]
        if ($lastMechanism -notmatch '^[+\-~?]?all$') {
            $syntaxIssues += "Recommend placing 'all' mechanism as the last mechanism"
        }
    }
    
    return $syntaxIssues
}

# Function to validate DKIM record syntax
function Test-DKIMSyntax {
    param([string]$dkimRecord, [string]$selector)
    
    $syntaxIssues = @()
    
    if ([string]::IsNullOrWhiteSpace($dkimRecord)) {
        $syntaxIssues += "Empty DKIM record"
        return $syntaxIssues
    }
    
    # Parse DKIM record using helper function
    $tags = ConvertFrom-DKIMRecord $dkimRecord
    
    if ($tags.Count -eq 0) {
        $syntaxIssues += "No valid DKIM tags found"
        return $syntaxIssues
    }
    
    # Check for invalid tag format in original record
    $parts = $dkimRecord -split ';' | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne '' }
    foreach ($part in $parts) {
        if ($part -notmatch '^([a-z]+)=(.*)$') {
            $syntaxIssues += "Invalid tag format: '$part'"
        }
    }
    
    # Check required tags
    
    # 'v=' tag (version) - optional but recommended
    if ($tags.ContainsKey('v')) {
        if ($tags['v'] -ne 'DKIM1') {
            $syntaxIssues += "Invalid version: expected 'DKIM1', found '$($tags['v'])'"
        }
    }
    
    # 'k=' tag (key type) - optional, defaults to 'rsa'
    if ($tags.ContainsKey('k')) {
        $validKeyTypes = @('rsa', 'ed25519')
        if ($tags['k'] -notin $validKeyTypes) {
            $syntaxIssues += "Invalid key type: '$($tags['k'])' (valid: $($validKeyTypes -join ', '))"
        }
    }
    
    # 'p=' tag (public key) - required and must not be empty for active keys
    if (-not $tags.ContainsKey('p')) {
        $syntaxIssues += "Missing required 'p=' tag (public key)"
    } else {
        $publicKey = $tags['p']
        if ([string]::IsNullOrWhiteSpace($publicKey)) {
            # Empty p= tag indicates revoked key
            $syntaxIssues += "Empty public key (p=) - key is revoked"
        } else {
            # Basic Base64 validation for public key
            try {
                $cleanKey = $publicKey -replace '\s', ''
                if ($cleanKey -notmatch '^[A-Za-z0-9+/]*={0,2}$') {
                    $syntaxIssues += "Invalid Base64 format in public key"
                }
            } catch {
                $syntaxIssues += "Invalid public key format"
            }
        }
    }
    
    # 'h=' tag (hash algorithms) - optional
    if ($tags.ContainsKey('h')) {
        $validHashAlgorithms = @('sha1', 'sha256')
        $hashAlgorithms = $tags['h'] -split ':' | ForEach-Object { $_.Trim() }
        foreach ($hash in $hashAlgorithms) {
            if ($hash -notin $validHashAlgorithms) {
                $syntaxIssues += "Invalid hash algorithm: '$hash' (valid: $($validHashAlgorithms -join ', '))"
            }
        }
        # Recommend sha256 over sha1
        if ($hashAlgorithms -contains 'sha1' -and $hashAlgorithms -notcontains 'sha256') {
            $syntaxIssues += "Consider using 'sha256' instead of 'sha1' for better security"
        }
    }
    
    # 'g=' tag (granularity) - optional, deprecated
    if ($tags.ContainsKey('g')) {
        $syntaxIssues += "Granularity tag 'g=' is deprecated and should be removed"
    }
    
    # 's=' tag (service type) - optional
    if ($tags.ContainsKey('s')) {
        $validServiceTypes = @('email', '*')
        $serviceTypes = $tags['s'] -split ':' | ForEach-Object { $_.Trim() }
        foreach ($service in $serviceTypes) {
            if ($service -notin $validServiceTypes) {
                $syntaxIssues += "Invalid service type: '$service' (valid: $($validServiceTypes -join ', '))"
            }
        }
    }
    
    # 't=' tag (flags) - optional
    if ($tags.ContainsKey('t')) {
        $validFlags = @('y', 's')
        $flags = $tags['t'] -split ':' | ForEach-Object { $_.Trim() }
        foreach ($flag in $flags) {
            if ($flag -notin $validFlags) {
                $syntaxIssues += "Invalid flag: '$flag' (valid: $($validFlags -join ', '))"
            }
        }
        # Check for testing flag
        if ($flags -contains 'y') {
            $syntaxIssues += "Testing flag 'y' is set - remove for production use"
        }
    }
    
    # Check for unknown tags
    $knownTags = @('v', 'k', 'p', 'h', 'g', 's', 't', 'n')
    foreach ($tagName in $tags.Keys) {
        if ($tagName -notin $knownTags) {
            $syntaxIssues += "Unknown tag: '$tagName'"
        }
    }
    
    return $syntaxIssues
}



# Function to detect DKIM service providers
function Get-DKIMServiceProvider {
    param([hashtable]$dkimRecords, [string]$domain)
    
    $providerInfo = @{
        DetectedProviders = @()
        SelectorPatterns = @()
        Details = @()
    }
    
    # Common DKIM provider patterns
    $providerPatterns = @{
        'Microsoft/Office 365' = @('selector1', 'selector2')
        'Google/Gmail' = @('google', 'gmail')
        'Amazon SES' = @('amazonses')
        'Mailchimp' = @('k1', 'k2', 'k3')
        'SendGrid' = @('s1', 's2', 'smtpapi')
        'Constant Contact' = @('k1', 'k2')
        'Mailgun' = @('k1', 'mailo')
        'Mandrill' = @('mandrill')
        'Postmark' = @('pm', 'postmark')
        'SparkPost' = @('scph')
        'Zendesk' = @('zendesk1', 'zendesk2')
        'Salesforce' = @('salesforce')
        'HubSpot' = @('hs1', 'hs2')
        'Klaviyo' = @('dkim')
        'Campaign Monitor' = @('cm')
        'AWeber' = @('aweber')
        'GetResponse' = @('getresponse')
        'ConvertKit' = @('convertkit')
        'ActiveCampaign' = @('ac')
        'Drip' = @('drip')
        'Infusionsoft' = @('ifs')
        'Pardot' = @('pardot')
        'Marketo' = @('marketo')
        'Eloqua' = @('eloqua')
        'Braze' = @('braze')
        'Iterable' = @('iterable')
        'Sendlane' = @('sendlane')
        'Moosend' = @('moosend')
        'Omnisend' = @('omnisend')
        'Benchmark' = @('benchmark')
        'EmailOctopus' = @('emailoctopus')
        'Sendinblue' = @('sendinblue')
        'Elastic Email' = @('elasticemail')
        'Pepipost' = @('pepipost')
        'Socketlabs' = @('socketlabs')
        'Mailjet' = @('mailjet')
        'SMTP2GO' = @('smtp2go')
        'Turbo-SMTP' = @('turbo-smtp')
        'Dynadot' = @('dynadot')
        'Zoho Mail' = @('zoho')
        'Titan Email' = @('titan')
        'Protonmail' = @('protonmail')
        'Fastmail' = @('fm1', 'fm2', 'fm3')
        'Rackspace' = @('rackspace')
        'Bluehost' = @('default')
        'GoDaddy' = @('k1')
        'Namecheap' = @('default')
        'HostGator' = @('default')
        'SiteGround' = @('default')
        'cPanel' = @('default')
        'Plesk' = @('default')
        'Generic' = @('default', 'mail', 'dkim', 'key1', 'key2')
    }
    
    foreach ($selector in $dkimRecords.Keys) {
        $selectorName = $selector.ToLower()
        $providerInfo.SelectorPatterns += $selectorName
        
        $matchedProvider = $null
        foreach ($provider in $providerPatterns.Keys) {
            $patterns = $providerPatterns[$provider]
            if ($patterns -contains $selectorName) {
                $matchedProvider = $provider
                break
            }
        }
        
        if ($matchedProvider) {
            if ($matchedProvider -notin $providerInfo.DetectedProviders) {
                $providerInfo.DetectedProviders += $matchedProvider
            }
            $providerInfo.Details += "Selector '$selector': Matches $matchedProvider pattern"
        } else {
            $providerInfo.Details += "Selector '$selector': Custom/Unknown provider"
        }
    }
    
    return $providerInfo
}

# Function to extract and analyze SPF all mechanism
function Get-SPFAllMechanism {
    param([string]$spfRecord)
    
    # Split SPF record into mechanisms
    $mechanisms = $spfRecord -split '\s+' | Where-Object { $_ -ne '' }
    
    # Find all mechanism
    $allMechanism = $mechanisms | Where-Object { $_ -match '^[+\-~?]?all$' } | Select-Object -Last 1
    
    if ($allMechanism) {
        return $allMechanism
    } else {
        return ""
    }
}

# Function to check for multiple SPF records (RFC violation)
function Test-MultipleSPFRecords {
    param([string]$domain)
    
    $multipleRecordIssues = @()
    
    try {
        # Get authoritative servers for the domain
        $authServers = Get-AuthoritativeDNSServers $domain
        $allTxtRecords = Resolve-DnsNameAuthoritative -Name $domain -Type TXT -AuthoritativeServers $authServers
        $spfRecords = $allTxtRecords | Where-Object { $_.Strings -like "v=spf*" }
        
        if ($spfRecords.Count -gt 1) {
            $multipleRecordIssues += "Multiple SPF records found - RFC 7208 violation (only one allowed)"
            for ($i = 0; $i -lt $spfRecords.Count; $i++) {
                $recordContent = $spfRecords[$i].Strings -join ""
                $multipleRecordIssues += "SPF Record $($i+1): $recordContent"
            }
        }
    } catch {
        $multipleRecordIssues += "Error checking for multiple SPF records: $($_.Exception.Message)"
    }
    
    return $multipleRecordIssues
}

# Function to validate SPF macros and check for security issues
function Test-SPFMacroSecurity {
    param([string]$spfRecord)
    
    $macroSecurityIssues = @()
    
    if ([string]::IsNullOrWhiteSpace($spfRecord)) {
        return $macroSecurityIssues
    }
    
    # Check for SPF macros (% followed by {})
    $macroMatches = [regex]::Matches($spfRecord, '%\{([^}]*)\}')
    
    if ($macroMatches.Count -eq 0) {
        # No macros found - this is good for security
        return $macroSecurityIssues
    }
    
    # Validate each macro for security and syntax
    foreach ($macroMatch in $macroMatches) {
        $fullMacro = $macroMatch.Value
        $macroContent = $macroMatch.Groups[1].Value
        
        # Parse macro components: letter[digits[r]][delimiter[...]]
        if ($macroContent -match '^([slodiptcrv])(\d+)?(r)?(\.[^}]*)?$') {
            $macroLetter = $matches[1]
            $digits = $matches[2]
            $reverse = $matches[3]
            $delimiter = $matches[4]
            
            # Check for potentially dangerous macro letters
            switch ($macroLetter) {
                'i' { 
                    # IP address - generally safe but can reveal infrastructure
                    if ($digits -and [int]$digits -lt 16) {
                        $macroSecurityIssues += "Macro '$fullMacro' uses short IP truncation ($digits chars) - may not provide sufficient uniqueness"
                    }
                }
                'p' { 
                    # PTR record - deprecated and slow, potential security risk
                    $macroSecurityIssues += "Macro '$fullMacro' uses PTR mechanism (deprecated) - can cause performance issues and DNS dependencies"
                }
                'c' { 
                    # Client IP - can be spoofed in some contexts
                    $macroSecurityIssues += "Macro '$fullMacro' uses client IP validation - ensure this is intended and secure in your environment"
                }
                'r' { 
                    # Domain name in reverse - complex processing
                    if (-not $reverse) {
                        $macroSecurityIssues += "Macro '$fullMacro' processes domain names - verify the source domain is trusted"
                    }
                }
                't' { 
                    # Timestamp - can be manipulated
                    $macroSecurityIssues += "Macro '$fullMacro' uses timestamp validation - ensure time synchronization is reliable"
                }
            }
            
            # Check for overly complex delimiters
            if ($delimiter -and $delimiter.Length -gt 10) {
                $macroSecurityIssues += "Macro '$fullMacro' has complex delimiter '$delimiter' - review for necessity and security"
            }
            
            # Check for reverse processing combined with truncation
            if ($reverse -and $digits -and [int]$digits -lt 8) {
                $macroSecurityIssues += "Macro '$fullMacro' combines reverse processing with short truncation - may cause unexpected behavior"
            }
            
        } else {
            # Invalid macro syntax
            $macroSecurityIssues += "Invalid macro syntax: '$fullMacro' - does not match valid SPF macro format"
        }
    }
    
    # Check for macros in exists: mechanisms (often used for complex lookups)
    $existsWithMacros = [regex]::Matches($spfRecord, 'exists:[^%]*%\{[^}]*\}')
    if ($existsWithMacros.Count -gt 0) {
        $macroSecurityIssues += "Complex macro usage in exists: mechanism detected - review for security and necessity (can be used for data exfiltration)"
    }
    
    # Check for multiple macros in a single mechanism
    $mechanisms = $spfRecord -split '\s+' | Where-Object { $_ -ne '' -and $_ -ne 'v=spf1' }
    foreach ($mechanism in $mechanisms) {
        $mechanismMacros = [regex]::Matches($mechanism, '%\{[^}]*\}')
        if ($mechanismMacros.Count -gt 2) {
            $macroSecurityIssues += "Mechanism '$mechanism' contains $($mechanismMacros.Count) macros - excessive complexity may indicate security risk"
        }
    }
    
    # Overall macro count check
    if ($macroMatches.Count -gt 5) {
        $macroSecurityIssues += "SPF record contains $($macroMatches.Count) macros - high complexity increases attack surface and debugging difficulty"
    }
    
    return $macroSecurityIssues
}

# Function to check TTL for SPF sub-records (A records referenced in SPF)
function Test-SPFSubRecordsTTL {
    param([string]$spfRecord, [string]$domain)
    
    $subRecordIssues = @()
    $checkedRecords = @()
    
    if ([string]::IsNullOrWhiteSpace($spfRecord)) {
        return $subRecordIssues
    }
    
    # Extract A record mechanisms from SPF record
    $mechanisms = $spfRecord -split '\s+' | Where-Object { $_ -ne '' -and $_ -ne 'v=spf1' }
    
    foreach ($mechanism in $mechanisms) {
        $domainToCheck = $null
        
        # Check for a: mechanisms with explicit domain
        if ($mechanism -match '^[+\-~?]?a:([^/\s]+)') {
            $domainToCheck = $matches[1]
        }
        # Check for a mechanism without domain (uses current domain)
        elseif ($mechanism -match '^[+\-~?]?a(/\d+)?$') {
            $domainToCheck = $domain
        }
        # Check for mx: mechanisms with explicit domain
        elseif ($mechanism -match '^[+\-~?]?mx:([^/\s]+)') {
            $domainToCheck = $matches[1]
        }
        # Check for mx mechanism without domain (uses current domain)
        elseif ($mechanism -match '^[+\-~?]?mx(/\d+)?$') {
            $domainToCheck = $domain
        }
        
        # Skip if no domain to check or already checked
        if (-not $domainToCheck -or $domainToCheck -in $checkedRecords) {
            continue
        }
        
        $checkedRecords += $domainToCheck
        
        try {
            # Check A records for the domain against authoritative servers
            $authServers = Get-AuthoritativeDNSServers $domainToCheck
            $aRecords = Resolve-DnsNameAuthoritative -Name $domainToCheck -Type A -AuthoritativeServers $authServers
            
            if ($aRecords) {
                foreach ($aRecord in $aRecords) {
                    if ($aRecord.TTL -lt 3600) {
                        $subRecordIssues += "A record for '$domainToCheck' has low TTL ($($aRecord.TTL) seconds) - recommend 3600+ seconds for stability"
                    }
                }
            } else {
                $subRecordIssues += "A record for '$domainToCheck' not found or inaccessible - SPF validation may fail"
            }
            
            # Also check MX records if it's an MX mechanism
            if ($mechanism -match '^[+\-~?]?mx') {
                $mxAuthServers = Get-AuthoritativeDNSServers $domainToCheck
                $mxRecords = Resolve-DnsNameAuthoritative -Name $domainToCheck -Type MX -AuthoritativeServers $mxAuthServers
                
                if ($mxRecords) {
                    foreach ($mxRecord in $mxRecords) {
                        if ($mxRecord.TTL -lt 3600) {
                            $subRecordIssues += "MX record for '$domainToCheck' has low TTL ($($mxRecord.TTL) seconds) - recommend 3600+ seconds for stability"
                        }
                    }
                } else {
                    $subRecordIssues += "MX record for '$domainToCheck' not found or inaccessible - SPF validation may fail"
                }
            }
            
        } catch {
            $subRecordIssues += "Error checking records for '$domainToCheck': $($_.Exception.Message)"
        }
    }
    
    return $subRecordIssues
}

# Function to collect TTL values for SPF sub-records (A/MX records referenced in SPF)
function Get-SPFSubRecordsTTLValues {
    param([string]$spfRecord, [string]$domain)
    
    $subRecordTTLValues = @{}
    $checkedRecords = @()
    
    if ([string]::IsNullOrWhiteSpace($spfRecord)) {
        return $subRecordTTLValues
    }
    
    # Extract A record mechanisms from SPF record
    $mechanisms = $spfRecord -split '\s+' | Where-Object { $_ -ne '' -and $_ -ne 'v=spf1' }
    
    foreach ($mechanism in $mechanisms) {
        $domainToCheck = $null
        $recordType = ""
        
        # Check for a: mechanisms with explicit domain
        if ($mechanism -match '^[+\-~?]?a:([^/\s]+)') {
            $domainToCheck = $matches[1]
            $recordType = "A"
        }
        # Check for a mechanism without domain (uses current domain)
        elseif ($mechanism -match '^[+\-~?]?a(/\d+)?$') {
            $domainToCheck = $domain
            $recordType = "A"
        }
        # Check for mx: mechanisms with explicit domain
        elseif ($mechanism -match '^[+\-~?]?mx:([^/\s]+)') {
            $domainToCheck = $matches[1]
            $recordType = "MX"
        }
        # Check for mx mechanism without domain (uses current domain)
        elseif ($mechanism -match '^[+\-~?]?mx(/\d+)?$') {
            $domainToCheck = $domain
            $recordType = "MX"
        }
        
        # Skip if no domain to check or already checked
        if (-not $domainToCheck -or $domainToCheck -in $checkedRecords) {
            continue
        }
        
        $checkedRecords += $domainToCheck
        
        try {
            # Check A records for the domain against authoritative servers
            if ($recordType -eq "A" -or $mechanism -match '^[+\-~?]?a') {
                $authServers = Get-AuthoritativeDNSServers $domainToCheck
                $aRecords = Resolve-DnsNameAuthoritative -Name $domainToCheck -Type A -AuthoritativeServers $authServers
                
                if ($aRecords) {
                    $ttlValues = @()
                    foreach ($aRecord in $aRecords) {
                        $ttlValues += "$($aRecord.IPAddress): $($aRecord.TTL)s"
                    }
                    if ($ttlValues.Count -gt 0) {
                        $subRecordTTLValues["$domainToCheck (A)"] = $ttlValues -join ", "
                    }
                }
            }
            
            # Also check MX records if it's an MX mechanism
            if ($mechanism -match '^[+\-~?]?mx') {
                $mxAuthServers = Get-AuthoritativeDNSServers $domainToCheck
                $mxRecords = Resolve-DnsNameAuthoritative -Name $domainToCheck -Type MX -AuthoritativeServers $mxAuthServers
                
                if ($mxRecords) {
                    $ttlValues = @()
                    foreach ($mxRecord in $mxRecords) {
                        $ttlValues += "$($mxRecord.NameExchange) (Priority: $($mxRecord.Preference)): $($mxRecord.TTL)s"
                    }
                    if ($ttlValues.Count -gt 0) {
                        $subRecordTTLValues["$domainToCheck (MX)"] = $ttlValues -join ", "
                    }
                }
            }
            
        } catch {
            $subRecordTTLValues["$domainToCheck (Error)"] = "Unable to retrieve TTL: $($_.Exception.Message)"
        }
    }
    
    return $subRecordTTLValues
}

# Function to extract DKIM all mechanism (if present)
# Function to extract DKIM key length from public key
function Get-DKIMKeyLength {
    param([string]$dkimRecord)
    
    if ([string]::IsNullOrWhiteSpace($dkimRecord)) {
        return @{
            KeyLength = 0
            KeyType = "Unknown"
            IsWeak = $false
            Error = "No DKIM record provided"
        }
    }
    
    # Parse DKIM record using helper function
    $tags = ConvertFrom-DKIMRecord $dkimRecord
    
    # Get key type (default is RSA if not specified)
    $keyType = if ($tags.ContainsKey('k')) { $tags['k'] } else { "rsa" }
    
    # Check if key is revoked (empty p= tag)
    if ($tags.ContainsKey('p') -and [string]::IsNullOrWhiteSpace($tags['p'])) {
        return @{
            KeyLength = 0
            KeyType = $keyType
            IsWeak = $false
            Error = "Key is revoked (empty p= tag)"
        }
    }
    
    # Get public key
    if (-not $tags.ContainsKey('p')) {
        return @{
            KeyLength = 0
            KeyType = $keyType
            IsWeak = $false
            Error = "No public key (p=) tag found"
        }
    }
    
    $publicKey = $tags['p']
    if ([string]::IsNullOrWhiteSpace($publicKey)) {
        return @{
            KeyLength = 0
            KeyType = $keyType
            IsWeak = $false
            Error = "Empty public key"
        }
    }
    
    try {
        # Clean the Base64 key (remove whitespace)
        $cleanKey = $publicKey -replace '\s', ''
        
        # Validate Base64 format
        if ($cleanKey -notmatch '^[A-Za-z0-9+/]*={0,2}$') {
            return @{
                KeyLength = 0
                KeyType = $keyType
                IsWeak = $false
                Error = "Invalid Base64 format in public key"
            }
        }
        
        # Decode Base64 to get the DER-encoded key
        $keyBytes = [System.Convert]::FromBase64String($cleanKey)
        
        # For RSA keys, we need to parse the ASN.1 DER structure
        if ($keyType -eq "rsa") {
            # RSA public key in DER format starts with a sequence
            # We'll do a simplified parsing to extract the modulus length
            
            # Look for the RSA modulus (first large integer in the sequence)
            # This is a simplified approach - in a real implementation you'd use proper ASN.1 parsing
            
            # The modulus typically starts after the algorithm identifier
            # We'll search for large byte sequences that likely represent the modulus
            $keyLength = 0
            
            # Look for typical RSA key patterns
            # 1024-bit keys typically have modulus around 128 bytes (256 hex chars)
            # 2048-bit keys typically have modulus around 256 bytes (512 hex chars)
            # 4096-bit keys typically have modulus around 512 bytes (1024 hex chars)
            
            $keyLength = switch ($keyBytes.Length) {
                {$_ -ge 512 -and $_ -lt 768} { 4096 }  # 4096-bit key
                {$_ -ge 294 -and $_ -lt 512} { 2048 }  # 2048-bit key
                {$_ -ge 162 -and $_ -lt 294} { 1024 }  # 1024-bit key
                {$_ -ge 94 -and $_ -lt 162} { 512 }    # 512-bit key (very weak)
                default { 
                    # Try to estimate based on total key size
                    $estimatedBits = [math]::Round(($keyBytes.Length - 30) * 8 / 1.2, 0)
                    if ($estimatedBits -gt 4096) { 4096 }
                    elseif ($estimatedBits -gt 2048) { 2048 }
                    elseif ($estimatedBits -gt 1024) { 1024 }
                    elseif ($estimatedBits -gt 512) { 512 }
                    else { $estimatedBits }
                }
            }
            
            $isWeak = $keyLength -lt 1024  # Only keys below 1024 are considered weak
            
            return @{
                KeyLength = $keyLength
                KeyType = $keyType
                IsWeak = $isWeak
                Error = $null
            }
        }
        elseif ($keyType -eq "ed25519") {
            # Ed25519 keys are always 256 bits (32 bytes for the public key)
            return @{
                KeyLength = 256
                KeyType = $keyType
                IsWeak = $false  # Ed25519 is considered secure
                Error = $null
            }
        }
        else {
            return @{
                KeyLength = 0
                KeyType = $keyType
                IsWeak = $false
                Error = "Unsupported key type: $keyType"
            }
        }
    }
    catch {
        return @{
            KeyLength = 0
            KeyType = $keyType
            IsWeak = $false
            Error = "Failed to parse public key: $($_.Exception.Message)"
        }
    }
}

# Helper function to get DKIM key status
function Get-DKIMKeyStatus {
    param([string]$dkimRecord)
    
    if ([string]::IsNullOrWhiteSpace($dkimRecord)) {
        return "N/A"
    }
    
    $tags = ConvertFrom-DKIMRecord $dkimRecord
    
    # Check if this is a revoked key (empty p= tag)
    if ($tags.ContainsKey('p') -and [string]::IsNullOrWhiteSpace($tags['p'])) {
        return "REVOKED"
    }
    
    # Check for testing flag
    if ($tags.ContainsKey('t') -and $tags['t'] -match 'y') {
        return "TESTING"
    }
    
    # Check for active key with valid public key
    if ($tags.ContainsKey('p') -and -not [string]::IsNullOrWhiteSpace($tags['p'])) {
        return "ACTIVE"
    }
    
    return "UNKNOWN"
}

# Function to get authoritative DNS servers and their IP addresses for a domain
function Get-AuthoritativeDNSServers {
    param([string]$domain)
    
    $authServers = @()
    
    try {
        # Get NS records for the domain
        $nsRecords = Resolve-DnsName -Name $domain -Type NS -ErrorAction SilentlyContinue
        
        if ($nsRecords) {
            foreach ($ns in $nsRecords) {
                if ($ns.Type -eq "NS") {
                    try {
                        # Resolve IP address of NS server
                        $nsIP = (Resolve-DnsName -Name $ns.NameHost -Type A -ErrorAction SilentlyContinue)[0].IPAddress
                        if ($nsIP) {
                            $authServers += [PSCustomObject]@{
                                NameHost = $ns.NameHost
                                IPAddress = $nsIP
                            }
                        }
                    }
                    catch {
                        Write-Verbose "Could not resolve IP for NS server $($ns.NameHost): $_"
                    }
                }
            }
        }
        
        # If no NS records found for the domain, try the parent domain
        if ($authServers.Count -eq 0 -and $domain.Contains('.')) {
            $parentDomain = $domain.Substring($domain.IndexOf('.') + 1)
            $parentNS = Resolve-DnsName -Name $parentDomain -Type NS -ErrorAction SilentlyContinue
            
            if ($parentNS) {
                foreach ($ns in $parentNS) {
                    if ($ns.Type -eq "NS") {
                        try {
                            $nsIP = (Resolve-DnsName -Name $ns.NameHost -Type A -ErrorAction SilentlyContinue)[0].IPAddress
                            if ($nsIP) {
                                $authServers += [PSCustomObject]@{
                                    NameHost = $ns.NameHost
                                    IPAddress = $nsIP
                                }
                            }
                        }
                        catch {
                            Write-Verbose "Could not resolve IP for parent NS server $($ns.NameHost): $_"
                        }
                    }
                }
            }
        }
    }
    catch {
        Write-Verbose "Error finding authoritative servers for $domain`: $_"
    }
    
    return $authServers
}

# Function to perform DNS query against authoritative servers
function Resolve-DnsNameAuthoritative {
    param(
        [string]$Name,
        [string]$Type,
        [array]$AuthoritativeServers = @()
    )
    
    $results = @()
    
    # If no authoritative servers provided, find them
    if ($AuthoritativeServers.Count -eq 0) {
        $domain = $Name
        # Extract domain from subdomain queries like _dmarc.example.com or selector1._domainkey.example.com
        if ($Name.Contains('.')) {
            $parts = $Name -split '\.'
            if ($parts.Count -gt 2) {
                # For DKIM records like selector1._domainkey.example.com, extract example.com
                if ($Name -match '_domainkey\.(.+)$') {
                    $domain = $matches[1]
                }
                # For DMARC records like _dmarc.example.com, extract example.com
                elseif ($Name -match '^_dmarc\.(.+)$') {
                    $domain = $matches[1]
                }
                # For other subdomains, try the main domain
                else {
                    $domain = ($parts[-2..-1]) -join '.'
                }
            }
        }
        $AuthoritativeServers = Get-AuthoritativeDNSServers $domain
    }
    
    # If we have authoritative servers, query them directly
    if ($AuthoritativeServers.Count -gt 0) {
        foreach ($server in $AuthoritativeServers) {
            try {
                Write-Verbose "Querying authoritative server: $($server.NameHost) ($($server.IPAddress)) for $Name ($Type)"
                # Query using the IP address of the authoritative server
                $result = Resolve-DnsName -Name $Name -Type $Type -Server $server.IPAddress -ErrorAction SilentlyContinue
                if ($result) {
                    $results += $result
                    Write-Verbose "Successfully retrieved $($result.Count) records from $($server.NameHost)"
                    break  # Use first successful result
                }
            }
            catch {
                Write-Verbose "Failed to query $($server.NameHost) ($($server.IPAddress)) for $Name`: $_"
                continue
            }
        }
    }
    
    # Fallback to regular DNS query if authoritative query fails
    if ($results.Count -eq 0) {
        try {
            Write-Verbose "Falling back to regular DNS query for $Name ($Type)"
            $results = Resolve-DnsName -Name $Name -Type $Type -ErrorAction SilentlyContinue
        }
        catch {
            Write-Verbose "Regular DNS query also failed for $Name`: $_"
        }
    }
    
    return $results
}


# Show enhanced banner at script start
Show-Banner



# Common DKIM selectors to check - expanded list for better detection
$commonSelectors = @("default", "selector1", "selector2", "google", "gmail", "k1", "k2", "dkim", "mail", "email", "s1", "s2", "smtpapi", "amazonses", "mandrill", "mailgun", "pm", "zendesk1", "mxvault")

# Results storage
$allResults = @()

# Check each domain
### --- Simple User Interface Menu --- ###
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "      Email Authentication Checker" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "[1] Single Domain Analysis"

Write-Host "[2] Multiple Domain Analysis"
Write-Host "[3] Load Domains from File (.txt)"

$menuChoice = Read-Host "Please select an option (1, 2, or 3)"

switch ($menuChoice) {
    '1' {
        $domain = Read-Host "Enter the domain name to analyze (e.g., example.com)"
        $domains = @($domain.Trim())
    }
    '2' {
        $domainList = Read-Host "Enter domains separated by commas (e.g., example.com,contoso.com)"
        $domains = $domainList -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }
    }
    '3' {
        $filePath = Read-Host "Enter the full path to the .txt file containing domains (one per line)"
        if (-not (Test-Path -Path $filePath)) {
            Write-Host "File not found: $filePath" -ForegroundColor Red
            exit
        }
        $domains = Get-Content -Path $filePath | ForEach-Object { $_.Trim() } | Where-Object { $_ }
        if (-not $domains -or $domains.Count -eq 0) {
            Write-Host "No domains found in the file. Exiting..." -ForegroundColor Red
            exit
        }
    }
    default {
        Write-Host "Invalid option. Exiting..." -ForegroundColor Red
        exit
    }
}

foreach ($domain in $domains) {
    Write-Host "Analyzing domain: $domain" -ForegroundColor Yellow
    Write-Host "-" * 50 -ForegroundColor DarkGray
    
    # Get authoritative servers for this domain
    $authServers = Get-AuthoritativeDNSServers $domain
    if ($authServers.Count -gt 0) {
        Write-Host "    Authoritative DNS servers found:" -ForegroundColor Gray
        foreach ($server in $authServers) {
            Write-Host "      - $($server.NameHost) ($($server.IPAddress))" -ForegroundColor Gray
        }
    } else {
        Write-Host "    No authoritative DNS servers found, using default resolvers" -ForegroundColor Yellow
    }
    Write-Host ""
    
    # Initialize result object
    $result = [PSCustomObject]@{
        Domain = $domain
        SPFFound = $false
        SPFRecord = ""
        SPFIssues = @()
        SPFDNSLookups = 0
        SPFRecordLength = 0
        SPFTTL = 0
        SPFAllMechanism = ""
        SPFSyntaxValid = $true
        SPFSyntaxIssues = @()
        DMARCFound = $false
        DMARCRecord = ""
        DMARCPolicy = ""
        DMARCSubdomainPolicy = ""  # sp= tag
        DMARCSPFAlignment = ""     # aspf= tag
        DMARCDKIMAlignment = ""    # adkim= tag
        DMARCTTL = 0
        DMARCIssues = @()
        DKIMFound = $false
        DKIMSelectors = @()
        DKIMRecords = @{}  # Dictionary to store selector -> record mapping
        DKIMAllMechanisms = @{}  # Dictionary to store selector -> all mechanism mapping
        DKIMKeyLengths = @{}  # Dictionary to store selector -> key length info mapping
        DKIMTTL = @{}  # Dictionary to store selector -> TTL mapping
        DKIMTTLIssues = @{}  # Dictionary to store selector -> TTL issues mapping
        DKIMSyntaxValid = $true
        DKIMSyntaxIssues = @{}  # Dictionary to store selector -> issues mapping
        SPFMultipleRecordsCheck = $true  # New check for multiple SPF records
        SPFMacroSecurityCheck = $true  # New check for SPF macro security
        SPFSubRecordsTTLCheck = $true  # New check for TTL of sub-records (A/MX records referenced in SPF)
        SPFSubRecordsTTLValues = @{}  # Dictionary to store domain -> TTL values for A/MX records referenced in SPF
        Score = 0
        Status = ""
        Recommendations = @()
    }
    
    # CHECK SPF RECORD
    Write-Host "  [1/3] Checking SPF record..." -ForegroundColor White
    
    # First, check for multiple SPF records (RFC violation)
    $multipleSPFIssues = Test-MultipleSPFRecords $domain
    if ($multipleSPFIssues.Count -gt 0) {
        $result.SPFMultipleRecordsCheck = $false
        foreach ($issue in $multipleSPFIssues) {
            $result.SPFIssues += $issue
        }
        Write-Host "        Multiple SPF records detected - RFC violation!" -ForegroundColor Red
        foreach ($issue in $multipleSPFIssues) {
            if ($issue -like "SPF Record*") {
                Write-Host "        $issue" -ForegroundColor Yellow
            }
        }
    } else {
        $result.SPFMultipleRecordsCheck = $true
        Write-Host "        Single SPF record compliance: PASSED" -ForegroundColor Green
    }
    
    # Query SPF record from authoritative servers
    $authServers = Get-AuthoritativeDNSServers $domain
    $spfTxtRecords = Resolve-DnsNameAuthoritative -Name $domain -Type TXT -AuthoritativeServers $authServers
    $spfRecord = $spfTxtRecords | Where-Object {$_.Strings -like "v=spf*"} | Select-Object -First 1
    
    if ($spfRecord) {
        $result.SPFFound = $true
        $result.SPFRecord = $spfRecord.Strings -join ""
        $result.SPFTTL = $spfRecord.TTL
        Write-Host "        SPF record found" -ForegroundColor Green
        
        # Extract and analyze SPF all mechanism
        $allMechanism = Get-SPFAllMechanism $result.SPFRecord
        $result.SPFAllMechanism = $allMechanism
        
        # Check SPF all mechanism issues with detailed analysis
        if ($allMechanism -eq "+all") {
            $result.SPFIssues += "Uses '+all' (allows any server) - CRITICAL SECURITY RISK"
            Write-Host "        All Mechanism: +all (CRITICAL - allows any server)" -ForegroundColor Red
        } elseif ($allMechanism -eq "?all") {
            $result.SPFIssues += "Uses '?all' (neutral/weak protection) - provides minimal security"
            Write-Host "        All Mechanism: ?all (WEAK - neutral protection)" -ForegroundColor Yellow
        } elseif ($allMechanism -eq "~all") {
            Write-Host "        All Mechanism: ~all (GOOD - soft fail recommended)" -ForegroundColor Green
        } elseif ($allMechanism -eq "-all") {
            Write-Host "        All Mechanism: -all (STRICT - hard fail)" -ForegroundColor Green
        } elseif ([string]::IsNullOrEmpty($allMechanism)) {
            $result.SPFIssues += "Missing 'all' mechanism - SPF policy incomplete"
            Write-Host "        All Mechanism: MISSING (policy incomplete)" -ForegroundColor Red
        } else {
            $result.SPFIssues += "Unknown 'all' mechanism format: $allMechanism"
            Write-Host "        All Mechanism: $allMechanism (UNKNOWN format)" -ForegroundColor Yellow
        }
        
        # Check SPF record length (RFC 7208 - DNS TXT record limit is 255 characters)
        $result.SPFRecordLength = $result.SPFRecord.Length
        if ($result.SPFRecordLength -gt 255) {
            $result.SPFIssues += "Record too long ($($result.SPFRecordLength) characters) - exceeds 255 character limit"
            Write-Host "        Record Length: $($result.SPFRecordLength) characters (EXCEEDS LIMIT)" -ForegroundColor Red
        } elseif ($result.SPFRecordLength -gt 200) {
            $result.SPFIssues += "Record approaching length limit ($($result.SPFRecordLength) characters) - consider optimization"
            Write-Host "        Record Length: $($result.SPFRecordLength) characters (approaching limit)" -ForegroundColor Yellow
        } else {
            Write-Host "        Record Length: $($result.SPFRecordLength) characters" -ForegroundColor Green
        }
        
        # Count DNS lookups in SPF record
        $dnsLookupCount = Get-SPFDNSLookupCount $result.SPFRecord
        $result.SPFDNSLookups = $dnsLookupCount
        
        if ($dnsLookupCount -gt 10) {
            $result.SPFIssues += "Exceeds DNS lookup limit ($dnsLookupCount/10 lookups) - SPF will fail"
        } elseif ($dnsLookupCount -gt 8) {
            $result.SPFIssues += "Near DNS lookup limit ($dnsLookupCount/10 lookups) - consider optimization"
        } else {
            Write-Host "        DNS lookups: $dnsLookupCount/10" -ForegroundColor Green
        }
        
        # Check TTL (Time To Live) - recommend minimum 3600 seconds (1 hour)
        if ($result.SPFTTL -lt 3600) {
            $result.SPFIssues += "Low TTL ($($result.SPFTTL) seconds) - recommend minimum 3600 seconds for stability"
            Write-Host "        TTL warning: $($result.SPFTTL) seconds (recommend 3600+)" -ForegroundColor Yellow
        } else {
            Write-Host "        TTL: $($result.SPFTTL) seconds" -ForegroundColor Green
        }
        
        # Validate SPF syntax
        $syntaxIssues = Test-SPFSyntax $result.SPFRecord
        $result.SPFSyntaxIssues = $syntaxIssues
        $result.SPFSyntaxValid = ($syntaxIssues.Count -eq 0)
        
        if ($syntaxIssues.Count -gt 0) {
            Write-Host "        Syntax issues found: $($syntaxIssues.Count)" -ForegroundColor Yellow
            # Add syntax issues to general SPF issues for scoring
            foreach ($syntaxIssue in $syntaxIssues) {
                $result.SPFIssues += "Syntax: $syntaxIssue"
            }
        } else {
            Write-Host "        Syntax validation: PASSED" -ForegroundColor Green
        }
        
        # Validate SPF macro security
        $macroSecurityIssues = Test-SPFMacroSecurity $result.SPFRecord
        if ($macroSecurityIssues.Count -gt 0) {
            $result.SPFMacroSecurityCheck = $false
            Write-Host "        Macro security issues found: $($macroSecurityIssues.Count)" -ForegroundColor Yellow
            foreach ($macroIssue in $macroSecurityIssues) {
                $result.SPFIssues += "Macro Security: $macroIssue"
            }
        } else {
            $result.SPFMacroSecurityCheck = $true
            Write-Host "        Macro security validation: PASSED" -ForegroundColor Green
        }
        
        # Validate TTL for SPF sub-records (A/MX records referenced in SPF)
        $subRecordsTTLIssues = Test-SPFSubRecordsTTL $result.SPFRecord $domain
        $result.SPFSubRecordsTTLValues = Get-SPFSubRecordsTTLValues $result.SPFRecord $domain
        if ($subRecordsTTLIssues.Count -gt 0) {
            $result.SPFSubRecordsTTLCheck = $false
            Write-Host "        TTL sub-records issues found: $($subRecordsTTLIssues.Count)" -ForegroundColor Yellow
            foreach ($ttlIssue in $subRecordsTTLIssues) {
                $result.SPFIssues += "TTL Sub-Records: $ttlIssue"
            }
        } else {
            $result.SPFSubRecordsTTLCheck = $true
            Write-Host "        TTL sub-records validation: PASSED" -ForegroundColor Green
        }

        if ($result.SPFIssues.Count -gt 0) {
            $issuesList = $result.SPFIssues -join '; '
            Write-Host "        Warning: $issuesList" -ForegroundColor Yellow
        }
    } else {
        Write-Host "        No SPF record found" -ForegroundColor Red
        # Set all SPF check flags to false when SPF record is not found
        $result.SPFMultipleRecordsCheck = $false
        $result.SPFMacroSecurityCheck = $false
        $result.SPFSubRecordsTTLCheck = $false
        $result.SPFSyntaxValid = $false
        # Set specific values for missing SPF record
        $result.SPFAllMechanism = "Missing"
        $result.SPFIssues += "SPF record not found - implement SPF protection"
    }
    
    # CHECK DMARC RECORD
    Write-Host "  [2/3] Checking DMARC record..." -ForegroundColor White
    $dmarcDomain = "_dmarc.$domain"
    # Query DMARC record from authoritative servers
    $dmarcAuthServers = Get-AuthoritativeDNSServers $domain
    $dmarcTxtRecords = Resolve-DnsNameAuthoritative -Name $dmarcDomain -Type TXT -AuthoritativeServers $dmarcAuthServers
    $dmarcRecord = $dmarcTxtRecords | Where-Object { $_.Strings -match "^v=DMARC1" } | Select-Object -First 1
    
    if ($dmarcRecord) {
        $result.DMARCFound = $true
        $result.DMARCRecord = $dmarcRecord.Strings -join ""
        $result.DMARCTTL = $dmarcRecord.TTL
        Write-Host "        DMARC record found" -ForegroundColor Green
        
        # Extract main policy (p=)
        if ($result.DMARCRecord -match "p=(\w+)") {
            $result.DMARCPolicy = $matches[1]
            Write-Host "        Policy: $($result.DMARCPolicy)" -ForegroundColor Cyan
        }
        
        # Extract subdomain policy (sp=)
        if ($result.DMARCRecord -match "sp=(\w+)") {
            $result.DMARCSubdomainPolicy = $matches[1]
            Write-Host "        Subdomain Policy: $($result.DMARCSubdomainPolicy)" -ForegroundColor Cyan
        } else {
            # If sp= is not specified, it defaults to the main policy
            $result.DMARCSubdomainPolicy = $result.DMARCPolicy
            Write-Host "        Subdomain Policy: $($result.DMARCSubdomainPolicy) (inherited from main policy)" -ForegroundColor Gray
        }
        
        # Extract SPF alignment mode (aspf=)
        if ($result.DMARCRecord -match "aspf=([rs])") {
            $result.DMARCSPFAlignment = $matches[1]
            $alignmentText = if ($matches[1] -eq "r") { "relaxed" } else { "strict" }
            Write-Host "        SPF Alignment: $alignmentText ($($matches[1]))" -ForegroundColor Cyan
        } else {
            # Default is relaxed if not specified
            $result.DMARCSPFAlignment = "r"
            Write-Host "        SPF Alignment: relaxed (r) - default" -ForegroundColor Gray
        }
        
        # Extract DKIM alignment mode (adkim=)
        if ($result.DMARCRecord -match "adkim=([rs])") {
            $result.DMARCDKIMAlignment = $matches[1]
            $alignmentText = if ($matches[1] -eq "r") { "relaxed" } else { "strict" }
            Write-Host "        DKIM Alignment: $alignmentText ($($matches[1]))" -ForegroundColor Cyan
        } else {
            # Default is relaxed if not specified
            $result.DMARCDKIMAlignment = "r"
            Write-Host "        DKIM Alignment: relaxed (r) - default" -ForegroundColor Gray
        }
        
        # Check DMARC issues
        if ($result.DMARCPolicy -eq "none") {
            $result.DMARCIssues += "Policy is 'none' (monitoring only)"
        }
        
        # Validate subdomain policy
        $validPolicies = @("none", "quarantine", "reject")
        if ($result.DMARCSubdomainPolicy -notin $validPolicies) {
            $result.DMARCIssues += "Invalid subdomain policy: '$($result.DMARCSubdomainPolicy)' (valid: $($validPolicies -join ', '))"
        }
        
        # Check if subdomain policy is weaker than main policy
        $policyStrength = @{ "none" = 0; "quarantine" = 1; "reject" = 2 }
        if ($policyStrength[$result.DMARCSubdomainPolicy] -lt $policyStrength[$result.DMARCPolicy]) {
            $result.DMARCIssues += "Subdomain policy '$($result.DMARCSubdomainPolicy)' is weaker than main policy '$($result.DMARCPolicy)' - consider strengthening"
        }
        
        # Validate alignment modes
        $validAlignmentModes = @("r", "s")
        if ($result.DMARCSPFAlignment -notin $validAlignmentModes) {
            $result.DMARCIssues += "Invalid SPF alignment mode: '$($result.DMARCSPFAlignment)' (valid: r=relaxed, s=strict)"
        }
        if ($result.DMARCDKIMAlignment -notin $validAlignmentModes) {
            $result.DMARCIssues += "Invalid DKIM alignment mode: '$($result.DMARCDKIMAlignment)' (valid: r=relaxed, s=strict)"
        }
        
        # Security recommendations for alignment
        if ($result.DMARCSPFAlignment -eq "r" -and $result.DMARCDKIMAlignment -eq "r") {
            $result.DMARCIssues += "Both SPF and DKIM use relaxed alignment - consider strict alignment for enhanced security"
        }
        
        if ($result.DMARCRecord -notmatch "rua=") {
            $result.DMARCIssues += "No reporting email configured"
        }
        
        # Check TTL (Time To Live) - recommend minimum 3600 seconds (1 hour)
        if ($result.DMARCTTL -lt 3600) {
            $result.DMARCIssues += "Low TTL ($($result.DMARCTTL) seconds) - recommend minimum 3600 seconds for stability"
            Write-Host "        TTL warning: $($result.DMARCTTL) seconds (recommend 3600+)" -ForegroundColor Yellow
        } else {
            Write-Host "        TTL: $($result.DMARCTTL) seconds" -ForegroundColor Green
        }
        
        if ($result.DMARCIssues.Count -gt 0) {
            $issuesList = $result.DMARCIssues -join '; '
            Write-Host "        Warning: $issuesList" -ForegroundColor Yellow
        }
    } else {
        Write-Host "        No DMARC record found" -ForegroundColor Red
        # Set default values for missing DMARC record
        $result.DMARCPolicy = "Missing"
        $result.DMARCSubdomainPolicy = "Missing"
        $result.DMARCSPFAlignment = "Missing"
        $result.DMARCDKIMAlignment = "Missing"
        $result.DMARCTTL = 0
    }
      # CHECK DKIM RECORDS
    Write-Host "  [3/3] Checking DKIM records..." -ForegroundColor White
    # DKIM checking with fallback mechanism for better reliability
    foreach ($selector in $commonSelectors) {
        $dkimDomain = "$selector._domainkey.$domain"
        $dkimRecord = $null
        
        # Debug output
        Write-Verbose "Checking DKIM selector: $dkimDomain"
        
        # Try authoritative servers first, then fallback to regular DNS
        try {
            # Query DKIM record from authoritative servers for accurate TTL
            $dkimAuthServers = Get-AuthoritativeDNSServers $domain
            if ($dkimAuthServers.Count -gt 0) {
                Write-Verbose "Using $($dkimAuthServers.Count) authoritative servers for DKIM query"
                $dkimTxtRecords = Resolve-DnsNameAuthoritative -Name $dkimDomain -Type TXT -AuthoritativeServers $dkimAuthServers
                $dkimRecord = $dkimTxtRecords | Where-Object { 
                    # More inclusive pattern - any TXT record containing DKIM-related tags
                    ($_.Strings -join '') -match "v=DKIM1|k=|p=|t=|s=|h=" 
                } | Select-Object -First 1
            }
        }
        catch {
            Write-Verbose "Authoritative DKIM query failed for $dkimDomain`: $_"
        }
        
        # Fallback to regular DNS query if authoritative failed
        if (-not $dkimRecord) {
            try {
                Write-Verbose "Falling back to regular DNS query for $dkimDomain"
                $dkimTxtRecords = Resolve-DnsName -Name $dkimDomain -Type TXT -ErrorAction SilentlyContinue
                if ($dkimTxtRecords) {
                    Write-Verbose "Found $($dkimTxtRecords.Count) TXT records for $dkimDomain"
                    foreach ($txtRecord in $dkimTxtRecords) {
                        Write-Verbose "TXT Record: $($txtRecord.Strings -join '')"
                    }
                }
                $dkimRecord = $dkimTxtRecords | Where-Object { 
                    # More inclusive pattern - any TXT record containing DKIM-related tags
                    ($_.Strings -join '') -match "v=DKIM1|k=|p=|t=|s=|h=" 
                } | Select-Object -First 1
            }
            catch {
                Write-Verbose "Regular DKIM query failed for $dkimDomain`: $_"
            }
        }
        
        if ($dkimRecord) {
            $result.DKIMFound = $true
            $result.DKIMSelectors += $selector
            $dkimRecordString = $dkimRecord.Strings -join ""
            $result.DKIMRecords[$selector] = $dkimRecordString
            $result.DKIMTTL[$selector] = $dkimRecord.TTL
            
            # Display individual selector details
            Write-Host "        DKIM selector '$selector' found" -ForegroundColor Green
            if ($selector -eq "selector1" -or $selector -eq "selector2") {
                Write-Host "        $selector record: $dkimRecordString" -ForegroundColor Cyan
            }
            
            # Check TTL (Time To Live) - recommend minimum 3600 seconds (1 hour)
            $ttlIssues = @()
            if ($dkimRecord.TTL -lt 3600) {
                $ttlIssues += "Low TTL ($($dkimRecord.TTL) seconds) - recommend minimum 3600 seconds for stability"
                Write-Host "        $selector TTL warning: $($dkimRecord.TTL) seconds (recommend 3600+)" -ForegroundColor Yellow
            } else {
                Write-Host "        $selector TTL: $($dkimRecord.TTL) seconds" -ForegroundColor Green
            }
            $result.DKIMTTLIssues[$selector] = $ttlIssues
        }
    }
    
    if ($result.DKIMFound) {
        $selectorsList = $result.DKIMSelectors -join ', '
        Write-Host "        DKIM records found: $selectorsList" -ForegroundColor Green
        
        # Validate DKIM syntax and status for each selector
        $totalSyntaxIssues = 0
        foreach ($selector in $result.DKIMSelectors) {
            if ($result.DKIMRecords.ContainsKey($selector)) {
                $dkimRecord = $result.DKIMRecords[$selector]
                
                # Syntax validation
                $syntaxIssues = Test-DKIMSyntax $dkimRecord $selector
                $result.DKIMSyntaxIssues[$selector] = $syntaxIssues
                $totalSyntaxIssues += $syntaxIssues.Count
                
                # Key length analysis
                $keyLengthInfo = Get-DKIMKeyLength $dkimRecord
                $result.DKIMKeyLengths[$selector] = $keyLengthInfo
                
                # All mechanism status check
                $allMechanism = Get-DKIMKeyStatus $dkimRecord
                $result.DKIMAllMechanisms[$selector] = $allMechanism
                
                if ($syntaxIssues.Count -gt 0) {
                    Write-Host "        $selector syntax issues: $($syntaxIssues.Count)" -ForegroundColor Yellow
                } else {
                    Write-Host "        $selector syntax validation: PASSED" -ForegroundColor Green
                }
                
                # Display key length information
                if ($keyLengthInfo.Error) {
                    Write-Host "        $selector key length: ERROR - $($keyLengthInfo.Error)" -ForegroundColor Red
                } else {
                    $keyLengthColor = if ($keyLengthInfo.IsWeak) { "Red" } 
                                     elseif ($keyLengthInfo.KeyLength -eq 1024) { "Yellow" }
                                     else { "Green" }
                    
                    $statusText = if ($keyLengthInfo.IsWeak) { " (WEAK - recommend 2048+ bits)" }
                                 elseif ($keyLengthInfo.KeyLength -eq 1024) { " (WARNING - consider upgrading to 2048+ bits)" }
                                 else { "" }
                    
                    Write-Host "        $selector key length: $($keyLengthInfo.KeyLength) bits ($($keyLengthInfo.KeyType))$statusText" -ForegroundColor $keyLengthColor
                    
                    # Add weakness to syntax issues if key is weak
                    if ($keyLengthInfo.IsWeak -and $keyLengthInfo.KeyLength -gt 0) {
                        $syntaxIssues += "Weak key length ($($keyLengthInfo.KeyLength) bits) - recommend 2048+ bits for better security"
                        $result.DKIMSyntaxIssues[$selector] = $syntaxIssues
                        $totalSyntaxIssues++
                    }
                    
                    # Add recommendation for 1024-bit keys (warning, not weakness)
                    if ($keyLengthInfo.KeyLength -eq 1024) {
                        $recommendations += "Consider upgrading DKIM key to 2048+ bits for enhanced security (currently using 1024-bit key for selector '$selector') - Microsoft DKIM Best Practices: https://docs.microsoft.com/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email#dkim-key-sizes"
                    }
                }
                
                # Display all mechanism status
                $statusColor = switch ($allMechanism) {
                    "ACTIVE" { "Green" }
                    "TESTING" { "Yellow" }
                    "REVOKED" { "Red" }
                    "UNKNOWN" { "Yellow" }
                    default { "White" }
                }
                Write-Host "        $selector status: $allMechanism" -ForegroundColor $statusColor
                
                # Display TTL validation results
                if ($result.DKIMTTLIssues.ContainsKey($selector) -and $result.DKIMTTLIssues[$selector].Count -gt 0) {
                    $ttlIssuesList = $result.DKIMTTLIssues[$selector] -join '; '
                    Write-Host "        $selector TTL issues: $ttlIssuesList" -ForegroundColor Yellow
                } else {
                    Write-Host "        $selector TTL validation: PASSED" -ForegroundColor Green
                }
            }
        }
        
        $result.DKIMSyntaxValid = ($totalSyntaxIssues -eq 0)
        
        if ($totalSyntaxIssues -gt 0) {
            Write-Host "        Total DKIM syntax issues found: $totalSyntaxIssues" -ForegroundColor Yellow
        } else {
            Write-Host "        All DKIM syntax validation: PASSED" -ForegroundColor Green
        }
        
        # Display overall TTL validation summary
        $totalTTLIssues = 0
        foreach ($selector in $result.DKIMSelectors) {
            if ($result.DKIMTTLIssues.ContainsKey($selector)) {
                $totalTTLIssues += $result.DKIMTTLIssues[$selector].Count
            }
        }
        
        if ($totalTTLIssues -gt 0) {
            Write-Host "        Total DKIM TTL issues found: $totalTTLIssues" -ForegroundColor Yellow
        } else {
            Write-Host "        All DKIM TTL validation: PASSED" -ForegroundColor Green
        }
        
        # Enhanced DKIM Analysis
        Write-Host "        Running enhanced DKIM analysis..." -ForegroundColor Cyan
        
        # Service Provider Detection
        $providerInfo = Get-DKIMServiceProvider $result.DKIMRecords $domain
        $result | Add-Member -MemberType NoteProperty -Name "DKIMProviders" -Value $providerInfo
        
        if ($providerInfo.DetectedProviders.Count -gt 0) {
            Write-Host "        Service Provider: $($providerInfo.DetectedProviders -join ', ')" -ForegroundColor Cyan
        } else {
            Write-Host "        Service Provider: NOT IDENTIFIED (custom/self-hosted)" -ForegroundColor White
        }
        
        # Display selector1 and selector2 details if found
        if ($result.DKIMRecords.ContainsKey("selector1")) {
            Write-Host "        Selector1 Details: $($result.DKIMRecords['selector1'])" -ForegroundColor White
        }
        if ($result.DKIMRecords.ContainsKey("selector2")) {
            Write-Host "        Selector2 Details: $($result.DKIMRecords['selector2'])" -ForegroundColor White
        }
    } else {
        Write-Host "        No DKIM records found" -ForegroundColor Red
        # Initialize empty TTL issues for missing DKIM records
        $result.DKIMTTLIssues = @{}
    }
    
    # CALCULATE SCORE AND STATUS
    $score = 0
    $recommendations = @()
    
    # SPF scoring (30 points)
    if ($result.SPFFound) {
        if ($result.SPFIssues.Count -eq 0) {
            $score += 30
        } else {
            $score += 15
            # Add specific SPF recommendations based on issues found
            foreach ($issue in $result.SPFIssues) {
                $recommendations += Get-Recommendation -Issue $issue -Protocol "SPF"
            }
        }
    } else {
        $recommendations += "Implement SPF record - Microsoft Setup Guide: $($script:MSURLs.SPFSetup)"
    }
        
        # DMARC scoring (40 points)
        if ($result.DMARCFound) {
            if ($result.DMARCPolicy -eq "reject") {
                $score += 40
            } elseif ($result.DMARCPolicy -eq "quarantine") {
                $score += 30
                $recommendations += "Consider upgrading DMARC policy to 'reject' - Microsoft DMARC Guide: $($script:MSURLs.DMARCSetup)"
            } else {
                $score += 15
                $recommendations += "Upgrade DMARC policy from 'none' to 'quarantine' or 'reject' - Microsoft DMARC Implementation: $($script:MSURLs.DMARCImplementation)"
            }
            
            if ($result.DMARCIssues.Count -gt 0) {
                foreach ($issue in $result.DMARCIssues) {
                    $recommendations += Get-Recommendation -Issue $issue -Protocol "DMARC"
                }
            }
        } else {
            $recommendations += "Implement DMARC record - Microsoft DMARC Setup Guide: $($script:MSURLs.DMARCSetup)"
        }
        
        # DKIM scoring (30 points)
        if ($result.DKIMFound) {
            # Calculate total TTL issues for scoring consideration
            $totalTTLIssues = 0
            foreach ($selector in $result.DKIMSelectors) {
                if ($result.DKIMTTLIssues.ContainsKey($selector)) {
                    $totalTTLIssues += $result.DKIMTTLIssues[$selector].Count
                }
            }
            
            if ($result.DKIMSyntaxValid -and $totalTTLIssues -eq 0) {
                $score += 30  # Full points for perfect DKIM
            } elseif ($result.DKIMSyntaxValid -and $totalTTLIssues -gt 0) {
                $score += 25  # Slight deduction for TTL issues
                $recommendations += "Fix DKIM TTL issues - consider increasing TTL to 3600+ seconds for better stability and to avoid any DNS timeout issues"
            } else {
                $score += 20  # Partial credit for having DKIM but with syntax issues
                $recommendations += "Fix DKIM syntax errors - Microsoft DKIM Configuration Guide: $($script:MSURLs.DKIMConfiguration)"
                if ($totalTTLIssues -gt 0) {
                    $recommendations += "Fix DKIM TTL issues - consider increasing TTL to 3600+ seconds for better stability and to avoid any DNS timeout issues"
                }
            }
        } else {
            $recommendations += "Implement DKIM signing - Microsoft DKIM Setup Guide: $($script:MSURLs.DKIMSetup)"
        }
        
        # Determine status
        if ($score -ge 90) {
            $status = "Excellent"
            $statusColor = "Green"
        } elseif ($score -ge 70) {
            $status = "Good"
            $statusColor = "Cyan"
        } elseif ($score -ge 50) {
            $status = "Fair"
            $statusColor = "Yellow"
        } else {
            $status = "Poor"
            $statusColor = "Red"
        }
        
        $result.Score = $score
        $result.Status = $status
        $result.Recommendations = $recommendations
        
        # Display summary
        Write-Host ""
        Write-Host "  SUMMARY FOR $domain" -ForegroundColor Cyan
        Write-Host "  Score: $score/100 ($status)" -ForegroundColor $statusColor
        Write-Host "  SPF: $(if($result.SPFFound){'FOUND'}else{'MISSING'})" -NoNewline
        Write-Host " | DMARC: $(if($result.DMARCFound){'FOUND'}else{'MISSING'})" -NoNewline
        Write-Host " | DKIM: $(if($result.DKIMFound){'FOUND'}else{'MISSING'})"
        
        if ($recommendations.Count -gt 0) {
            Write-Host "  Recommendations:" -ForegroundColor Yellow
            foreach ($rec in $recommendations) {
                Write-Host "    • $rec" -ForegroundColor Yellow
            }
        }    
        Write-Host ""
        $allResults += $result
    }

# === Prompt user for the directory to save the files ===
$path = Read-Host "Enter the full path (without filename) to save the reports (e.g., C:\temp)"

# === Create directory if it doesn't exist ===
if (-not (Test-Path -Path $path)) {
    New-Item -ItemType Directory -Path $path -Force | Out-Null
}

Write-Host ""
Write-Host "Generating HTML report..." -ForegroundColor Green

# Generate timestamps and statistics
$reportDate = Get-Date -Format "MMMM d, yyyy"
$fileTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"

# Calculate overall statistics
$totalDomains = $allResults.Count
$avgScore = if ($totalDomains -gt 0) { [math]::Round(($allResults | Measure-Object -Property Score -Average).Average, 1) } else { 0 }

# Function to calculate check percentages for donut charts
function Get-ProtocolCheckPercentage {
    param(
        [PSCustomObject]$result,
        [string]$protocol
    )
    
    switch ($protocol) {
        "SPF" {
            if (-not $result.SPFFound) { return 0 }
            
            $totalChecks = 9  # Updated from 8 to 9 checks
            $passedChecks = 0
            
            # Check 1: SPF Present
            if ($result.SPFFound) { $passedChecks++ }
            
            # Check 2: Single SPF Record (no multiples)
            if ($result.SPFMultipleRecordsCheck) { $passedChecks++ }
            
            # Check 3: Macro Security
            if ($result.SPFMacroSecurityCheck) { $passedChecks++ }
            
            # Check 4: TTL for Sub-Records (A/MX records TTL >= 3600)
            if ($result.SPFSubRecordsTTLCheck) { $passedChecks++ }
            
            # Check 5: DNS Lookups (< 10)
            if ($result.SPFDNSLookups -le 10) { $passedChecks++ }
            
            # Check 6: Record Length (< 255)
            if ($result.SPFRecordLength -le 255) { $passedChecks++ }
            
            # Check 7: TTL (>= 3600)
            if ($result.SPFTTL -ge 3600) { $passedChecks++ }
            
            # Check 8: All Mechanism (strict)
            if ($result.SPFAllMechanism -eq "~all" -or $result.SPFAllMechanism -eq "-all") { $passedChecks++ }
            
            # Check 9: Syntax Valid
            if ($result.SPFSyntaxValid) { $passedChecks++ }
            
            return [math]::Round(($passedChecks / $totalChecks) * 100, 0)
        }
        
        "DMARC" {
            if (-not $result.DMARCFound) { return 0 }
            
            $totalChecks = 7  # Updated from 4 to 7 checks
            $passedChecks = 0
            
            # Check 1: DMARC Present
            if ($result.DMARCFound) { $passedChecks++ }
            
            # Check 2: Policy not 'none'
            if ($result.DMARCPolicy -ne "none") { $passedChecks++ }
            
            # Check 3: Reporting configured
            if ($result.DMARCRecord -match "rua=") { $passedChecks++ }
            
            # Check 4: Strong policy (quarantine or reject)
            if ($result.DMARCPolicy -eq "quarantine" -or $result.DMARCPolicy -eq "reject") { $passedChecks++ }
            
            # Check 5: Subdomain policy is not weaker than main policy
            $policyStrength = @{ "none" = 0; "quarantine" = 1; "reject" = 2; "Missing" = -1 }
            if ($result.DMARCSubdomainPolicy -ne "Missing" -and $result.DMARCPolicy -ne "Missing" -and $policyStrength[$result.DMARCSubdomainPolicy] -ge $policyStrength[$result.DMARCPolicy]) { $passedChecks++ }
            
            # Check 6: TTL >= 3600 seconds
            if ($result.DMARCTTL -ge 3600) { $passedChecks++ }
            
            # Check 7: At least one alignment mode is strict (enhanced security)
            if ($result.DMARCSPFAlignment -eq "s" -or $result.DMARCDKIMAlignment -eq "s") { $passedChecks++ }
            
            return [math]::Round(($passedChecks / $totalChecks) * 100, 0)
        }
        
        "DKIM" {
            if (-not $result.DKIMFound) { return 0 }
            
            $totalChecks = 5  # Updated from 4 to 5 checks (added TTL check)
            $passedChecks = 0
            
            # Check 1: DKIM Present
            if ($result.DKIMFound) { $passedChecks++ }
            
            # Check 2: Syntax Valid
            if ($result.DKIMSyntaxValid) { $passedChecks++ }
            
            # Check 3: Keys are Active (not revoked/testing)
            $activeKeys = 0
            foreach ($status in $result.DKIMAllMechanisms.Values) {
                if ($status -eq "ACTIVE") { $activeKeys++ }
            }
            if ($activeKeys -gt 0) { $passedChecks++ }
            
            # Check 4: Strong key lengths (no weak keys)
            $hasWeakKeys = $false
            foreach ($keyInfo in $result.DKIMKeyLengths.Values) {
                if ($keyInfo.IsWeak) { $hasWeakKeys = $true; break }
            }
            if (-not $hasWeakKeys) { $passedChecks++ }
            
            # Check 5: TTL >= 3600 for all DKIM selectors
            $allTTLValid = $true
            foreach ($selector in $result.DKIMSelectors) {
                if ($result.DKIMTTL.ContainsKey($selector)) {
                    if ($result.DKIMTTL[$selector] -lt 3600) {
                        $allTTLValid = $false
                        break
                    }
                }
            }
            if ($allTTLValid) { $passedChecks++ }
            
            return [math]::Round(($passedChecks / $totalChecks) * 100, 0)
        }
    }
    
    return 0
}

# Function to generate enhanced interactive segmented donut chart SVG
function New-SegmentedDonutChart {
    param($checks, $protocol)
    
    $totalChecks = $checks.Count
    $passedChecks = ($checks | Where-Object { $_.Passed }).Count
    $percentage = if($totalChecks -gt 0) { [math]::Round(($passedChecks / $totalChecks) * 100, 0) } else { 0 }
    
    $circumference = 2 * [math]::PI * 15.915
    $segmentSize = $circumference / $totalChecks
    
    # Generate unique chart ID for interactivity
    $chartId = "chart-$protocol-$(Get-Random)"
    
    $svg = @"
<svg viewBox="0 0 42 42" class="interactive-donut" id="$chartId">
    <defs>
        <filter id="glow-$protocol" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2" result="coloredBlur"/>
            <feMerge> 
                <feMergeNode in="coloredBlur"/>
                <feMergeNode in="SourceGraphic"/>
            </feMerge>
        </filter>
        <linearGradient id="grad-$protocol" x1="0%" y1="0%" x2="100%" y2="100%">
            <stop offset="0%" style="stop-color:$(if($protocol -eq 'SPF'){'#28a745'}elseif($protocol -eq 'DMARC'){'#007bff'}else{'#b007ff'});stop-opacity:1" />
            <stop offset="100%" style="stop-color:$(if($protocol -eq 'SPF'){'#20c997'}elseif($protocol -eq 'DMARC'){'#6610f2'}else{'#e83e8c'});stop-opacity:1" />
        </linearGradient>
    </defs>
    <circle class="background" cx="21" cy="21" r="15.915" fill="none" stroke="#e9ecef" stroke-width="4"></circle>
"@
    
    $currentOffset = 0
    for ($i = 0; $i -lt $checks.Count; $i++) {
        $check = $checks[$i]
        $segmentId = "$chartId-segment-$i"
        $segmentColor = if ($check.Passed) { $check.Color } else { "#dee2e6" }
        $segmentOpacity = if ($check.Passed) { "1.0" } else { "0.6" }
        
        $svg += @"
    <circle id="$segmentId" cx="21" cy="21" r="15.915" fill="none" 
        stroke="$segmentColor" 
        stroke-width="4" 
        stroke-dasharray="$segmentSize $($circumference - $segmentSize)" 
        stroke-dashoffset="$currentOffset" 
        stroke-linecap="round" 
        opacity="$segmentOpacity"
        class="chart-segment $(if($check.Passed){'passed-segment'}else{'failed-segment'})"
        data-check="$($check.Name)"
        data-status="$(if($check.Passed){'PASS'}else{'FAIL'})"
        data-protocol="$protocol"
        onmouseover="highlightSegment('$segmentId', '$($check.Name)', '$(if($check.Passed){'PASS'}else{'FAIL'})', '$protocol')"
        onmouseout="resetSegment('$segmentId')"
        style="cursor: pointer; transition: all 0.3s ease;">
    </circle>
"@
        $currentOffset -= $segmentSize
    }
    
    $svg += @"
</svg>
<div class="percentage-display">
    <div class="percentage-number">$percentage%</div>
    <div class="percentage-label">Compliant</div>
</div>
"@
    
    return $svg
}

# Function to get individual check results for segmented charts
function Get-ProtocolCheckDetails {
    param($result, $protocol)
    
    $checks = @()
    
    switch ($protocol) {
        "SPF" {
            $checks += @{
                Name = "Record Present"
                Passed = $result.SPFFound
                Color = if($result.SPFFound) { "#28a745" } else { "#dc3545" }
            }
            $checks += @{
                Name = "Single Record"
                Passed = ($result.SPFFound -and $result.SPFMultipleRecordsCheck)
                Color = if($result.SPFFound -and $result.SPFMultipleRecordsCheck) { "#28a745" } else { "#dc3545" }
            }
            $checks += @{
                Name = "Macro Security"
                Passed = ($result.SPFFound -and $result.SPFMacroSecurityCheck)
                Color = if($result.SPFFound -and $result.SPFMacroSecurityCheck) { "#28a745" } else { "#dc3545" }
            }
            $checks += @{
                Name = "TTL Sub-Records"
                Passed = ($result.SPFFound -and $result.SPFSubRecordsTTLCheck)
                Color = if($result.SPFFound -and $result.SPFSubRecordsTTLCheck) { "#28a745" } else { "#dc3545" }
            }
            $checks += @{
                Name = "DNS Lookups < 10"
                Passed = ($result.SPFFound -and $result.SPFDNSLookups -le 10)
                Color = if($result.SPFFound -and $result.SPFDNSLookups -le 10) { "#28a745" } else { "#dc3545" }
            }
            $checks += @{
                Name = "Record Length < 255"
                Passed = ($result.SPFFound -and $result.SPFRecordLength -le 255)
                Color = if($result.SPFFound -and $result.SPFRecordLength -le 255) { "#28a745" } else { "#dc3545" }
            }
            $checks += @{
                Name = "TTL >= 3600"
                Passed = ($result.SPFFound -and $result.SPFTTL -ge 3600)
                Color = if($result.SPFFound -and $result.SPFTTL -ge 3600) { "#28a745" } else { "#dc3545" }
            }
            $checks += @{
                Name = "Strict All Mechanism"
                Passed = ($result.SPFFound -and ($result.SPFAllMechanism -eq "~all" -or $result.SPFAllMechanism -eq "-all"))
                Color = if($result.SPFFound -and ($result.SPFAllMechanism -eq "~all" -or $result.SPFAllMechanism -eq "-all")) { "#28a745" } else { "#dc3545" }
            }
            $checks += @{
                Name = "Syntax Valid"
                Passed = ($result.SPFFound -and $result.SPFSyntaxValid)
                Color = if($result.SPFFound -and $result.SPFSyntaxValid) { "#28a745" } else { "#dc3545" }
            }
        }
        
        "DMARC" {
            $checks += @{
                Name = "Record Present"
                Passed = $result.DMARCFound
                Color = if($result.DMARCFound) { "#007bff" } else { "#dc3545" }
            }
            $checks += @{
                Name = "Policy Not None"
                Passed = ($result.DMARCFound -and $result.DMARCPolicy -ne "none")
                Color = if($result.DMARCFound -and $result.DMARCPolicy -ne "none") { "#007bff" } else { "#dc3545" }
            }
            $checks += @{
                Name = "Reporting Configured"
                Passed = ($result.DMARCFound -and $result.DMARCRecord -match "rua=")
                Color = if($result.DMARCFound -and $result.DMARCRecord -match "rua=") { "#007bff" } else { "#dc3545" }
            }
            $checks += @{
                Name = "Strong Policy"
                Passed = ($result.DMARCFound -and ($result.DMARCPolicy -eq "quarantine" -or $result.DMARCPolicy -eq "reject"))
                Color = if($result.DMARCFound -and ($result.DMARCPolicy -eq "quarantine" -or $result.DMARCPolicy -eq "reject")) { "#007bff" } else { "#dc3545" }
            }
            $checks += @{
                Name = "Subdomain Policy"
                Passed = ($result.DMARCFound -and $result.DMARCSubdomainPolicy -ne "Missing" -and ($result.DMARCSubdomainPolicy -eq $result.DMARCPolicy -or $result.DMARCSubdomainPolicy -eq "quarantine" -or $result.DMARCSubdomainPolicy -eq "reject"))
                Color = if($result.DMARCFound -and $result.DMARCSubdomainPolicy -ne "Missing" -and ($result.DMARCSubdomainPolicy -eq $result.DMARCPolicy -or $result.DMARCSubdomainPolicy -eq "quarantine" -or $result.DMARCSubdomainPolicy -eq "reject")) { "#007bff" } else { "#dc3545" }
            }
            $checks += @{
                Name = "TTL >= 3600"
                Passed = ($result.DMARCFound -and $result.DMARCTTL -ge 3600)
                Color = if($result.DMARCFound -and $result.DMARCTTL -ge 3600) { "#007bff" } else { "#dc3545" }
            }
            $checks += @{
                Name = "Strict Alignment"
                Passed = ($result.DMARCFound -and ($result.DMARCSPFAlignment -eq "s" -or $result.DMARCDKIMAlignment -eq "s"))
                Color = if($result.DMARCFound -and ($result.DMARCSPFAlignment -eq "s" -or $result.DMARCDKIMAlignment -eq "s")) { "#007bff" } else { "#dc3545" }
            }
        }
        
        "DKIM" {
            $checks += @{
                Name = "Record Present"
                Passed = $result.DKIMFound
                Color = if($result.DKIMFound) { "#b007ff" } else { "#dc3545" }
            }
            $checks += @{
                Name = "Syntax Valid"
                Passed = ($result.DKIMFound -and $result.DKIMSyntaxValid)
                Color = if($result.DKIMFound -and $result.DKIMSyntaxValid) { "#b007ff" } else { "#dc3545" }
            }
            
            $activeKeys = 0
            foreach ($status in $result.DKIMAllMechanisms.Values) {
                if ($status -eq "ACTIVE") { $activeKeys++ }
            }
            $checks += @{
                Name = "Keys Active"
                Passed = ($result.DKIMFound -and $activeKeys -gt 0)
                Color = if($result.DKIMFound -and $activeKeys -gt 0) { "#b007ff" } else { "#dc3545" }
            }
            
            $hasWeakKeys = $false
            foreach ($keyInfo in $result.DKIMKeyLengths.Values) {
                if ($keyInfo.IsWeak) { $hasWeakKeys = $true; break }
            }
            $checks += @{
                Name = "Strong Keys"
                Passed = ($result.DKIMFound -and -not $hasWeakKeys)
                Color = if($result.DKIMFound -and -not $hasWeakKeys) { "#b007ff" } else { "#dc3545" }
            }
            
            # Check TTL for all DKIM selectors
            $allTTLValid = $true
            if ($result.DKIMFound) {
                foreach ($selector in $result.DKIMSelectors) {
                    if ($result.DKIMTTL.ContainsKey($selector)) {
                        if ($result.DKIMTTL[$selector] -lt 3600) {
                            $allTTLValid = $false
                            break
                        }
                    }
                }
            } else {
                $allTTLValid = $false
            }
            $checks += @{
                Name = "TTL >= 3600"
                Passed = ($result.DKIMFound -and $allTTLValid)
                Color = if($result.DKIMFound -and $allTTLValid) { "#b007ff" } else { "#dc3545" }
            }
            
        }
    }
    
    return $checks
}

# Add check percentages to results
foreach ($result in $allResults) {
    $spfPercentage = Get-ProtocolCheckPercentage $result "SPF"
    $dmarcPercentage = Get-ProtocolCheckPercentage $result "DMARC"  
    $dkimPercentage = Get-ProtocolCheckPercentage $result "DKIM"
    
    $result | Add-Member -MemberType NoteProperty -Name "SPFCheckPercentage" -Value $spfPercentage
    $result | Add-Member -MemberType NoteProperty -Name "DMARCCheckPercentage" -Value $dmarcPercentage
    $result | Add-Member -MemberType NoteProperty -Name "DKIMCheckPercentage" -Value $dkimPercentage
}

# Start building HTML content
$html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Email Authentication Report with Microsoft Documentation</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background-color: #f5f7fa; 
        }
        .header { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            padding: 30px; 
            border-radius: 15px; 
            margin-bottom: 30px; 
            text-align: center;
            box-shadow: 0 4px 15px rgba(0,0,0,0.2);
        }
        .header h1 {
            margin:  0;
            font-size: 2.5em;
            font-weight: 300;
        }
        .header p {
            margin: 10px 0 0 0;
            opacity: 0.9;
            font-size: 1.1em;
        }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .summary-card {
            background: white;
            padding: 25px;
            border-radius:  12px;
            box-shadow: 0 3px 10px rgba(0,0,0,0.1);
            text-align: center;
            border-left: 5px solid #b200ff;
        }
        .summary-card h3 {
            margin: 0 0 10px 0;
            color: #495057;
            font-size: 1.1em;
        }
        .summary-card .number {
            font-size: 2.5em;
            font-weight: bold;
            color: #007bff;
            margin: 10px 0;
        }
        .domain-section { 
            background: white; 
            border-radius: 12px; 
            padding: 25px; 
            margin-bottom: 25px; 
            box-shadow: 0 3px 15px rgba(0,0,0,0.1); 
            border-left: 5px solid #28a745;
        }
        .domain-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
            flex-wrap: wrap;
            gap: 15px;
        }
        .domain-name {
            font-size: 1.8em;
            font-weight: 600;
            color: #2c3e50;
            margin: 0;
        }
        .score-section {
            display: flex;
            align-items: center;
            gap: 15px;
        }
        .status-excellent { color: #28a745; font-weight: bold; }
        .status-good { color: #17a2b8; font-weight: bold; }
        .status-fair { color: #ffc107; font-weight: bold; }
        .status-poor { color: #fd7e14; font-weight: bold; }
        .status-critical { color: #dc3545; font-weight: bold; }
        .record-found { color: #28a745; font-weight: 600; }
        .record-missing { color: #dc3545; font-weight: 600; }
        .auth-table { 
            width: 100%; 
            border-collapse: collapse; 
            margin: 20px 0; 
            border-radius: 8px;
            overflow: hidden;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .auth-table th, .auth-table td { 
            padding: 15px; 
            text-align: left; 
            border-bottom: 1px solid #e9ecef; 
        }
        .auth-table th { 
            background-color: #f8f9fa; 
        }   
        .auth-table tr:hover {
            background-color: #f8f9fa;
        }
        .auth-table .record-type {
            vertical-align: top;
            width: 20%;
            font-weight: bold;
        }
        .auth-table .record-value {
            vertical-align: top;
            line-height: 1.5;
            word-break: break-all;
            max-width: 0;
        }
        
        /* Donut Chart Styles */
        .charts-section {
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin: 25px 0;
            box-shadow: 0 3px 15px rgba(0,0,0,0.1);
        }
        .charts-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 30px;
            margin-top: 25px;
        }
        .chart-container {
            text-align: center;
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 8px 25px rgba(0,0,0,0.1);
            transition: all 0.3s ease;
            position: relative;
            overflow: hidden;
        }
        .chart-container:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 35px rgba(0,0,0,0.15);
        }
        .chart-container.enhanced-chart {
            border-top: 4px solid transparent;
        }
        .chart-container[data-protocol="SPF"] {
            border-top-color: #28a745;
        }
        .chart-container[data-protocol="DMARC"] {
            border-top-color: #007bff;
        }
        .chart-container[data-protocol="DKIM"] {
            border-top-color: #b007ff;
        }
        .chart-header {
            display: flex;
            align-items: center;
            justify-content: center;
            margin-bottom: 20px;
            gap: 15px;
        }
        .protocol-icon {
            font-size: 13px;
            animation: pulse 2s infinite;
            display: flex;
            align-items: center;
            justify-content: center;
            width: 80px;
            height: 48px;
            border-radius: 12px;
            color: white;
            font-weight: bold;
            text-align: center;
        }
        .protocol-icon.spf-icon {
            background: linear-gradient(135deg, #28a745, #20c997);
        }
        .protocol-icon.dmarc-icon {
            background: linear-gradient(135deg, #007bff, #6610f2);
        }
        .protocol-icon.dkim-icon {
            background: linear-gradient(135deg, #b007ff, #e83e8c);
        }
        @keyframes pulse {
            0% { transform: scale(1); }
            50% { transform: scale(1.1); }
            100% { transform: scale(1); }
        }
        .status-icon {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            width: 16px;
            height: 16px;
            border-radius: 50%;
            font-size: 10px;
            font-weight: bold;
            color: white;
        }
        .status-icon.pass {
            background: #28a745;
        }
        .status-icon.fail {
            background: #dc3545;
        }
        .chart-icon {
            display: inline-block;
            font-size: 20px;
            margin-right: 8px;
        }
        .chart-title-section {
            text-align: left;
        }
        .chart-title {
            font-size: 20px;
            font-weight: 700;
            color: #2c3e50;
            margin-bottom: 2px;
        }
        .chart-subtitle {
            font-size: 12px;
            color: #6c757d;
            font-weight: 500;
        }
        .donut-chart-container {
            position: relative;
            width: 180px;
            height: 180px;
            margin: 0 auto 20px;
        }
        .interactive-donut {
            width: 100%;
            height: 100%;
            transform: rotate(-90deg);
            transition: transform 0.3s ease;
        }
        .interactive-donut:hover {
            transform: rotate(-90deg) scale(1.05);
        }
        .chart-segment {
            transition: all 0.3s ease;
            filter: drop-shadow(0 2px 4px rgba(0,0,0,0.1));
        }
        .chart-segment:hover {
            stroke-width: 5;
            filter: drop-shadow(0 4px 8px rgba(0,0,0,0.2));
        }
        .percentage-display {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }
        .percentage-number {
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
            line-height: 1;
        }
        .percentage-label {
            font-size: 11px;
            color: #6c757d;
            font-weight: 500;
            margin-top: 2px;
        }
        .enhanced-legend {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 10px;
            margin-top: 20px;
            font-size: 12px;
        }
        .legend-item {
            display: flex;
            align-items: center;
            gap: 8px;
            padding: 8px;
            border-radius: 6px;
            transition: all 0.2s ease;
            cursor: pointer;
        }
        .legend-item:hover {
            background: #f8f9fa;
            transform: translateX(3px);
        }
        .legend-item.legend-passed {
            border-left: 3px solid #28a745;
        }
        .legend-item.legend-failed {
            border-left: 3px solid #dc3545;
        }
        .legend-icon {
            font-size: 14px;
            flex-shrink: 0;
        }
        .legend-text {
            line-height: 1.2;
            font-weight: 500;
        }
        .protocol-summary-bar {
            display: flex;
            justify-content: space-around;
            background: linear-gradient(135deg, #f8f9fa 0%, #e9ecef 100%);
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 25px;
            border: 1px solid #dee2e6;
        }
        .summary-item {
            text-align: center;
        }
        .summary-label {
            display: block;
            font-size: 12px;
            color: #6c757d;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .summary-value {
            display: block;
            font-size: 24px;
            font-weight: bold;
            color: #2c3e50;
            margin-top: 5px;
        }
        .summary-value.passed-count {
            color: #28a745;
        }
        .summary-value.failed-count {
            color: #dc3545;
        }
        .summary-value.overall-score {
            color: #007bff;
        }
        .protocol-details-toggle {
            margin-top: 15px;
            padding: 8px 15px;
            background: #f8f9fa;
            border: 1px solid #dee2e6;
            border-radius: 20px;
            cursor: pointer;
            transition: all 0.2s ease;
            font-size: 12px;
            font-weight: bold;
            text-align: center;
            user-select: none;
        }
        .protocol-details-toggle:hover {
            background: #e9ecef;
            border-color: #adb5bd;
            transform: translateY(-1px);
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        }
        .protocol-details-toggle:active {
            transform: translateY(0);
        }
        .toggle-arrow {
            transition: transform 0.2s ease;
        }
        .protocol-details-toggle.expanded .toggle-arrow {
            transform: rotate(180deg);
        }
        .protocol-details {
            margin-top: 15px;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            animation: slideDown 0.3s ease;
            border: 1px solid #e9ecef;
            box-shadow: 0 2px 8px rgba(0,0,0,0.05);
            width: 100%;
            max-width: 100%;
            box-sizing: border-box;
            overflow: hidden;
        }
        @keyframes slideDown {
            from { opacity: 0; max-height: 0; }
            to { opacity: 1; max-height: 300px; }
        }
        .detail-item {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            padding: 5px 0;
            border-bottom: 1px solid #dee2e6;
            flex-wrap: wrap;
            width: 100%;
            max-width: 100%;
            box-sizing: border-box;
        }
        .detail-item:last-child {
            border-bottom: none;
        }
        .detail-item[style*="flex-direction: column"] {
            align-items: flex-start;
            width: 100%;
        }
        .detail-label {
            font-size: 12px;
            font-weight: bold;
        }
        .detail-value {
            font-size: 14px;
            color: #5a3899;
            font-weight: bold;
        }
        .record-value-container {
            display: flex;
            flex-direction: column;
            gap: 8px;
            margin-top: 10px;
            padding: 10px;
            background: #ffffff;
            border: 1px solid #dee2e6;
            border-radius: 6px;
            width: 100%;
            max-width: 100%;
            box-sizing: border-box;
        }
        .record-value-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 8px;
        }
        .record-value-text {
            font-family: 'Courier New', monospace;
            font-size: 11px;
            word-break: break-all;
            word-wrap: break-word;
            overflow-wrap: break-word;
            line-height: 1.6;
            max-height: 80px;
            overflow-y: auto;
            padding: 8px;
            background: #f8f9fa;
            border-radius: 4px;
            white-space: pre-wrap;
            width: 100%;
            max-width: 100%;
            box-sizing: border-box;
            text-align: left;
        }
        .copy-button {
            background: #007bff;
            color: white;
            border: none;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 10px;
            cursor: pointer;
            transition: all 0.2s ease;
            min-width: 60px;
        }
        .copy-button:hover {
            background: #0056b3;
            transform: translateY(-1px);
        }
        .copy-button:active {
            transform: translateY(0);
        }
        .copy-button.copied {
            background: #28a745;
        }
        .chart-tooltip {
            position: fixed;
            background: #2c3e50;
            color: white;
            padding: 12px 16px;
            border-radius: 8px;
            font-size: 12px;
            z-index: 1000;
            pointer-events: none;
            opacity: 0;
            transition: all 0.2s ease;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            max-width: 250px;
        }
        .chart-tooltip.visible {
            opacity: 1;
        }
        .tooltip-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            padding-bottom: 8px;
            border-bottom: 1px solid rgba(255,255,255,0.2);
        }
        .tooltip-protocol {
            font-weight: bold;
            font-size: 13px;
        }
        .tooltip-status {
            font-size: 11px;
            padding: 2px 6px;
            border-radius: 4px;
            background: rgba(255,255,255,0.2);
        }
        .tooltip-check {
            font-weight: 600;
            margin-bottom: 4px;
        }
        .tooltip-description {
            font-size: 11px;
            opacity: 0.9;
            line-height: 1.3;
        }
        .protocol-comparison {
            margin-top: 30px;
            padding: 25px;
            background: white;
            border-radius: 15px;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
        }
        .protocol-comparison h4 {
            margin: 0 0 20px 0;
            color: #2c3e50;
            font-weight: 600;
            text-align: center;
        }
        .comparison-bars {
            display: grid;
            gap: 15px;
        }
        .comparison-item {
            display: grid;
            grid-template-columns: 60px 1fr 50px;
            align-items: center;
            gap: 15px;
        }
        .comparison-label {
            font-weight: 600;
            color: #2c3e50;
            font-size: 14px;
        }
        .comparison-bar {
            height: 25px;
            background: #e9ecef;
            border-radius: 12px;
            overflow: hidden;
            position: relative;
        }
        .comparison-fill {
            height: 100%;
            border-radius: 12px;
            transition: width 1.5s ease;
            position: relative;
            background: linear-gradient(90deg, transparent 0%, rgba(255,255,255,0.3) 50%, transparent 100%);
            background-size: 200% 100%;
            animation: shimmer 2s infinite;
        }
        @keyframes shimmer {
            0% { background-position: -200% 0; }
            100% { background-position: 200% 0; }
        }
        .comparison-fill.spf-fill {
            background: linear-gradient(90deg, #28a745, #20c997);
        }
        .comparison-fill.dmarc-fill {
            background: linear-gradient(90deg, #007bff, #6610f2);
        }
        .comparison-fill.dkim-fill {
            background: linear-gradient(90deg, #b007ff, #e83e8c);
        }
        .comparison-value {
            font-weight: bold;
            color: #2c3e50;
            text-align: right;
            font-size: 14px;
        }
        .recommendations { 
            background: linear-gradient(135deg, #fff3cd 0%, #ffeaa7 100%); 
            border: 1px solid #ffeaa7; 
            border-radius: 10px; 
            padding: 20px; 
            margin-top: 20px; 
            border-left: 3px solid #ab7517;
        }
        .recommendations h4 {
            margin-top: 0;
            color: #856404;
        }
        .recommendations ul {
            margin-bottom: 0;
        }
        .recommendations li {
            margin-bottom: 12px;
            color: #856404;
            line-height: 1.5;
        }
        .recommendations a {
            color: #0066cc;
            text-decoration: none;
            font-weight: 500;
        }
        .recommendations a:hover {
            text-decoration: underline;
        }
        .microsoft-resources {
            background: linear-gradient(135deg, #e3f2fd 0%, #bbdefb 100%);
            border: 1px solid #bbdefb;
            border-radius: 10px;
            padding: 20px;
            margin-top: 20px;
        }
        .microsoft-resources h4 {
            margin-top: 0;
            color: #1565c0;
        }
        .microsoft-resources ul {
            margin-bottom: 0;
        }
        .microsoft-resources li {
            margin-bottom: 8px;
            color: #1976d2;
        }
        .microsoft-resources a {
            color: #0d47a1;
            text-decoration: none;
            font-weight: 500;
        }
        .microsoft-resources a:hover {
            text-decoration: underline;
        }
        .score-badge { 
            display: inline-block; 
            background: linear-gradient(135deg, #007bff 0%, #0056b3 100%); 
            color: white; 
            padding: 8px 16px; 
            border-radius: 20px; 
            font-weight: bold; 
            font-size: 1.1em;
        }
        .progress-bar {
            width: 100%;
            height: 25px;
            background-color: #e9ecef;
            border-radius: 12px;
            overflow: hidden;
            margin: 10px 0;
        }
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #28a745 0%, #20c997 100%);
            border-radius: 12px;
            transition: width 0.3s ease;
            display: flex;
            align-items: center;
            justify-content: center;
            color: white;
            font-weight: bold;
            font-size: 0.9em;
        }
        .record-details {
            border-radius: 6px;
            padding: 10px;
            margin-top: 10px;
            word-break: break-all;
            border-left: 3px solid #007bff;
        }
        .icon {
            font-size: 1.2em;
            margin-right: 8px;
        }
        .footer {
            background: white;
            border-radius: 12px;
            padding: 25px;
            margin-top: 30px;
            box-shadow: 0 3px 15px rgba(0,0,0,0.1);
            text-align: center;
        }
        .legend {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin-top: 20px;
        }
        .legend-item {
            text-align: center;
            padding: 10px;
        }
        
        @media (max-width: 768px) {
            .domain-header {
                flex-direction: column;
                align-items: flex-start;
            }
            
            .summary-cards {
                grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            }
        }
    </style>
    <script>
        // Protocol Details Toggle Functionality
        function toggleProtocolDetails(detailsId) {
            const details = document.getElementById(detailsId);
            const toggle = details.previousElementSibling;
            const arrow = toggle.querySelector('.toggle-arrow');
            
            if (details.style.display === 'none' || details.style.display === '') {
                details.style.display = 'block';
                arrow.innerHTML = '&uarr;';
                toggle.classList.add('expanded');
                
                // Smooth scroll to the details section
                setTimeout(() => {
                    details.scrollIntoView({ 
                        behavior: 'smooth', 
                        block: 'nearest',
                        inline: 'nearest'
                    });
                }, 100);
            } else {
                details.style.display = 'none';
                arrow.innerHTML = '&darr;';
                toggle.classList.remove('expanded');
            }
        }
        
        // Interactive Chart Functionality
        function highlightSegment(segmentId, checkName, status, protocol) {
            const segment = document.getElementById(segmentId);
            const tooltip = document.getElementById('chart-tooltip');
            
            // Highlight the segment
            segment.style.strokeWidth = '6';
            segment.style.filter = 'drop-shadow(0 4px 12px rgba(0,0,0,0.3))';
            
            // Show tooltip
            const protocolElement = tooltip.querySelector('.tooltip-protocol');
            const statusElement = tooltip.querySelector('.tooltip-status');
            const checkElement = tooltip.querySelector('.tooltip-check');
            const descriptionElement = tooltip.querySelector('.tooltip-description');
            
            protocolElement.textContent = protocol;
            statusElement.textContent = status;
            statusElement.style.backgroundColor = status === 'PASS' ? '#28a745' : '#dc3545';
            checkElement.textContent = checkName;
            
            // Add descriptions for different checks
            const descriptions = {
                'Record Present': 'Checks if the DNS record exists for this domain',
                'Single Record': 'Ensures only one SPF record exists (RFC requirement)',
                'Macro Security': 'Validates safe usage of SPF macros',
                'TTL Sub-Records': 'Verifies TTL values for A/MX records referenced in SPF',
                'DNS Lookups < 10': 'SPF records must not exceed 10 DNS lookups',
                'Record Length < 255': 'DNS TXT records have a 255 character limit',
                'TTL >= 3600': 'Minimum recommended TTL for DNS stability',
                'Strict All Mechanism': 'Uses ~all or -all for proper email protection',
                'Syntax Valid': 'Record follows correct syntax standards',
                'Policy Not None': 'DMARC policy should enforce actions (not just monitor)',
                'Reporting Configured': 'RUA/RUF tags configured for DMARC reporting',
                'Strong Policy': 'Uses quarantine or reject policy for security',
                'Keys Active': 'DKIM keys are active and not revoked',
                'Strong Keys': 'Key lengths meet security standards (1024+ bits)',
                'Subdomain Policy': 'Explicit DKIM policy configuration for subdomains',
                'Key Age Tracking': 'DKIM key expiration and rotation tracking available',
                'Canonicalization': 'Optimal DKIM canonicalization methods configured'
            };
            
            descriptionElement.textContent = descriptions[checkName] || 'Security check validation';
            
            // Position tooltip
            tooltip.style.left = event.pageX + 10 + 'px';
            tooltip.style.top = event.pageY - 10 + 'px';
            tooltip.classList.add('visible');
        }
        
        function resetSegment(segmentId) {
            const segment = document.getElementById(segmentId);
            const tooltip = document.getElementById('chart-tooltip');
            
            // Reset segment styling
            segment.style.strokeWidth = '4';
            segment.style.filter = 'drop-shadow(0 2px 4px rgba(0,0,0,0.1))';
            
            // Hide tooltip
            tooltip.classList.remove('visible');
        }
        
        // Copy to clipboard functionality
        function copyToClipboard(text, buttonId) {
            navigator.clipboard.writeText(text).then(function() {
                const button = document.getElementById(buttonId);
                const originalText = button.textContent;
                button.textContent = 'Copied!';
                button.classList.add('copied');
                
                setTimeout(function() {
                    button.textContent = originalText;
                    button.classList.remove('copied');
                }, 2000);
            }).catch(function(err) {
                // Fallback for older browsers
                const textArea = document.createElement('textarea');
                textArea.value = text;
                document.body.appendChild(textArea);
                textArea.select();
                document.execCommand('copy');
                document.body.removeChild(textArea);
                
                const button = document.getElementById(buttonId);
                const originalText = button.textContent;
                button.textContent = 'Copied!';
                button.classList.add('copied');
                
                setTimeout(function() {
                    button.textContent = originalText;
                    button.classList.remove('copied');
                }, 2000);
            });
        }
        
        // Calculate and update summary counts
        function updateSummaryCounts() {
            const domains = document.querySelectorAll('.domain-section');
            domains.forEach((domain, index) => {
                const passedElements = domain.querySelectorAll('.legend-item.legend-passed');
                const failedElements = domain.querySelectorAll('.legend-item.legend-failed');
                
                const passedCount = passedElements.length;
                const failedCount = failedElements.length;
                
                // Find the passed/failed count elements in this domain
                const passedCountElement = domain.querySelector('.passed-count');
                const failedCountElement = domain.querySelector('.failed-count');
                
                if (passedCountElement) passedCountElement.textContent = passedCount;
                if (failedCountElement) failedCountElement.textContent = failedCount;
            });
        }
        
        // Initialize interactive features
        document.addEventListener('DOMContentLoaded', function() {
            // Initialize interactive features
            updateSummaryCounts();
            
            // Add hover effects to legend items
            const legendItems = document.querySelectorAll('.legend-item');
            legendItems.forEach(item => {
                item.addEventListener('mouseenter', function() {
                    const checkName = this.getAttribute('data-check');
                    const protocol = this.getAttribute('data-protocol');
                    
                    // Find corresponding chart segment
                    const chartContainer = this.closest('.chart-container');
                    const segments = chartContainer.querySelectorAll('.chart-segment');
                    segments.forEach(segment => {
                        if (segment.getAttribute('data-check') === checkName) {
                            segment.style.strokeWidth = '6';
                            segment.style.filter = 'drop-shadow(0 4px 12px rgba(0,0,0,0.3))';
                        }
                    });
                });
                
                item.addEventListener('mouseleave', function() {
                    const checkName = this.getAttribute('data-check');
                    const chartContainer = this.closest('.chart-container');
                    const segments = chartContainer.querySelectorAll('.chart-segment');
                    segments.forEach(segment => {
                        if (segment.getAttribute('data-check') === checkName) {
                            segment.style.strokeWidth = '4';
                            segment.style.filter = 'drop-shadow(0 2px 4px rgba(0,0,0,0.1))';
                        }
                    });
                });
            });
        });
    </script>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1><span class="chart-icon">&#128231;</span>Email Authentication Report</h1>
            <p>Analyzing SPF, DKIM, and DMARC records</p>
            <p>Generated on $reportDate at $(Get-Date -Format "HH:mm:ss")</p>
        </div>
        
        <div class="summary-section">
            <h2 class="summary-title">Analysis Summary</h2>
            <div class="summary-cards">
                <div class="summary-card">
                    <h3>Total Domains</h3>
                    <div class="number">$totalDomains</div>
                    <div class="label">Analyzed</div>
                </div>
                <div class="summary-card">
                    <h3>Average Score</h3>
                    <div class="number">$avgScore</div>
                    <div class="label">Out of 100</div>
                </div>
   
            </div>
        </div>
        
        <div class="content">
"@

# Add domain sections
$domainIndex = 0
foreach ($result in $allResults) {
    $domainIndex++
    $domainId = ($result.Domain -replace '[^a-zA-Z0-9]', '') + $domainIndex  # Create safe ID from domain name + index
    
    $statusClass = switch ($result.Status) {
        "Excellent" { "status-excellent" }
        "Good" { "status-good" }
        "Fair" { "status-fair" }
        "Poor" { "status-poor" }
        "Critical" { "status-critical" }
    }
    
    $progressWidth = $result.Score
    $progressText = "$($result.Score)%"
    
    # Set progress bar color based on score
    $progressColor = if ($result.Score -ge 80) { "linear-gradient(90deg, #28a745 0%, #20c997 100%)" }
                     elseif ($result.Score -ge 60) { "linear-gradient(90deg, #17a2b8 0%, #138496 100%)" }
                     elseif ($result.Score -ge 40) { "linear-gradient(90deg, #ffc107 0%, #e0a800 100%)" }
                     else { "linear-gradient(90deg, #fd7e14 0%, #e55353 100%)" }
    
    $html += @"
    <div class="domain-section">
        <div class="domain-header">
            <h2 class="domain-name"><span class="chart-icon">&#127760;</span>$($result.Domain)</h2>
            <div class="score-section">
                <span class="score-badge">Score: $($result.Score)/100</span> 
                <span class="$statusClass">$($result.Status)</span>
            </div>
        </div>
        
        <div class="progress-bar">
            <div class="progress-fill" style="width: $progressWidth%; background: $progressColor;">$progressText</div>
        </div>
        
        <div class="charts-section">
            <h3><span class="chart-icon">&#128202;</span>Protocol Health Overview</h3>
            <div class="protocol-summary-bar">
                <div class="summary-item">
                    <span class="summary-label">Total Checks:</span>
                    <span class="summary-value">21</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Passed:</span>
                    <span class="summary-value passed-count" id="passed-count-$domainId">0</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Failed:</span>
                    <span class="summary-value failed-count" id="failed-count-$domainId">0</span>
                </div>
                <div class="summary-item">
                    <span class="summary-label">Overall:</span>
                    <span class="summary-value overall-score">$($result.Score)%</span>
                </div>
            </div>
            
            <div class="charts-grid">
                <div class="chart-container enhanced-chart" data-protocol="SPF">
                    <div class="chart-header">
                        <div class="protocol-icon spf-icon">SPF</div>
                        <div class="chart-title-section">
                            <div class="chart-title">SPF Protection</div>
                            <div class="chart-subtitle">Sender Policy Framework</div>
                        </div>
                    </div>
                    <div class="donut-chart-container">
$(New-SegmentedDonutChart (Get-ProtocolCheckDetails $result "SPF") "SPF")
                    </div>
                    <div class="chart-status $(if($result.SPFCheckPercentage -ge 90){'excellent'}elseif($result.SPFCheckPercentage -ge 70){'good'}elseif($result.SPFCheckPercentage -ge 50){'fair'}else{'poor'})">
                        $(if($result.SPFFound){"$($result.SPFCheckPercentage)% Compliant"}else{"Not Configured"})
                    </div>
                    <div class="segment-legend enhanced-legend" id="spf-legend-$domainId">
$((Get-ProtocolCheckDetails $result "SPF") | ForEach-Object {
    $statusIcon = if($_.Passed) { "<span class='status-icon pass'>&check;</span>" } else { "<span class='status-icon fail'>&times;</span>" }
    $statusClass = if($_.Passed) { "legend-passed" } else { "legend-failed" }
    "<div class='legend-item $statusClass' data-check='$($_.Name)' data-protocol='SPF'><div class='legend-icon'>$statusIcon</div><div class='legend-text'>$($_.Name)</div></div>"
} | Out-String)
                    </div>
                    <div class="protocol-details-toggle" onclick="toggleProtocolDetails('spf-details-$domainId')">
                        <span>View Details</span> <span class="toggle-arrow">&darr;</span>
                    </div>
                    <div class="protocol-details" id="spf-details-$domainId" style="display: none;">
                        <div class="detail-item">
                            <span class="detail-label">Record Length:</span>
                            <span class="detail-value">$($result.SPFRecordLength) chars</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">DNS Lookups:</span>
                            <span class="detail-value">$($result.SPFDNSLookups)/10</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">TTL:</span>
                            <span class="detail-value">$($result.SPFTTL) seconds</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Single Record:</span>
                            <span class="detail-value">$(if(-not $result.SPFFound) { 'Missing record' } elseif($result.SPFMultipleRecordsCheck) { 'Yes' } else { 'Multiple records found' })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Macro Security:</span>
                            <span class="detail-value">$(if(-not $result.SPFFound) { 'Missing' } elseif($result.SPFMacroSecurityCheck) { 'Safe Macro Usage' } else { 'Review Macro Security' })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">TTL Sub-Records:</span>
                            <span class="detail-value">$(if(-not $result.SPFFound) { 'Missing' } elseif($result.SPFSubRecordsTTLCheck) { 'A/MX records TTL &ge;3600s' } else { 'Low TTL on A/MX records' })</span>
                        </div>
$(if($result.SPFSubRecordsTTLValues -and $result.SPFSubRecordsTTLValues.Count -gt 0) {
"                        <div class='detail-item' style='flex-direction: column; align-items: flex-start;'>
                            <span class='detail-label'>Sub-Record TTL Details:</span>
                            <div class='record-value-container'>
                                <div class='record-value-header'>
                                    <span style='font-size: 11px; color: #6c757d;'>A/MX record TTL values referenced in SPF</span>
                                </div>
                                <div class='record-value-text'>$(($result.SPFSubRecordsTTLValues.GetEnumerator() | ForEach-Object { "<strong>$($_.Key):</strong> $($_.Value)" }) -join "<br>")</div>
                            </div>
                        </div>"
})
                        <div class="detail-item">
                            <span class="detail-label">All Mechanism:</span>
                            <span class="detail-value">$(
                                if(-not $result.SPFFound) { 'Missing' } else {
                                    switch ($result.SPFAllMechanism) {
                                        '+all' { '+all (CRITICAL - allows any server)' }
                                        '?all' { '?all (WEAK - neutral protection)' }
                                        '~all' { '~all (GOOD - soft fail)' }
                                        '-all' { '-all (STRICT - hard fail)' }
                                        'Missing' { 'Missing' }
                                        '' { 'MISSING (incomplete policy)' }
                                        default { $result.SPFAllMechanism }
                                    }
                                }
                            )</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Syntax:</span>
                            <span class="detail-value">$(if($result.SPFSyntaxValid) { 'Valid' } else { 'Invalid' })</span>
                        </div>
                        <div class="detail-item" style="flex-direction: column; align-items: flex-start;">
                            <span class="detail-label">SPF Record:</span>
                            <div class="record-value-container">
                                <div class="record-value-header">
                                    <span style="font-size: 11px;">Click to copy record value</span>
                                    <button class="copy-button" id="copy-spf-$domainId" onclick="copyToClipboard('$(if($result.SPFRecord) { $result.SPFRecord -replace "'", "\'" } else { "No SPF record found" })', 'copy-spf-$domainId')">Copy</button>
                                </div>
                                <div class="record-value-text">$(if($result.SPFRecord) { $result.SPFRecord } else { "No SPF record found" })</div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="chart-container enhanced-chart" data-protocol="DMARC">
                    <div class="chart-header">
                        <div class="protocol-icon dmarc-icon">DMARC</div>
                        <div class="chart-title-section">
                            <div class="chart-title">DMARC Policy</div>
                            <div class="chart-subtitle">Domain-based Message Authentication</div>
                        </div>
                    </div>
                    <div class="donut-chart-container">
$(New-SegmentedDonutChart (Get-ProtocolCheckDetails $result "DMARC") "DMARC")
                    </div>
                    <div class="chart-status $(if($result.DMARCCheckPercentage -ge 90){'excellent'}elseif($result.DMARCCheckPercentage -ge 70){'good'}elseif($result.DMARCCheckPercentage -ge 50){'fair'}else{'poor'})">
                        $(if($result.DMARCFound){"$($result.DMARCCheckPercentage)% Compliant"}else{"Not Configured"})
                    </div>
                    <div class="segment-legend enhanced-legend" id="dmarc-legend-$domainId">
$((Get-ProtocolCheckDetails $result "DMARC") | ForEach-Object {
    $statusIcon = if($_.Passed) { "<span class='status-icon pass'>&check;</span>" } else { "<span class='status-icon fail'>&times;</span>" }
    $statusClass = if($_.Passed) { "legend-passed" } else { "legend-failed" }
    "<div class='legend-item $statusClass' data-check='$($_.Name)' data-protocol='DMARC'><div class='legend-icon'>$statusIcon</div><div class='legend-text'>$($_.Name)</div></div>"
} | Out-String)
                    </div>
                    <div class="protocol-details-toggle" onclick="toggleProtocolDetails('dmarc-details-$domainId')">
                        <span>View Details</span> <span class="toggle-arrow">&darr;</span>
                    </div>
                    <div class="protocol-details" id="dmarc-details-$domainId" style="display: none;">
                        <div class="detail-item">
                            <span class="detail-label">Policy:</span>
                            <span class="detail-value">$($result.DMARCPolicy)</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Subdomain Policy:</span>
                            <span class="detail-value">$(if($result.DMARCSubdomainPolicy -eq $result.DMARCPolicy) { "$($result.DMARCSubdomainPolicy) (inherited)" } else { $result.DMARCSubdomainPolicy })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">SPF Alignment:</span>
                            <span class="detail-value">$(if($result.DMARCSPFAlignment -eq 'r') { 'Relaxed (r)' } elseif($result.DMARCSPFAlignment -eq 's') { 'Strict (s)' } else { $result.DMARCSPFAlignment })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">DKIM Alignment:</span>
                            <span class="detail-value">$(if($result.DMARCDKIMAlignment -eq 'r') { 'Relaxed (r)' } elseif($result.DMARCDKIMAlignment -eq 's') { 'Strict (s)' } else { $result.DMARCDKIMAlignment })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Reporting:</span>
                            <span class="detail-value">$(if($result.DMARCRecord -match 'rua=') { 'Configured' } else { 'Not Configured' })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Record Found:</span>
                            <span class="detail-value">$(if($result.DMARCFound) { 'Yes' } else { 'No' })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">TTL:</span>
                            <span class="detail-value">$(if($result.DMARCTTL -gt 0) { "$($result.DMARCTTL)s" } else { 'Not Available' })</span>
                        </div>
                        <div class="detail-item" style="flex-direction: column; align-items: flex-start;">
                            <span class="detail-label">DMARC Record:</span>
                            <div class="record-value-container">
                                <div class="record-value-header">
                                    <span style="font-size: 11px; color: #6c757d;">Click to copy record value</span>
                                    <button class="copy-button" id="copy-dmarc-$domainId" onclick="copyToClipboard('$(if($result.DMARCRecord) { $result.DMARCRecord -replace "'", "\'" } else { "No DMARC record found" })', 'copy-dmarc-$domainId')">Copy</button>
                                </div>
                                <div class="record-value-text">$(if($result.DMARCRecord) { $result.DMARCRecord } else { "No DMARC record found" })</div>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="chart-container enhanced-chart" data-protocol="DKIM">
                    <div class="chart-header">
                        <div class="protocol-icon dkim-icon">DKIM</div>
                        <div class="chart-title-section">
                            <div class="chart-title">DKIM Signatures</div>
                            <div class="chart-subtitle">DomainKeys Identified Mail</div>
                        </div>
                    </div>
                    <div class="donut-chart-container">
$(New-SegmentedDonutChart (Get-ProtocolCheckDetails $result "DKIM") "DKIM")
                    </div>
                    <div class="chart-status $(if($result.DKIMCheckPercentage -ge 90){'excellent'}elseif($result.DKIMCheckPercentage -ge 70){'good'}elseif($result.DKIMCheckPercentage -ge 50){'fair'}else{'poor'})">
                        $(if($result.DKIMFound){"$($result.DKIMCheckPercentage)% Compliant"}else{"Not Configured"})
                    </div>
                    <div class="segment-legend enhanced-legend" id="dkim-legend-$domainId">
$((Get-ProtocolCheckDetails $result "DKIM") | ForEach-Object {
    $statusIcon = if($_.Passed) { "<span class='status-icon pass'>&check;</span>" } else { "<span class='status-icon fail'>&times;</span>" }
    $statusClass = if($_.Passed) { "legend-passed" } else { "legend-failed" }
    "<div class='legend-item $statusClass' data-check='$($_.Name)' data-protocol='DKIM'><div class='legend-icon'>$statusIcon</div><div class='legend-text'>$($_.Name)</div></div>"
} | Out-String)
                    </div>
                    <div class="protocol-details-toggle" onclick="toggleProtocolDetails('dkim-details-$domainId')">
                        <span>View Details</span> <span class="toggle-arrow">&darr;</span>
                    </div>
                    <div class="protocol-details" id="dkim-details-$domainId" style="display: none;">
                        <div class="detail-item">
                            <span class="detail-label">Selectors Found:</span>
                            <span class="detail-value">$(if($result.DKIMSelectors.Count -gt 0) { $result.DKIMSelectors.Count } else { '0' })</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Active Keys:</span>
                            <span class="detail-value">$(($result.DKIMAllMechanisms.Values | Where-Object { $_ -eq 'ACTIVE' }).Count)</span>
                        </div>
                        <div class="detail-item">
                            <span class="detail-label">Syntax Valid:</span>
                            <span class="detail-value">$(if($result.DKIMSyntaxValid) { 'Yes' } else { 'No' })</span>
                        </div>
$(if($result.DKIMTTL -and $result.DKIMTTL.Count -gt 0) {
    $ttlSummary = @()
    foreach ($kvp in $result.DKIMTTL.GetEnumerator()) {
        $selector = $kvp.Key
        $ttlValue = $kvp.Value
        if ($ttlValue -gt 0) {
            $ttlText = if ($ttlValue -lt 3600) { "$ttlValue s (Low)" } else { "$ttlValue s" }
            $ttlSummary += "$selector`: $ttlText"
        }
    }
    if ($ttlSummary.Count -gt 0) {
"                        <div class='detail-item'>
                            <span class='detail-label'>TTL:</span>
                            <span class='detail-value'>$($ttlSummary -join ', ')</span>
                        </div>"
    }
})
$(if($result.DKIMKeyLengths -and $result.DKIMKeyLengths.Count -gt 0) {
    $keyLengthSummary = @()
    foreach ($kvp in $result.DKIMKeyLengths.GetEnumerator()) {
        $selector = $kvp.Key
        $keyInfo = $kvp.Value
        if ($keyInfo.KeyLength -gt 0) {
            $strengthText = if ($keyInfo.IsWeak) { " (Weak)" } else { " (Strong)" }
            $keyLengthSummary += "$selector`: $($keyInfo.KeyLength) bits$strengthText"
        }
    }
    if ($keyLengthSummary.Count -gt 0) {
"                        <div class='detail-item'>
                            <span class='detail-label'>Key Lengths:</span>
                            <span class='detail-value'>$($keyLengthSummary -join ', ')</span>
                        </div>"
    }
})
$(if($result.DKIMProviders -and $result.DKIMProviders.Detected.Count -gt 0) {
"                        <div class='detail-item'>
                            <span class='detail-label'>Service Provider:</span>
                            <span class='detail-value'>$($result.DKIMProviders.Detected -join ', ')</span>
                        </div>"
})
                        <div class="detail-item" style="flex-direction: column; align-items: flex-start;">
                            <span class="detail-label">DKIM Records:</span>
                            <div class="record-value-container">
                                <div class="record-value-header">
                                    <span style="font-size: 11px; color: #6c757d;">Click to copy record values</span>
                                    <button class="copy-button" id="copy-dkim-$domainId" onclick="copyToClipboard('$(if($result.DKIMRecords.Count -gt 0) { ($result.DKIMRecords.GetEnumerator() | ForEach-Object { "$($_.Key): $($_.Value)" }) -join "`n" -replace "'", "\'" } else { "No DKIM records found" })', 'copy-dkim-$domainId')">Copy</button>
                                </div>
                                <div class="record-value-text">$(if($result.DKIMRecords.Count -gt 0) { ($result.DKIMRecords.GetEnumerator() | ForEach-Object { "<strong>$($_.Key):</strong> $($_.Value)" }) -join "<br>" } else { "No DKIM records found" })</div>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
            
            <!-- Interactive Tooltip -->
            <div id="chart-tooltip" class="chart-tooltip">
                <div class="tooltip-header">
                    <span class="tooltip-protocol"></span>
                    <span class="tooltip-status"></span>
                </div>
                <div class="tooltip-content">
                    <div class="tooltip-check"></div>
                    <div class="tooltip-description"></div>
                </div>
            </div>
            
            <div class="protocol-comparison">
                <h4>Security Level Comparison</h4>
                <div class="comparison-bars">
                    <div class="comparison-item">
                        <div class="comparison-label">SPF</div>
                        <div class="comparison-bar">
                            <div class="comparison-fill spf-fill" style="width: $($result.SPFCheckPercentage)%"></div>
                        </div>
                        <div class="comparison-value">$($result.SPFCheckPercentage)%</div>
                    </div>
                    <div class="comparison-item">
                        <div class="comparison-label">DMARC</div>
                        <div class="comparison-bar">
                            <div class="comparison-fill dmarc-fill" style="width: $($result.DMARCCheckPercentage)%"></div>
                        </div>
                        <div class="comparison-value">$($result.DMARCCheckPercentage)%</div>
                    </div>
                    <div class="comparison-item">
                        <div class="comparison-label">DKIM</div>
                        <div class="comparison-bar">
                            <div class="comparison-fill dkim-fill" style="width: $($result.DKIMCheckPercentage)%"></div>
                        </div>
                        <div class="comparison-value">$($result.DKIMCheckPercentage)%</div>
                    </div>
                </div>
            </div>
        </div>
            
            <div style="margin-top: 20px; padding: 15px; background: #f8f9fa; border-radius: 8px;">
                <h4 style="margin: 0 0 10px 0; color: #495057;">Check Details:</h4>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(250px, 1fr)); gap: 15px; font-size: 12pt; line-height: 1.5;">
                    <div>
                        <strong style="color: #28a745;">SPF Checks (9 total):</strong>
                        <ul style="margin: 5px 0 0 15px; padding: 0;">
                            <li>Record Present</li>
                            <li>Single Record</li>
                            <li>Macro Security (safe macro usage)</li>
                            <li>TTL Sub-Records (A/MX records TTL &ge;3600s)</li>
                            <li>DNS Lookups &lt; 10</li>
                            <li>Record Length &lt; 255 chars</li>
                            <li>TTL &ge;3600 seconds</li>
                            <li>Strict All Mechanism (~all or -all)</li>
                            <li>Valid Syntax</li>
                        </ul>
                    </div>
                    <div>
                        <strong style="color: #007bff;">DMARC Checks (7 total):</strong>
                        <ul style="margin: 5px 0 0 15px; padding: 0;">
                            <li>Record Present</li>
                            <li>Policy Not 'none'</li>
                            <li>Reporting Configured (rua)</li>
                            <li>Strong Policy (quarantine/reject)</li>
                            <li>Subdomain Policy (sp)</li>
                            <li>SPF Alignment Mode (aspf)</li>
                            <li>DKIM Alignment Mode (adkim)</li>
                        </ul>
                    </div>
                    <div>
                        <strong style="color:rgb(176, 7, 255);">DKIM Checks (4 total):</strong>
                        <ul style="margin: 5px 0 0 15px; padding: 0;">
                            <li>Record Present</li>
                            <li>Valid Syntax</li>
                            <li>Active Keys (not revoked)</li>
                            <li>Strong Key Lengths (&ge;1024 bits)</li>
                        </ul>                    </div>
                </div>
            </div>
        </div>
"@
        
    $html += "        <div class='recommendations'>"
    $html += "            <h4>&#128295; Action Items &amp; Microsoft Documentation</h4>"
    $html += "            <ul>"
    
    foreach ($recommendation in $result.Recommendations) {
        # Format recommendations with proper HTML links
        $formattedRec = $recommendation -replace "(https://[^\s]+)", '<a href="$1" target="_blank">$1</a>'
        $html += "                <li>$formattedRec</li>"
    }
    $html += "            </ul>"
    $html += "        </div>"
    $html += "    </div>"
}

# Close HTML document
$html += '        <div class="microsoft-resources">'
$html += "            <h4>&#128218; Microsoft Official Documentation</h4>"
$html += "            <ul>"
$html += '                <li><strong>SPF Setup:</strong> <a href="https://docs.microsoft.com/microsoft-365/security/office-365-security/set-up-spf-in-office-365-to-help-prevent-spoofing" target="_blank">Set up SPF in Microsoft 365 to help prevent spoofing</a></li>'
$html += '                <li><strong>DKIM Configuration:</strong> <a href="https://docs.microsoft.com/microsoft-365/security/office-365-security/use-dkim-to-validate-outbound-email" target="_blank">Use DKIM to validate outbound email sent from your domain</a></li>'
$html += '                <li><strong>DMARC Implementation:</strong> <a href="https://docs.microsoft.com/microsoft-365/security/office-365-security/use-dmarc-to-validate-email" target="_blank">Use DMARC to validate email in Microsoft 365</a></li>'
$html += '                <li><strong>Email Security Overview:</strong> <a href="https://docs.microsoft.com/microsoft-365/security/office-365-security/anti-spoofing-protection" target="_blank">Anti-spoofing protection in Microsoft 365</a></li>'
$html += '                <li><strong>Exchange Online Protection:</strong> <a href="https://docs.microsoft.com/microsoft-365/security/office-365-security/exchange-online-protection-overview" target="_blank">Exchange Online Protection (EOP) overview</a></li>'
$html += "            </ul>"
$html += "        </div>"
$html += ""
$html += '    <div class="footer">'
$html += "        <h3>&#128202; Understanding Your Results</h3>"
$html += '        <div class="legend">'
$html += '            <div class="legend-item">'
$html += '                <span class="status-excellent">Excellent (90+)</span><br>'
$html += "                <small>All records properly configured</small>"
$html += "            </div>"
$html += '            <div class="legend-item">'
$html += '                <span class="status-good">Good (70-89)</span><br>'
$html += "                <small>Minor improvements needed</small>"
$html += "            </div>"
$html += '            <div class="legend-item">'
$html += '                <span class="status-fair">Fair (50-69)</span><br>'
$html += "                <small>Some security gaps present</small>"
$html += "            </div>"
$html += '            <div class="legend-item">'
$html += '                <span class="status-poor">Poor (&lt;50)</span><br>'
$html += "                <small>Significant security vulnerabilities</small>"
$html += "            </div>"
$html += "        </div>"
$html += '        <hr style="margin: 25px 0; border: none; border-top: 1px solid #ddd;">'
$html += '        <p style="color: #888; font-size: 0.9em;">'
$html += "            &#128231; Email Authentication Checker v1.0 | Generated on $reportDate at $(Get-Date -Format 'HH:mm:ss')"
$html += "        </p>"
$html += "    </div>"
$html += "    </div>"
$html += "</body>"
$html += "</html>"

# Save HTML report to selected location
$reportFileName = "Email-Auth-Report-$fileTimestamp.html"
$reportPath = Join-Path -Path $path -ChildPath $reportFileName

# Save the HTML file
$html | Out-File -FilePath $reportPath -Encoding UTF8 -Force

Write-Host ""
Write-Host "HTML report successfully generated!" -ForegroundColor Green
Write-Host "Report saved to: $reportPath" -ForegroundColor Cyan
Write-Host ""

# Display final summary
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "              FINAL SUMMARY" -ForegroundColor Cyan
Write-Host "============================================" -ForegroundColor Cyan
Write-Host "Total domains analyzed: $totalDomains" -ForegroundColor White
Write-Host "Average security score: $avgScore/100" -ForegroundColor White
Write-Host ""

# Ask if user wants to open the report
$openChoice = Read-Host "Would you like to open the HTML report now? (y/n)"
if ($openChoice -eq 'y' -or $openChoice -eq 'Y' -or $openChoice -eq 'yes') {
    Start-Process $reportPath
    Write-Host "Opening report in your default browser..." -ForegroundColor Green
}

Write-Host ""
Write-Host "Thank you for using Email Authentication Checker with Microsoft Documentation!" -ForegroundColor Green
Write-Host "============================================" -ForegroundColor Cyan

# SIG # Begin signature block
# MIIFiwYJKoZIhvcNAQcCoIIFfDCCBXgCAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUwEX+hzMzRwqhZCz3+WlYaieA
# SVmgggMcMIIDGDCCAgCgAwIBAgIQLmc4TbNqUYVPsD95nRS6TDANBgkqhkiG9w0B
# AQsFADAkMSIwIAYDVQQDDBlBYmR1bGxhaFptYWlsaUNvZGVTaWduaW5nMB4XDTI1
# MDcxNjE1MjM1MloXDTI2MDcxNjE1NDM1MlowJDEiMCAGA1UEAwwZQWJkdWxsYWha
# bWFpbGlDb2RlU2lnbmluZzCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEB
# AKmnQXy9ni4FnSYTL3l9RKv7mq1rr9OS2+RoJkuJlK1arJQRoiMy3XN1fFlkiFdH
# LB4v1cVxNY11rlAv07gaJOtR+QTjkA9N2dUVl1cA6IjMJFTEAssbFf4uTSpK06It
# 88Z8JTpB++Ud/5kySH8bmBzRBO5LEdKkctdqoNvOBy2tX6IuhCqsc75Q1SwzQewf
# 02+CE4OUdR++eKSG38BD1PHTTsuc9F9oVm8M0RzdAuLPj0+ciKjAA97fq9vaLGmF
# Z53YcaLqK7UjEhF56jVkrFnZ2DKT8WWm5dDMQ0KCiOisbRroYl6w7zYbX33j1aCr
# 7vnYp+NYddNkiSTizYDJfsUCAwEAAaNGMEQwDgYDVR0PAQH/BAQDAgeAMBMGA1Ud
# JQQMMAoGCCsGAQUFBwMDMB0GA1UdDgQWBBRysS6bLJa+jwmsLys/2qEkpx6mrzAN
# BgkqhkiG9w0BAQsFAAOCAQEAQYcNW/yolMC8lWlHtkJ9kkpPQ92GG0pE1Z88dQgo
# ELAog5zTez/JqweIrL0fdGp5R+DEDIKFWz2dStb++MbnVIz2rYRoipn6ZBEK/277
# h/FBu+hHouR0HnG1RYcbrvf0hpyURD6YTZ9hNP/Tz5hSBXMIgH1ZmSLPnoVePzUc
# OcLoH74fZQ/EASue1jnk12eRzlLXsPWDfa0mu8faFmNzMJ7tlGYW8TsF5PPHjDYW
# sz6cGAd9ba2OgolJVUmtNkYU3ahJtvNv9U58ZS7oQbBrHnCEjfAsonqecH0S6xJ2
# 6Vt/tLU4avu8IBwRIDhBovirWZM2TUf7AODZOx92R1MwNTGCAdkwggHVAgEBMDgw
# JDEiMCAGA1UEAwwZQWJkdWxsYWhabWFpbGlDb2RlU2lnbmluZwIQLmc4TbNqUYVP
# sD95nRS6TDAJBgUrDgMCGgUAoHgwGAYKKwYBBAGCNwIBDDEKMAigAoAAoQKAADAZ
# BgkqhkiG9w0BCQMxDAYKKwYBBAGCNwIBBDAcBgorBgEEAYI3AgELMQ4wDAYKKwYB
# BAGCNwIBFTAjBgkqhkiG9w0BCQQxFgQUVQcP6ta8I/b4Z3+a+Hr9KLt9nOIwDQYJ
# KoZIhvcNAQEBBQAEggEAaq5P3UW8imHkEQRkxWiuvMGFgGhEz2nICXWOmzzhCQNs
# Yl6WFljrd7B/UL5ihG+4shB6BBmhREJd7ZOLnk1my9U6TaATta0341alnchfWCl6
# qtLSd+KzGZMIaPNva8rsCwjtw1mnAFP0koUI/ofpE8IIpLuGr9Jn6tynM9J5Oc17
# oJe5xvLf9BrPljCyYTIrQQXiRF3wbt9A3OR3y/P38D33LG4ZN9HcvOJPuJyr0f6N
# CFRTkGvxJqsfWLOpmB0qTFD/IlHWdJrPrl9/VNRSL9IVTW8pZ/l0fjxd/05S/Ybm
# /i6MmFp3YxGRO9nACjwrzRSERk8ztqI2NsG1beWf+g==
# SIG # End signature block
