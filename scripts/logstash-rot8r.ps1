<#
.DESCRIPTION
    Permission requirements:
    - Azure AD: Application needs to be owner of it's own application.
    - Azure AD: Application requires the application permission Application.ReadWrite.OwnedBy.

    Run Add-AppOwner.ps1 separately for one-time setup of proper permissions on your application.

    https://docs.microsoft.com/en-us/graph/api/resources/application?view-graph-rest-1.0

    .PARAMETER secretAddDays [Int32]
    The number of days the new application secret will be valid. Default is for 31 days.
    .PARAMETER tenantId [string]
    The Tenant ID of the Azure Active Directory in which the application resides.
    .PARAMETER applicationId [string]
    The app id of the application on which the secret needs to be rotated.
    .PARAMETER logstashConfigLocation [string]
    Path to logstash pipeline configuration file i.e. '/etc/logstash/conf.d/syslog-to-dcr-based-sentinel.conf'.
    .PARAMETER logstashKeystoreKey [string]
    Name of the key in the keystore container the app secret referenced inside the Logstash configuration file.
    .PARAMETER hideOutput [boolean]
    Default is $true. Set to $false for easier troubleshooting external Logstash-specific command like update keystore key and restarting service.

    If there is a problem updating key value in Logstash' keystore. Please check:
        ● Permissions for running 'logstash-keystore remove/add'
        ● Properly created keystore and access to keystore password value in environment variable
        ● Keystore password value in environment variable 'LOGSTASH_KEYSTORE_PASS'

    Verify keystore by running 'logstash-keystore list'

    https://www.elastic.co/guide/en/logstash/current/keystore.html

#>

[CmdletBinding()]
param (
    [Parameter (Mandatory = $false)]
    [Int32] $secretAddDays = 31,

    [Parameter (Mandatory = $true)]
    [string] $tenantId,

    [Parameter (Mandatory = $true)]
    [string] $applicationId,

    [Parameter (Mandatory = $false)]
    [string] $logstashConfigLocation,

    [Parameter (Mandatory = $false)]
    [string] $logstashKeystoreKey,

    [Parameter (Mandatory = $false)]
    [boolean] $hideOutput = $true

)

# Variables for running Logstash command outside of this script. Change depending on your scenario Linux/Windows etc.
$cmdRemoveKeystoreKey       = 'sudo -E /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash remove $($logstashKeystoreKey)'
$cmdAddKeystoreKey          = 'echo $($newSecret.secretText) | sudo -E /usr/share/logstash/bin/logstash-keystore --path.settings /etc/logstash add $($logstashKeystoreKey)'
$cmdRestartLogstashService  = 'systemctl restart logstash'


$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

Write-Host ""
Write-Host "            ┐    ┌─┐  ┌─┐  ┌─┐  ─┬─  ┌─┐  ┌─┐  ┐ ┌             " -ForegroundColor Magenta
Write-Host "            │    │ │  │ ┬  └─┐   │   ├─┤  └─┐  ├─┤             " -ForegroundColor Magenta
Write-Host "            └─┘  └─┘  └─┘  └─┘   ┴   ┘ └  └─┘  ┘ └             " -ForegroundColor Magenta
Write-Host "   :::::::::    ::::::::  :::::::::::  ::::::::   :::::::::    " -ForegroundColor Magenta
Write-Host "   :+:    :+:  :+:    :+:     :+:     :+:    :+:  :+:    :+:   " -ForegroundColor Magenta
Write-Host "   +:+    +:+  +:+    +:+     +:+     +:+    +:+  +:+    +:+   " -ForegroundColor Magenta
Write-Host "   +#++:++#:   +#+    +:+     +#+      +#++:++#   +#++:++#:    " -ForegroundColor Magenta
Write-Host "   +#+    +#+  +#+    +#+     +#+     +#+    +#+  +#+    +#+   " -ForegroundColor Magenta
Write-Host "   #+#    #+#  #+#    #+#     #+#     #+#    #+#  #+#    #+#   " -ForegroundColor Magenta
Write-Host "   ###    ###   ########      ###      ########   ###    ###   " -ForegroundColor Magenta
Write-Host "╙─────────────────────────────────────────────────────────────╜" -ForegroundColor Magenta

# Check if Logstash config file can be found
If (!$logstashKeystoreKey) {
    if (!$logstashConfigLocation) {
        Write-Host " ✘ No logstash configuration file, nor a key name for Logstash' keystore was provided!" -ForegroundColor Red
        Write-Host "   Provide either one and try again." -ForegroundColor Red
        Write-Host ""
        exit
    }
    else {
        If (!(Test-Path $logstashConfigLocation)) {
            Write-Host " ✘ Logstash configuration file $($logstashConfigLocation) not found!" -ForegroundColor Red
            Write-Host ""
            exit
        }
    }
} 

# Check if secure .cred file exists and construct $credentials
If (!(Test-Path "$($applicationId).cred")) {
    # Create a secure .cred file
    Write-Host "No credentials file found for $($applicationId)!" -ForegroundColor Yellow
    # Write-Host "Please create one by entering the a known secret." -ForegroundColor Yellow
    $credentials = Get-Credential -Message " " -Title "Please create one by entering a known secret." -UserName $applicationId
    $credentials.Password | ConvertFrom-SecureString | Out-File "$($credentials.Username).cred" -Force
}
else {
    # Read secure .cred file
    $SecureString = Get-Content "$($applicationId).cred" | ConvertTo-SecureString
    $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $applicationId, $SecureString
}

# Sign in to Azure Active Directory
Write-Host "   ▲ Connecting to Azure Active Directory..." -ForegroundColor Cyan 
$params = @{
    "Method" = "Post"
    "Uri"    = "https://login.microsoftonline.com/$($tenantId)/oauth2/token"
    "Body"   = @{
        "client_id"     = $applicationId
        "client_secret" = ($credentials.password | ConvertFrom-SecureString -AsPlainText)
        "grant_type"    = "client_credentials"
        "resource"      = "https://graph.microsoft.com/"
    }
}
try {
    $token = Invoke-RestMethod @params -UseBasicParsing
}
catch {
    Write-Host ""
    Write-Host "   ✘ There was a problem signing in to Azure Active Directory!" -ForegroundColor Red
    Write-Host "     Verify credentials, remove $($applicationId).cred file and try again." -ForegroundColor Red
    Write-Host ""
    exit
}

$headers = @{
    "Content-Type"  = "application/json"
    "Authorization" = "$($token.token_type) $($token.access_token)"
}

# Retrieve application
Write-Host "      ─┰─ " -ForegroundColor DarkGray
Write-Host "       ┖─ Retrieving application details..." -ForegroundColor DarkGray
$params = @{
    "Method"  = "Get"
    "Uri"     = "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$($applicationId)'"
    "Headers" = $headers
}
try {
    $applications = Invoke-RestMethod @params -UseBasicParsing
}
catch {
    Write-Host ""
    Write-Host "        ✘ There was a problem retrieving application with id $($applicationId) in Azure Active Directory!" -ForegroundColor Red
    Write-Host "          Please verify permissions requirements and re-run 'Add-AppOwner.ps1' is necessary." -ForegroundColor Red
    Write-Host ""
    exit
}
if ($applications.value.Count -ne 1) {
    Write-Host "          ✘ No application found with appId '$($applicationId)'" -ForegroundColor Red
}
else {
    $params = @{
        "Method"  = "Get"
        "Uri"     = "https://graph.microsoft.com/v1.0/applications/$($applications.value[0].id)"
        "Headers" = $headers
    }
    $application = Invoke-RestMethod @params -UseBasicParsing
    Write-Host "           ✓ Found application with displayName '$($application.displayName)'" -ForegroundColor Green
}

# Add new application secret
Write-Host "       ┖─ Generating new secret with a lifetime of $($secretAddDays) days..." -ForegroundColor DarkGray
# Constructing body with displayName and endDateTime
$body = @{
    "passwordCredential" = @{
        "displayName" = "secret-$(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ" -AsUTC)"
        "endDateTime" = (Get-Date).AddDays($secretAddDays) | Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ" -AsUTC
    }
}
$params = @{
    "Method"  = "Post"
    "Uri"     = "https://graph.microsoft.com/v1.0/applications/$($application.id)/addPassword"
    "Headers" = $headers
    "Body"    = $body | ConvertTo-Json -Compress
}
$newSecret = Invoke-RestMethod @params -UseBasicParsing
Write-Host "           ✓ New secret created with displayName $($body.passwordCredential.displayName) and endDateTime of $($body.passwordCredential.endDateTime)" -ForegroundColor Green

Write-Host "       ┖─ Updating secure .cred file for next rotation..." -ForegroundColor DarkGray
# Update secure .cred file with new secret value
$secureNewSecret = ConvertTo-SecureString $newSecret.secretText -AsPlainText -Force
$secureNewSecret | ConvertFrom-SecureString | Out-File "$($credentials.Username).cred" -Force
Write-Host "           ✓ Credentials encrypted and stored in $($applicationId).cred" -ForegroundColor Green

if (!$logstashKeystoreKey) {
    # Update Logstash configuration with new secret value
    Write-Host "       ┖─ Logstash Keystore disabled, updating configuration file $($logstashConfigLocation)..." -ForegroundColor DarkGray
    $Pattern = ' => '
    # Read Logstash config file
    $logstashConfigFile = Get-Content $logstashConfigLocation
    # Cleanup and keep only relevant config
    $logstashCleanConfigFile = ($logstashConfigFile | Where-Object { $_ -match $Pattern }).trim() -Replace '"', ''
    # Add configuration items to hashtable
    $logstashConfig = @{}
    foreach ($line in $logstashCleanConfigFile) {
        $arr = $line.Split('=>').trim()
        $logstashConfig.Add($arr[0], $arr[1])
    }
    # Replace application secret in Logstash config file
    try {
        $logstashConfigFile = $logstashConfigFile -replace $logstashConfig.client_app_secret, $newSecret.secretText
        $logstashConfigFile | Out-File $logstashConfigLocation
        Write-Host "           ✓ Logstash config file $($logstashConfigLocation) written." -ForegroundColor Green
    }
    catch {
        Write-Host "           ✘ There was a problem updating Logstash config file $($logstashConfigLocation)." -ForegroundColor Red
    }
}
else {
    # Update secret in Logstash Keystore
    Write-Host "       ┖─ Logstash Keystore enabled, removing old key '$($logstashKeystoreKey)'..." -ForegroundColor DarkGray
    If (!$hideOutput) {
        Invoke-Expression $cmdRemoveKeystoreKey
    } else {
        Invoke-Expression $cmdRemoveKeystoreKey | Out-Null
    }
    Write-Host "       ┖─ Logstash Keystore enabled, adding new key '$($logstashKeystoreKey)'..." -ForegroundColor DarkGray
    If (!$hideOutput) {
        Invoke-Expression $cmdAddKeystoreKey 
    } else { 
        Invoke-Expression $cmdAddKeystoreKey | Out-Null 
    }
}

# Cleanup old secrets
# Retrieve updated application
$params = @{
    "Method"  = "Get"
    "Uri"     = "https://graph.microsoft.com/v1.0/applications/$($applications.value[0].id)"
    "Headers" = $headers
}
$application = Invoke-RestMethod @params -UseBasicParsing

# Remove old application secrets, keep only newest +1
Write-Host "       ┖─ Looking for outdated secrets that can be cleaned up..." -ForegroundColor DarkGray
$passwordsToRemove = $application.passwordCredentials | Where-Object -FilterScript { $_.keyId -ne $newSecret.keyId } | Sort-Object -Property startDateTime -Descending | Select-Object -Skip 1
Write-Host "           ┖─ Found $(@($passwordsToRemove).Count) application secret(s) to remove" -ForegroundColor DarkGray
foreach ($secretToRemove in $passwordsToRemove) {
    Write-Host "           ┖─ Remove application secret '$($secretToRemove.displayName)'" -ForegroundColor DarkGray
    $body = @{
        "keyId" = $secretToRemove.keyId
    }
    $params = @{
        "Method"  = "Post"
        "Uri"     = "https://graph.microsoft.com/v1.0/applications/$($application.id)/removePassword"
        "Headers" = $headers
        "Body"    = $body | ConvertTo-Json -Compress
    }
    $removedSecret = Invoke-WebRequest @params -UseBasicParsing
    if ($removedSecret.StatusCode -eq 204) {
        Write-Host "               ✓ Removed application secret" -ForegroundColor Green
    }
    else {
        Write-Host "               ✘ Failed to remove password with status code $($removedSecret.StatusCode)" -ForegroundColor Orange
    }
}

# Restart Logstash system service
Write-Host ""
Write-Host "     ◔ Restarting Logstash service... ◕   " -ForegroundColor DarkYellow

If (!$hideOutput) {
    Invoke-Expression $cmdRestartLogstashService
} else {
    Invoke-Expression $cmdRestartLogstashService | Out-Null
}

Write-Host ""
Write-Host "      ┍━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┑  " -ForegroundColor Green
Write-Host "    ━━┥  🔑 Key rotation successful!  ┝━━" -ForegroundColor Green
Write-Host "      ┕━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┙  " -ForegroundColor Green
Write-Host ""
