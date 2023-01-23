<#
.DESCRIPTION
    Permission requirements:
    - Azure AD: Application needs to be owner of it's own application
    - Azure AD: Application requires the application permission Application.ReadWrite.OwnedBy

    https://docs.microsoft.com/en-us/rest/api/azure/devops/serviceendpoint/endpoints?view=azure-devops-rest-6.1
    https://docs.microsoft.com/en-us/graph/api/resources/application?view-graph-rest-1.0

    .PARAMETER secretAddDays [Int32]
    The number of days the new application secret will be valid. Default is for 15 days.
    .PARAMETER tenantId [string]
    The Tenant ID of the Azure Active Directory in which the application resides.
    .PARAMETER applicationId [string]
    The app id of the application on which the secret needs to be rotated.

#>
[CmdletBinding()]
param (
    [Parameter (Mandatory = $false)]
    [Int32] $secretAddDays = 31,

    [Parameter (Mandatory = $true)]
    [string] $tenantId = "da2d1fdd-f4f7-4483-960e-9742e3742ef4",

    [Parameter (Mandatory = $true)]
    [string] $applicationId = "5a2855f0-f2b4-42f2-9e00-d24b72bf4e62"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Check if secure .cred file exists and construct $credentials
If(!(Test-Path "$($applicationId).cred"))
{
    # Create a secure .cred file
    Write-Host "No credentials file found for $($applicationId).!" -ForegroundColor Yellow
    Write-Host "Please create one by entering the a known secret." -ForegroundColor Yellow
    $credentials = Get-Credential -Message "Provide secret." -UserName $applicationId
    $credentials.Password | ConvertFrom-SecureString | Out-File "$($credentials.Username).cred" -Force
} else {
    # Read secure .cred file
    $SecureString = Get-Content "$($applicationId).cred" | ConvertTo-SecureString
    $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $applicationId, $SecureString
}

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
$token = Invoke-RestMethod @params -UseBasicParsing

$headers = @{
    "Content-Type"  = "application/json"
    "Authorization" = "$($token.token_type) $($token.access_token)"
}

# Retrieve application
$params = @{
    "Method"  = "Get"
    "Uri"     = "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$($applicationId)'"
    "Headers" = $headers
}
$applications = Invoke-RestMethod @params -UseBasicParsing
if ($applications.value.Count -ne 1) {
    Write-Error "No application found with appId '$($applicationId)' which shouldn't be possible."
} else {
    $params = @{
        "Method"  = "Get"
        "Uri"     = "https://graph.microsoft.com/v1.0/applications/$($applications.value[0].id)"
        "Headers" = $headers
    }
    $application = Invoke-RestMethod @params -UseBasicParsing
    Write-Host "Found application with id '$($application.id)', appId '$($application.appId)' and displayName '$($application.displayName)'"
}

# Add new application secret
$body = @{
    "passwordCredential" = @{
        "displayName" = "secret-$(Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ" -AsUTC)"
        "endDateTime" = (Get-Date).AddDays($secretAddDays) | Get-Date -Format "yyyy-MM-ddTHH:mm:ssZ" -AsUTC
    }
}
Write-Host "Add new secret with the following displayName and endDateTime:"
Write-Host $body.passwordCredential.displayName
Write-Host $body.passwordCredential.endDateTime
$params = @{
    "Method"  = "Post"
    "Uri"     = "https://graph.microsoft.com/v1.0/applications/$($application.id)/addPassword"
    "Headers" = $headers
    "Body"    = $body | ConvertTo-Json -Compress
}
$newSecret = Invoke-RestMethod @params -UseBasicParsing
Write-Host "New secret created with id: $($newSecret.keyId)"

Write-Host "Updating secure .cred file..." -ForegroundColor DarkGray
# Update secure .cred file with new secret value
$secureNewSecret = ConvertTo-SecureString $newSecret.secretText -AsPlainText -Force
$secureNewSecret | ConvertFrom-SecureString | Out-File "$($credentials.Username).cred" -Force

# Update Logstash configuration with new secret value
Write-Host "Updating logstash config file $($sourceFile)..." -ForegroundColor DarkGray
$sourceFile = './logstash.conf'
$Pattern = ' => '
# Read Logstash config file
$logstashConfigFile = Get-Content $sourceFile
# Cleanup and keep only relevant config
$logstashConfig = ($logstashConfigFile | Where-Object { $_ -match $Pattern }).trim() -Replace ' => ','=' -Replace '"','' | ConvertFrom-StringData
# Replace application secret in Logstash config file
try {
    $logstashConfigFile = $logstashConfigFile -replace $logstashConfig.client_app_secret, $newSecret.secretText
    $logstashConfigfile | Out-File $sourceFile
    # $logstashConfigFile.replace($($logstashConfig.client_app_secret),$($newSecret.secretText)) | Out-File $sourceFile
    Write-Host "     ✓ Logstash config file $($sourceFile) written." -ForegroundColor Green
} catch {
    Write-Host "     ✘ There was a problem updating Logstash config file $($sourceFile)." -ForegroundColor Red
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
$passwordsToRemove = $application.passwordCredentials | Where-Object -FilterScript { $_.keyId -ne $newSecret.keyId } | Sort-Object -Property startDateTime -Descending | Select-Object -Skip 1
Write-Host "Found $(@($passwordsToRemove).Count) application secrets to remove"
foreach ($passwordToRemove in $passwordsToRemove) {
    Write-Host "Remove application secret '$($passwordToRemove.keyId)' with start date '$($passwordToRemove.startDateTime)' and end date '$($passwordToRemove.endDateTime)'"
    $body = @{
        "keyId" = $passwordToRemove.keyId
    }
    $params = @{
        "Method"  = "Post"
        "Uri"     = "https://graph.microsoft.com/v1.0/applications/$($application.id)/removePassword"
        "Headers" = $headers
        "Body"    = $body | ConvertTo-Json -Compress
    }
    $removedPassword = Invoke-WebRequest @params -UseBasicParsing
    if ($removedPassword.StatusCode -eq 204) {
        Write-Host "  Removed application secret"
    } else {
        Write-Warning "  Failed to remove password with status code $($removedPassword.StatusCode)"
    }
}
