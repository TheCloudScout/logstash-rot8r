<#
.DESCRIPTION
    Azure DevOps Pipeline details:
    - AzureCLI@2
    - scriptType: 'pscore'
    - addSpnToEnvironment: true
    Permission requirements:
    - Azure DevOps: <Project> Build Service needs to be member of the Endpoint Administrators group
    - Azure AD: Application needs to be owner of it's own application
    - Azure AD: Application requires the application permission Application.ReadWrite.OwnedBy

    https://docs.microsoft.com/en-us/rest/api/azure/devops/serviceendpoint/endpoints?view=azure-devops-rest-6.1
    https://docs.microsoft.com/en-us/graph/api/resources/application?view-graph-rest-1.0

.PARAMETER secretAddDays [Int32]
    The number of days the new application secret will be valid. Default is for 15 days.
.PARAMETER SecretAddedDays [string]
    The applicationId of the identity to authenticate with Azure with and to rotate its secrets.
#>
[CmdletBinding()]
param (
    [Parameter (Mandatory = $false)]
    [Int32] $secretAddDays = 15

    [Parameter (Mandatory = $true)]
    [string] $tenantId = "da2d1fdd-f4f7-4483-960e-9742e3742ef4"

    [Parameter (Mandatory = $true)]
    [string] $applicationId = "5a2855f0-f2b4-42f2-9e00-d24b72bf4e62"

    [Parameter (Mandatory = $false)]
    [string] $secret = "clm8Q~itmutY-KEg0M2w6pQ8LmebO2-wVvEwNcX0"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Check if secure .cred file exists and construct $credentials
If(!(Test-Path "$($applicationId).cred"))
{
    # Create a secure .cred file
    Write-Host "No credentials file found for $($applicationId).!" -ForegroundColor Yellow
    Write-Host "Please create one by entering the a known secret." -ForegroundColor Yellow
    $credentials = Get-Credential -Message "Provide secret:" -UserName $applicationId
    $credentials.Password | ConvertFrom-SecureString | Out-File "$($credentials.Username).cred" -Force
} else {
    # Read secure .cred file
    $SecureString = Get-Content "$($applicationId).cred" | ConvertTo-SecureString
    $credentials = New-Object System.Management.Automation.PSCredential -ArgumentList $applicationId, $SecureString
}

# Login to Azure with service principal details from $credentials
Add-AzAccount -Credential $credentials -TenantId $tenantId -ServicePrincipal





$accessToken = [System.Environment]::GetEnvironmentVariable("SYSTEM_ACCESSTOKEN")
if ([System.String]::IsNullOrWhiteSpace($accessToken)) {
    Write-Error "Environment variable 'SYSTEM_ACCESSTOKEN' not set."
}

$tenantId = [System.Environment]::GetEnvironmentVariable("tenantId")
$applicationId = [System.Environment]::GetEnvironmentVariable("servicePrincipalId")
$applicationSecret = [System.Environment]::GetEnvironmentVariable("servicePrincipalKey")
if ([System.String]::IsNullOrWhiteSpace($tenantId) -or [System.String]::IsNullOrWhiteSpace($applicationId) -or [System.String]::IsNullOrWhiteSpace($applicationSecret)) {
    Write-Error "Environment variable 'tenantId' or 'servicePrincipalId' or 'servicePrincipalKey' is not set."
}

$baseUri = [System.Environment]::GetEnvironmentVariable("SYSTEM_TEAMFOUNDATIONCOLLECTIONURI")
$projectName = [System.Environment]::GetEnvironmentVariable("SYSTEM_TEAMPROJECT")
$projectId = [System.Environment]::GetEnvironmentVariable("SYSTEM_TEAMPROJECTID")
if ([System.String]::IsNullOrWhiteSpace($baseUri) -or [System.String]::IsNullOrWhiteSpace($projectName) -or [System.String]::IsNullOrWhiteSpace($projectId)) {
    Write-Error "Environment variable 'SYSTEM_TEAMFOUNDATIONCOLLECTIONURI' or 'SYSTEM_TEAMPROJECT' or 'SYSTEM_TEAMPROJECTID' is not set."
}
$projectUri = "$($baseUri)$($projectId)"

$headerDevOps = @{
    "Authorization" = "Bearer $($accessToken)"
    "Content-Type"  = "application/json"
}

$params = @{
    "Method" = "Post"
    "Uri"    = "https://login.microsoftonline.com/$($tenantId)/oauth2/token"
    "Body"   = @{
        "client_id"     = $applicationId
        "client_secret" = $applicationSecret
        "grant_type"    = "client_credentials"
        "resource"      = "https://graph.microsoft.com/"
    }
}
$token = Invoke-RestMethod @params -UseBasicParsing
$headersGraph = @{
    "Content-Type"  = "application/json"
    "Authorization" = "$($token.token_type) $($token.access_token)"
}

# Retrieve application
$params = @{
    "Method"  = "Get"
    "Uri"     = "https://graph.microsoft.com/v1.0/applications?`$filter=appId eq '$($applicationId)'"
    "Headers" = $headersGraph
}
$applications = Invoke-RestMethod @params -UseBasicParsing
if ($applications.value.Count -ne 1) {
    Write-Error "No application found with appId '$($applicationId)' which shouldn't be possible."
}
$params = @{
    "Method"  = "Get"
    "Uri"     = "https://graph.microsoft.com/v1.0/applications/$($applications.value[0].id)"
    "Headers" = $headersGraph
}
$application = Invoke-RestMethod @params -UseBasicParsing
Write-Host "Found application with id '$($application.id)', appId '$($application.appId)' and displayName '$($application.displayName)'"

# Retrieve Service Connection
$params = @{
    "Method"  = "Get"
    "Uri"     = "$($projectUri)/_apis/serviceendpoint/endpoints?api-version=6.1-preview"
    "Headers" = $headerDevOps
}
$serviceConnections = Invoke-RestMethod @params -UseBasicParsing
$serviceConnection = $serviceConnections.value | Where-Object -FilterScript { $_.type -eq "azurerm" -and $_.authorization.scheme -eq "ServicePrincipal" -and $_.authorization.parameters.serviceprincipalid -eq $applicationId }
if (@($serviceConnection).Count -gt 1) {
    Write-Error "Multiple Service Connections found which uses applicationId '$($applicationId)': $([System.String]::Join(", ", @($serviceConnection | ForEach-Object { $_.name })))"
}
if (@($serviceConnection).Count -eq 0) {
    return
}
$params = @{
    "Method"  = "Get"
    "Uri"     = "$($projectUri)/_apis/serviceendpoint/endpoints/$($serviceConnection.id)?api-version=6.1-preview"
    "Headers" = $headerDevOps
}
$serviceConnection = Invoke-RestMethod @params -UseBasicParsing
Write-Host "Found Service Connection '$($serviceConnection.name)'"

# Add new application secret
$body = @{
    "passwordCredential" = @{
        "displayName" = [System.Environment]::GetEnvironmentVariable("RELEASE_RELEASEWEBURL")
        "endDateTime" = [System.DateTime]::UtcNow.AddDays($secretAddDays).ToString("yyyy-MM-ddTHH:mm:ssZ")
    }
}
Write-Host "Add new secret with the following displayName and endDateTime:"
Write-Host $body.passwordCredential.displayName
Write-Host $body.passwordCredential.endDateTime
$params = @{
    "Method"  = "Post"
    "Uri"     = "https://graph.microsoft.com/v1.0/applications/$($application.id)/addPassword"
    "Headers" = $headersGraph
    "Body"    = $body | ConvertTo-Json -Compress
}
$newPassword = Invoke-RestMethod @params -UseBasicParsing
Write-Host "New secret created with id: $($newPassword.keyId)"

# Update Service Connection
$serviceConnection.authorization.parameters.servicePrincipalKey = $newPassword.secretText
$serviceConnection.isReady = $false
$params = @{
    "Method"  = "Put"
    "Uri"     = "$($projectUri)/_apis/serviceendpoint/endpoints/$($serviceConnection.id)?api-version=6.1-preview"
    "Headers" = $headerDevOps
    "Body"    = $serviceConnection | ConvertTo-Json -Compress -Depth 99
}
$serviceConnection = Invoke-WebRequest @params -UseBasicParsing

# Retrieve updated application
$params = @{
    "Method"  = "Get"
    "Uri"     = "https://graph.microsoft.com/v1.0/applications/$($applications.value[0].id)"
    "Headers" = $headersGraph
}
$application = Invoke-RestMethod @params -UseBasicParsing

# Remove old application secrets
$passwordsToRemove = $application.passwordCredentials | Where-Object -FilterScript { $_.keyId -ne $newPassword.keyId } | Sort-Object -Property startDateTime | Select-Object -Skip 1
Write-Host "Found $(@($passwordsToRemove).Count) application secrets to remove"
foreach ($passwordToRemove in $passwordsToRemove) {
    Write-Host "Remove application secret '$($passwordToRemove.keyId)' with start date '$($passwordToRemove.startDateTime)' and end date '$($passwordToRemove.endDateTime)'"
    $body = @{
        "keyId" = $passwordToRemove.keyId
    }
    $params = @{
        "Method"  = "Post"
        "Uri"     = "https://graph.microsoft.com/v1.0/applications/$($application.id)/removePassword"
        "Headers" = $headersGraph
        "Body"    = $body | ConvertTo-Json -Compress
    }
    $removedPassword = Invoke-WebRequest @params -UseBasicParsing
    if ($removedPassword.StatusCode -eq 204) {
        Write-Host "  Removed application secret"
    } else {
        Write-Warning "  Failed to remove password with status code $($removedPassword.StatusCode)"
    }
}