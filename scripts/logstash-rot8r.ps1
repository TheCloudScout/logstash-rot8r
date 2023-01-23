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
    [string] $applicationId
)


# Funtion for writing credentials to secure .cred file
Function Save-Credential([string]$UserName, [string]$KeyPath)
{
    #Create directory for Key file
    If (!(Test-Path $KeyPath)) {       
        Try {
            New-Item -ItemType Directory -Path $KeyPath -ErrorAction STOP | Out-Null
        }
        Catch {
            Throw $_.Exception.Message
        }
    }
    #store password encrypted in file
    $Credential = Get-Credential -Message "Enter the Credentials:" -UserName $UserName
    $Credential.Password | ConvertFrom-SecureString | Out-File "$($KeyPath)\$($Credential.Username).cred" -Force
}

# Funtion for retrieving credentials from secure .cred file
Function Get-SavedCredential([string]$UserName,[string]$KeyPath)
{
    If(Test-Path "$($KeyPath)\$($Username).cred") {
        $SecureString = Get-Content "$($KeyPath)\$($Username).cred" | ConvertTo-SecureString
        $Credential = New-Object System.Management.Automation.PSCredential -ArgumentList $Username, $SecureString
    }
    Else {
        Throw "Unable to locate a credential for $($Username)"
    }
    Return $Credential
}
 
#Get encrypted password from the file
$Cred = Get-SavedCredential -UserName "salaudeen@crescent.com" -KeyPath "C:\Scripts"
 
#Connect to Azure AD from saved credentials
Connect-AzureAD -Credential $Cred






$secret = "clm8Q~itmutY-KEg0M2w6pQ8LmebO2-wVvEwNcX0"
$appid = "5a2855f0-f2b4-42f2-9e00-d24b72bf4e62"



Get-Content file.txt | Foreach-Object{
   $var = $_.Split('=')
   New-Variable -Name $var[0] -Value $var[1]
}

\\\
$credentials = [ordered]@{
    tenantId            = [System.Text.ASCIIEncoding]::ASCII.GetString([System.Convert]::FromBase64String(" YTZiMTY5ZjEtNTkyYi00MzI5LThmMzMtOGRiODkwMzAwM2M3 "))
    serviceprincipalId  = [System.Text.ASCIIEncoding]::ASCII.GetString([System.Convert]::FromBase64String(" MzExZjRiYjYtYjgwMS00ZDYyLWEwZTAtMWU5MGJmMzEzYmVk "))
    servicePrincipalKey = [System.Text.ASCIIEncoding]::ASCII.GetString([System.Convert]::FromBase64String(" Q3I2OFF+R2xNbld6TWROeHhqUS1faVR4alNldkx5U1R5Q0t0R2RBMw== "))
}
Write-Output -InputObject $credentials

 $psCred = New-Object System.Management.Automation.PSCredential($credentials.serviceprincipalId , (ConvertTo-SecureString $credentials.servicePrincipalKey -AsPlainText -Force))
 Add-AzAccount -Credential $psCred -TenantId $credentials.tenantId -ServicePrincipal
\\\




$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

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