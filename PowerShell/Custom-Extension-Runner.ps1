<#
.SYNOPSIS
    Runs Entra ID Governance Custom Extensions on-demand for a specific user.

.DESCRIPTION
    This script discovers Custom Extension Logic Apps in your Azure subscription based on tags
    (Purpose: Azure AD Lifecycle Workflows or Purpose: Azure AD Entitlement Management) and allows
    you to run them manually for any user. The script uses interactive authentication and is designed
    for administrative use when you need to execute a single Custom Extension task without triggering
    a full Lifecycle Workflow.
    
    The script passes user information (Object ID, UPN, DisplayName, Mail) in a payload structure
    that matches the Microsoft Lifecycle Workflows custom extension schema, so your Logic App
    receives the same data format it would get from a real Lifecycle Workflow.

.PARAMETER SubscriptionId
    The Azure subscription ID containing the Custom Extension Logic Apps.
    Example: "12345678-1234-1234-1234-123456789012"

.EXAMPLE
    .\Custom-Extension-Runner.ps1 -SubscriptionId "12345678-1234-1234-1234-123456789012"
    Discovers Custom Extensions and prompts for user selection

.NOTES
    Author: Christian Frohn
    https://www.linkedin.com/in/frohn/
    Version: 1.0
    
    Prerequisites:
    - Az PowerShell module
    - Microsoft.Graph PowerShell module
    - Azure subscription with Custom Extension Logic Apps tagged appropriately
    
    Required Permissions:
    - User.Read.All: Search and retrieve user information from Entra ID
    - Logic App Operator: Run Logic Apps in the specified subscription/resource group

.LINK
    https://github.com/ChrFrohn/Custom-Extension-Runner
    https://www.christianfrohn.dk
#>

param (
    [Parameter(Mandatory = $true)]
    [string]$SubscriptionId
)

# Tag configuration for discovering Custom Extension Logic Apps
$CustomExtensionTagValues = @(
    "Azure AD Lifecycle Workflows",
    "Azure AD Entitlement Management"
)

# Connect to Azure
try {
    Connect-AzAccount -Subscription $SubscriptionId -ErrorAction Stop | Out-Null
    Write-Output "SUCCESS: Connected to Azure subscription: $SubscriptionId"
}
catch {
    Write-Output "ERROR: Failed to connect to Azure: $($_.Exception.Message)"
    Exit 1
}

# Connect to Microsoft Graph
try {
    Connect-MgGraph -Scopes "User.Read.All" -NoWelcome -ErrorAction Stop
    Write-Output "SUCCESS: Connected to Microsoft Graph"
}
catch {
    Write-Output "ERROR: Failed to connect to Microsoft Graph: $($_.Exception.Message)"
    Exit 1
}

# Discover Logic Apps with Custom Extension tags
Write-Output "INFO: Discovering Custom Extension Logic Apps..."

try {
    $AllLogicApps = Get-AzLogicApp -ErrorAction Stop
    Write-Output "INFO: Found $($AllLogicApps.Count) Logic Apps total in subscription"
}
catch {
    Write-Output "ERROR: Failed to retrieve Logic Apps: $($_.Exception.Message)"
    Exit 1
}

# Filter Logic Apps by supported tags
$CustomExtensions = @{}
foreach ($LogicApp in $AllLogicApps) {
    $Tags = $LogicApp.Tags
    $FoundTag = $null
    
    if ($Tags -and $Tags["Purpose"]) {
        $PurposeValue = $Tags["Purpose"]
        if ($CustomExtensionTagValues -contains $PurposeValue) {
            $FoundTag = $PurposeValue
        }
    }
    
    if ($FoundTag) {
        # Extract resource group from the Id property
        $ResourceGroup = $LogicApp.Id.Split('/')[4]
        $WorkflowName = $LogicApp.Name
        $DisplayName = if ($Tags["DisplayName"]) { $Tags["DisplayName"] } else { $WorkflowName }
        
        $TagType = switch ($FoundTag) {
            "Azure AD Lifecycle Workflows" { "[LCW]" }
            "Azure AD Entitlement Management" { "[EM]" }
            default { "[Custom]" }
        }
        
        $DisplayNameWithType = "$TagType $DisplayName"
        
        $CustomExtensions[$DisplayNameWithType] = @{
            ResourceGroup = $ResourceGroup
            WorkflowName  = $WorkflowName
            Location      = $LogicApp.Location
            TagType       = $FoundTag
        }
        
        Write-Output "INFO: Found Custom Extension: $DisplayNameWithType ($ResourceGroup)"
    }
}

if ($CustomExtensions.Count -eq 0) {
    Write-Output "ERROR: No Logic Apps found with supported tags:"
    foreach ($Tag in $CustomExtensionTagValues) {
        Write-Output "  - Purpose: $Tag"
    }
    Write-Output "Please ensure your Logic Apps are tagged correctly."
    Exit 1
}

Write-Output "SUCCESS: Found $($CustomExtensions.Count) Custom Extension(s)"

# Search for a user
$SearchQuery = Read-Host "`nEnter user email or display name to search"

try {
    $UsersResult = Get-MgUser -Filter "startswith(mail,'$SearchQuery') or startswith(displayName,'$SearchQuery')" -Property Id, DisplayName, Mail, UserPrincipalName -ErrorAction Stop
    
    # Ensure we always have an array
    $Users = @($UsersResult)
    
    if ($Users.Count -eq 0) {
        Write-Output "ERROR: No users found matching '$SearchQuery'"
        Exit 1
    }
    
    Write-Output "SUCCESS: Found $($Users.Count) user(s)"
}
catch {
    Write-Output "ERROR: Failed to search users: $($_.Exception.Message)"
    Exit 1
}

# Display users and let admin select
Write-Output "`nFound users:"
for ($i = 0; $i -lt $Users.Count; $i++) {
    Write-Output "[$i] $($Users[$i].DisplayName) - $($Users[$i].Mail)"
}

$UserIndex = Read-Host "`nSelect user by number"
$SelectedUser = $Users[$UserIndex]
Write-Output "SUCCESS: Selected user: $($SelectedUser.DisplayName)"

# Display Custom Extensions and let admin select
Write-Output "`nAvailable Custom Extensions:"
$ExtensionNames = $CustomExtensions.Keys | Sort-Object
for ($i = 0; $i -lt $ExtensionNames.Count; $i++) {
    $Extension = $CustomExtensions[$ExtensionNames[$i]]
    Write-Output "[$i] $($ExtensionNames[$i]) ($($Extension.ResourceGroup)/$($Extension.WorkflowName))"
}

$ExtensionIndex = Read-Host "`nSelect Custom Extension by number"
$SelectedExtensionName = $ExtensionNames[$ExtensionIndex]
$SelectedExtension = $CustomExtensions[$SelectedExtensionName]
Write-Output "SUCCESS: Selected extension: $SelectedExtensionName"

# Prepare payload (matches Lifecycle Workflows format)
$Payload = @{
    data = @{
        subject = @{
            id                = $SelectedUser.Id
            userPrincipalName = $SelectedUser.UserPrincipalName
            displayName       = $SelectedUser.DisplayName
            mail              = $SelectedUser.Mail
        }
    }
}

$JsonPayload = $Payload | ConvertTo-Json -Depth 10

# Call the Custom Extension
Write-Output "`nINFO: Calling Custom Extension..."
Write-Output "INFO: Workflow: $($SelectedExtension.ResourceGroup)/$($SelectedExtension.WorkflowName)"
Write-Output "INFO: Payload: $JsonPayload"

try {
    $TriggerPath = "/subscriptions/$SubscriptionId/resourceGroups/$($SelectedExtension.ResourceGroup)/providers/Microsoft.Logic/workflows/$($SelectedExtension.WorkflowName)/triggers/manual/run?api-version=2016-06-01"
    $Response = Invoke-AzRestMethod -Path $TriggerPath -Method POST -Payload $JsonPayload -ErrorAction Stop
    
    if ($Response.StatusCode -ge 200 -and $Response.StatusCode -lt 300) {
        Write-Output "`nSUCCESS: Custom Extension executed successfully!"
        Write-Output "User: $($SelectedUser.DisplayName)"
        Write-Output "Extension: $SelectedExtensionName"
        Write-Output "Resource Group: $($SelectedExtension.ResourceGroup)"
        Write-Output "Workflow: $($SelectedExtension.WorkflowName)"
        
        if ($Response.Content) {
            Write-Output "`nResponse:"
            Write-Output $Response.Content
        }
    }
    else {
        Write-Output "ERROR: Custom Extension returned status code $($Response.StatusCode)"
        Write-Output $Response.Content
        Exit 1
    }
}
catch {
    Write-Output "ERROR: Failed to execute Custom Extension: $($_.Exception.Message)"
    Exit 1
}
