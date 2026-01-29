# Custom Extension Runner

A web application to execute Entra ID Governance Custom Extensions on-demand for specific users. This tool helps quickly run individual Custom Extension tasks without needing to navigate to the Automation Account or trigger a full Lifecycle Workflow.

This app is based on the PowerShell script found in this blog post: https://www.christianfrohn.dk/

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2FChrFrohn%2FCustom-Extension-Runner%2Fmain%2Fazuredeploy.json)

## Features

- 🔍 **Smart Discovery** - Automatically finds Custom Extension Logic Apps based on Azure tags (`Purpose: Azure AD Lifecycle Workflows` or `Purpose: Azure AD Entitlement Management`)
- ▶️ **On-Demand Execution** - Run any Custom Extension task individually without triggering the full Lifecycle Workflow
- 👥 **User Search** - Search and select users from your Entra ID directory
- 🔐 **Secure Authentication** - Uses Azure Managed Identity (no hardcoded credentials)

## How It Works

The app passes user information including Object ID, UserPrincipalName, DisplayName, and Mail in a payload structure that matches the Microsoft Lifecycle Workflows custom extension schema. This means your Custom extension code receives the same data format it would get from a real Lifecycle Workflow.

> ⚠️ **Note about Callback Actions**: If your Azure Logic App includes the callback HTTP action (the one that reports status back to Lifecycle Workflows), this step will show as failed when triggered outside of a Lifecycle workflow. This happens because there's no Lifecycle workflow running to report back to, so the `callbackUriPath` is empty. Don't worry though - this doesn't affect the actual work your Logic App does, only the callback step fails.

## Current Limitations

- It's currently only possible to pass user identity attributes, not other attributes like HireDate or Phone number etc.

<img width="1173" height="495" alt="Blog-AppScreenshot" src="https://github.com/user-attachments/assets/115594c6-fb5a-4a00-8aac-88dce07b1f66" />

## Prerequisites

- Azure subscription
- **Microsoft Graph PowerShell Module** (for granting permissions to Managed Identity)
    * Permissions needed for the managed identity (Web app):
      - LifecycleWorkflows.Read.All
      - EntitlementManagement.Read.All
      - User.Read.All
- **Azure PowerShell Module** (for managing Azure resources)
- **Azure RBAC**:
    * Logic App Operator on the resource group(s) containing your Custom Extension Logic Apps

## Deploy to Azure

Click the button above to deploy this application to your Azure subscription using the included ARM template.

> **⚠️ Important**: After deployment, you **must** configure Managed Identity permissions. See [Post-Deployment Configuration](#post-deployment-configuration).

### Post-Deployment Configuration

After deployment, you **must** configure Microsoft Graph API permissions for the Managed Identity.

> **💡 Recommended**: Once deployed, enable Single Sign-On (SSO) for better security and user experience. Follow the guide: [Configure Microsoft Entra ID authentication for App Service](https://learn.microsoft.com/azure/app-service/configure-authentication-provider-aad?tabs=workforce-configuration)

#### Step 1: Install Required PowerShell Modules

```powershell
# Install Microsoft Graph PowerShell module
Install-Module Microsoft.Graph -Scope CurrentUser

# Install Azure PowerShell module
Install-Module Az -Scope CurrentUser
```

#### Step 2: Grant Microsoft Graph Permissions to the Managed Identity

```powershell
# Connect to Azure (required to get Managed Identity details)
Connect-AzAccount

# Connect to Microsoft Graph (requires Global Administrator or Privileged Role Administrator)
Connect-MgGraph -Scopes "Application.Read.All", "AppRoleAssignment.ReadWrite.All"

# Prompt for your Web App details
$webAppName = Read-Host "Enter your Web App name"
$resourceGroup = Read-Host "Enter your Resource Group name"

# Get the Managed Identity's Object ID
$managedIdentity = Get-AzWebApp -ResourceGroupName $resourceGroup -Name $webAppName
$managedIdentityObjectId = $managedIdentity.Identity.PrincipalId

# Get Microsoft Graph Service Principal
$graphSP = Get-MgServicePrincipal -Filter "appId eq '00000003-0000-0000-c000-000000000000'"

# Assign LifecycleWorkflows.Read.All permission
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentityObjectId -BodyParameter @{
    PrincipalId = $managedIdentityObjectId
    ResourceId = $graphSP.Id
    AppRoleId = "7c67316a-232a-4b84-be22-cea2c0906404"
}

# Assign EntitlementManagement.Read.All permission
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentityObjectId -BodyParameter @{
    PrincipalId = $managedIdentityObjectId
    ResourceId = $graphSP.Id
    AppRoleId = "c74fd47d-ed3c-45c3-9a9e-b8676de685d2"
}

# Assign User.Read.All permission
New-MgServicePrincipalAppRoleAssignment -ServicePrincipalId $managedIdentityObjectId -BodyParameter @{
    PrincipalId = $managedIdentityObjectId
    ResourceId = $graphSP.Id
    AppRoleId = "df021288-bdef-4463-88db-98f22de89214"
}

Write-Host "Permissions assigned successfully!"
```

**Note**: Assigning Microsoft Graph permissions requires **Global Administrator** or **Privileged Role Administrator** role.

## License

MIT License

