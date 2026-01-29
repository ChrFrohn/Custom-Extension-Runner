const express = require('express');
const axios = require('axios');
const path = require('path');
const rateLimit = require('express-rate-limit');
const graphHelper = require('./utils/graphHelper');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Rate limiting for all requests
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // max 100 requests per IP per window
  message: {
    error: 'Too many requests from this IP, please try again later.',
    retryAfter: '15 minutes'
  },
  standardHeaders: true, // include rate limit info in headers
  legacyHeaders: false, // disable old X-RateLimit headers
});

// Stricter limits for sensitive operations
const strictLimiter = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 20, // max 20 requests per IP per window
  message: {
    error: 'Too many requests for this operation, please try again later.',
    retryAfter: '5 minutes'
  }
});

app.use(express.json({ limit: '10mb' })); // limit request body size
app.use(express.static('public'));

// Security headers for all responses
app.use((req, res, next) => {
  // Basic security headers
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  // keeping X-XSS-Protection for older browsers
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  
  // force HTTPS for a year
  res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  
  // block camera, microphone, location, payment APIs
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=(), payment=()');
  
  // content security policy
  res.setHeader('Content-Security-Policy', 
    "default-src 'self'; " +
    "style-src 'self' https://static2.sharepointonline.com; " +
    "font-src 'self' https://static2.sharepointonline.com; " +
    "img-src 'self' data:; " +
    "script-src 'self'; " +
    "connect-src 'self'; " +
    "object-src 'none'; " +
    "frame-ancestors 'none'; " +
    "base-uri 'self'; " +
    "form-action 'self'"
  );
  
  // hide server info
  res.removeHeader('X-Powered-By');
  
  next();
});

// Log all requests with timing
app.use((req, res, next) => {
  const start = Date.now();
  
  res.on('finish', () => {
    const duration = Date.now() - start;
    console.log(`${new Date().toISOString()} - ${req.method} ${req.originalUrl} - ${res.statusCode} - ${duration}ms - User: ${req.user?.name || 'anonymous'}`);
  });
  
  next();
});

// apply rate limiting to everything
app.use(limiter);

// parse user info from Azure App Service authentication (Easy Auth)
function parseUserFromEasyAuth(req, res, next) {
  const principalName = req.headers['x-ms-client-principal-name'];
  const principalId = req.headers['x-ms-client-principal-id'];
  const principalData = req.headers['x-ms-client-principal'];
  
  // Check if user is authenticated
  if (!principalName && !principalId) {
    req.user = null;
    return next();
  }
  
  // Base user info from simple headers
  req.user = {
    name: principalName,
    id: principalId,
    authenticated: !!(principalName || principalId)
  };
  
  // Parse the full principal data if available (contains claims, roles, etc.)
  if (principalData) {
    try {
      const decodedPrincipal = JSON.parse(Buffer.from(principalData, 'base64').toString('utf8'));
      
      // Extract claims from the decoded principal
      const claims = decodedPrincipal.claims || [];
      const claimsMap = {};
      claims.forEach(claim => {
        claimsMap[claim.typ] = claim.val;
      });
      
      // Add additional user properties from claims
      req.user.email = claimsMap['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress'] 
                    || claimsMap['email'] 
                    || claimsMap['preferred_username'];
      req.user.userPrincipalName = claimsMap['http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn'] 
                                || claimsMap['upn'] 
                                || principalName;
      req.user.roles = decodedPrincipal.roles || [];
      req.user.identityProvider = decodedPrincipal.identity_provider || 'aad';
      
    } catch (error) {
      console.warn('Failed to parse Easy Auth principal data:', error.message);
    }
  }
  
  next();
}

// Azure configuration from environment variables
const SUBSCRIPTION_ID = process.env.AZURE_SUBSCRIPTION_ID || process.env.SUBSCRIPTION_ID;
const LOGIC_APPS_RESOURCE_GROUP_RAW = process.env.LOGIC_APPS_RESOURCE_GROUP;

// Parse comma-separated resource groups into array (supports multiple resource groups)
const LOGIC_APPS_RESOURCE_GROUPS = LOGIC_APPS_RESOURCE_GROUP_RAW 
  ? LOGIC_APPS_RESOURCE_GROUP_RAW.split(',').map(rg => rg.trim()).filter(rg => rg.length > 0)
  : [];

// make sure we have the config we need
if (!SUBSCRIPTION_ID || LOGIC_APPS_RESOURCE_GROUPS.length === 0) {
  console.error('Missing required environment variables:');
  if (!SUBSCRIPTION_ID) console.error('  - AZURE_SUBSCRIPTION_ID');
  if (LOGIC_APPS_RESOURCE_GROUPS.length === 0) console.error('  - LOGIC_APPS_RESOURCE_GROUP (can be comma-separated for multiple resource groups)');
  process.exit(1);
}

console.log(`Configured to search ${LOGIC_APPS_RESOURCE_GROUPS.length} resource group(s): ${LOGIC_APPS_RESOURCE_GROUPS.join(', ')}`);

// get Graph token using our helper
async function getGraphToken() {
  try {
    return await graphHelper.getGraphToken();
  } catch (error) {
    console.error('Failed to get Graph API token via Graph helper:', error.message);
    throw error;
  }
}

// get Azure Resource Manager token using managed identity
async function getManagedIdentityToken() {
  try {
    const msi_endpoint = process.env.MSI_ENDPOINT || process.env.IDENTITY_ENDPOINT;
    const msi_secret = process.env.MSI_SECRET || process.env.IDENTITY_HEADER;
    
    let tokenUrl, headers;
    
    if (msi_endpoint && msi_secret) {
      tokenUrl = `${msi_endpoint}?api-version=2019-08-01&resource=https://management.azure.com/`;
      headers = { 'X-IDENTITY-HEADER': msi_secret };
    } else {
      tokenUrl = 'http://169.254.169.254/metadata/identity/oauth2/token';
      headers = { 'Metadata': 'true' };
    }
    
    const response = await axios.get(tokenUrl, {
      params: msi_endpoint ? {} : {
        'api-version': '2018-02-01',
        'resource': 'https://management.azure.com/'
      },
      headers: headers,
      timeout: 15000
    });
    
    return response.data.access_token;
  } catch (error) {
    console.error('Failed to get managed identity token:', error.message);
    throw new Error('Managed identity token acquisition failed');
  }
}

// get lifecycle workflow extensions from Graph API
async function getLifecycleWorkflowExtensions() {
  try {
    const extensions = await graphHelper.getCustomTaskExtensions();

    return extensions.map(ext => ({
      id: ext.id,
      name: ext.displayName || 'Unnamed Extension',
      description: ext.description || 'No description available',
      catalog: 'Lifecycle Workflows',
      catalogType: 'lifecycle',
      createdDate: ext.createdDateTime,
      source: 'graph-api'
    }));
  } catch (error) {
    console.error('Failed to get lifecycle workflow extensions:', error.message);
    
    // help with common auth issues
    if (error.message.includes('AuthenticationError') || error.message.includes('400')) {
      console.error('This usually means missing Entra ID Governance license or permissions');
      console.error('Make sure the managed identity has LifecycleWorkflows.Read.All permission');
    }
    
    return [];
  }
}

// get entitlement management extensions (access packages for now)
async function getEntitlementManagementExtensions() {
  try {
    // using access packages since custom workflow extensions are rare here
    const accessPackages = await graphHelper.getAccessPackages();

    return accessPackages.map(pkg => ({
      id: pkg.id,
      name: pkg.displayName || 'Unnamed Access Package',
      description: pkg.description || 'No description available',
      catalog: pkg.catalog?.displayName || 'Entitlement Management',
      catalogId: pkg.catalog?.id,
      catalogType: 'entitlement',
      source: 'graph-api'
    }));
  } catch (error) {
    console.error('Failed to get entitlement management extensions:', error.message);
    return [];
  }
}

// find Logic Apps tagged as custom extensions
async function getLogicAppsExtensions(managementToken) {
  try {
    if (!SUBSCRIPTION_ID || LOGIC_APPS_RESOURCE_GROUPS.length === 0) {
      console.warn('Azure config missing for Logic Apps discovery');
      return [];
    }

    const headers = {
      'Authorization': `Bearer ${managementToken}`,
      'Content-Type': 'application/json'
    };

    const customExtensionTagValues = [
      'Azure AD Lifecycle Workflows',
      'Azure AD Entitlement Management'
    ];

    const logicApps = [];
    
    // Loop through all configured resource groups
    for (const resourceGroupName of LOGIC_APPS_RESOURCE_GROUPS) {
      try {
        const logicAppsUri = `https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${resourceGroupName}/providers/Microsoft.Logic/workflows?api-version=2016-06-01`;
        const response = await axios.get(logicAppsUri, { headers });
        
        for (const logicApp of response.data.value || []) {
          const tags = logicApp.tags;
          let foundTag = null;
          
          if (tags && tags.Purpose) {
            const purposeValue = tags.Purpose;
            if (customExtensionTagValues.includes(purposeValue)) {
              foundTag = purposeValue;
            }
          }
          
          if (foundTag) {
            const resourceGroup = logicApp.id.split('/')[4];
            const workflowName = logicApp.name;
            
            const triggerUrl = `https://management.azure.com/subscriptions/${SUBSCRIPTION_ID}/resourceGroups/${resourceGroup}/providers/Microsoft.Logic/workflows/${workflowName}/triggers/manual/run?api-version=2016-06-01`;
            
            logicApps.push({
              name: workflowName,
              workflowName: workflowName,
              triggerUrl: triggerUrl,
              tagType: foundTag,
              catalogType: foundTag === 'Azure AD Lifecycle Workflows' ? 'lifecycle' : 'entitlement',
              resourceGroup: resourceGroup,
              location: logicApp.location,
              source: 'logic-apps'
            });
          }
        }
        
        console.log(`Found Logic Apps in resource group '${resourceGroupName}': ${response.data.value?.length || 0} total, ${logicApps.filter(la => la.resourceGroup === resourceGroupName).length} with custom extension tags`);
      } catch (rgError) {
        console.warn(`Failed to query Logic Apps in resource group '${resourceGroupName}': ${rgError.message}`);
        // Continue to next resource group even if one fails
      }
    }

    console.log(`Found ${logicApps.length} Logic App Custom Extensions across ${LOGIC_APPS_RESOURCE_GROUPS.length} resource group(s)`);
    return logicApps;
    return logicApps;
  } catch (error) {
    console.error('Failed to get Logic Apps extensions:', error.response?.data || error.message);
    return [];
  }
}

// match Graph extensions with Logic Apps by name
function matchExtensionsWithLogicApps(graphExtensions, logicApps) {
  const matchedExtensions = [];
  
  for (const graphExt of graphExtensions) {
    const matchingLogicApp = logicApps.find(logicApp => {
      if (logicApp.name.toLowerCase() === graphExt.name.toLowerCase()) return true;
      
      const cleanGraphName = graphExt.name.toLowerCase().replace(/[^a-z0-9]/g, '');
      const cleanLogicName = logicApp.name.toLowerCase().replace(/[^a-z0-9]/g, '');
      
      return cleanGraphName.includes(cleanLogicName) || cleanLogicName.includes(cleanGraphName);
    });
    
    if (matchingLogicApp) {
      matchedExtensions.push({
        ...graphExt,
        triggerUrl: matchingLogicApp.triggerUrl,
        workflowName: matchingLogicApp.workflowName,
        resourceGroup: matchingLogicApp.resourceGroup,
        executable: true,
        matchSource: 'hybrid'
      });
    } else {
      matchedExtensions.push({
        ...graphExt,
        executable: false,
        matchSource: 'graph-only'
      });
    }
  }
  
  return matchedExtensions;
}

// require auth for all API routes
app.use('/api', parseUserFromEasyAuth);

app.get('/api/extensions', async (req, res) => {
  try {
    const managementToken = await getManagedIdentityToken();

    // get extensions from both sources at the same time
    const [lifecycleExtensions, entitlementExtensions, logicApps] = await Promise.all([
      getLifecycleWorkflowExtensions(),
      getEntitlementManagementExtensions(),
      getLogicAppsExtensions(managementToken)
    ]);

    // combine all Graph extensions
    const graphExtensions = [...lifecycleExtensions, ...entitlementExtensions];

    // match them with Logic Apps
    const matchedExtensions = matchExtensionsWithLogicApps(graphExtensions, logicApps);

    // add Logic Apps that didn't match any Graph extension
    const unmatchedLogicApps = logicApps.filter(logicApp => 
      !matchedExtensions.some(ext => ext.workflowName === logicApp.workflowName)
    );

    for (const logicApp of unmatchedLogicApps) {
      matchedExtensions.push({
        id: `logic-app-${logicApp.workflowName}`,
        name: logicApp.name,
        description: 'Legacy Logic App - No Graph API metadata available',
        catalog: logicApp.tagType === 'Azure AD Lifecycle Workflows' ? 'Lifecycle Workflows' : 'Entitlement Management',
        catalogType: logicApp.catalogType,
        triggerUrl: logicApp.triggerUrl,
        workflowName: logicApp.workflowName,
        resourceGroup: logicApp.resourceGroup,
        executable: true,
        matchSource: 'logic-app-only',
        source: 'logic-apps'
      });
    }

    const executableCount = matchedExtensions.filter(ext => ext.executable).length;
    console.log(`Extensions: ${matchedExtensions.length} total, ${executableCount} executable`);
    
    res.json(matchedExtensions);
  } catch (error) {
    console.error('Extensions error:', error.message);
    res.status(500).json({ error: 'Failed to load extensions: ' + error.message });
  }
});

app.get('/api/users/search', strictLimiter, async (req, res) => {
  try {
    const { q } = req.query;
    
    // basic input checks
    if (!q || typeof q !== 'string') {
      return res.status(400).json({ error: 'Query parameter "q" is required and must be a string' });
    }

    // clean up the search query
    const sanitizedQuery = q.trim().slice(0, 100).replace(/['"\\;]/g, '');
    
    if (sanitizedQuery.length < 2) {
      return res.status(400).json({ error: 'Query must be at least 2 characters long' });
    }

    if (!/^[a-zA-Z0-9@._\-\s]+$/.test(sanitizedQuery)) {
      return res.status(400).json({ error: 'Query contains invalid characters' });
    }

    // search users using Graph SDK
    const users = await graphHelper.searchUsers(sanitizedQuery, 20);
    
    console.log(`User search for "${sanitizedQuery}" returned ${users.length} results`);
    res.json(users);
  } catch (error) {
    console.error('User search error:', error.message);
    
    if (error.message.includes('403') || error.message.includes('Access denied')) {
      res.status(403).json({ 
        error: 'Access denied',
        message: 'You do not have permission to search users in this directory'
      });
    } else if (error.message.includes('401') || error.message.includes('Authentication')) {
      res.status(401).json({ 
        error: 'Authentication failed',
        message: 'Invalid or expired authentication token'
      });
    } else {
      res.status(500).json({ 
        error: 'User search failed', 
        timestamp: new Date().toISOString() 
      });
    }
  }
});

// get info about the current user
app.get('/api/user/me', (req, res) => {
  try {
    if (!req.user || !req.user.authenticated) {
      return res.status(401).json({ 
        error: 'User not authenticated',
        message: 'No user context available from Easy Auth',
        authenticated: false
      });
    }

    // return user info from Easy Auth
    res.json({
      id: req.user.id,
      name: req.user.name,
      email: req.user.email || req.user.userPrincipalName,
      userPrincipalName: req.user.userPrincipalName,
      roles: req.user.roles || [],
      identityProvider: req.user.identityProvider,
      authenticated: true
    });
  } catch (error) {
    console.error('User info error:', error.message);
    res.status(500).json({ 
      error: 'Failed to get user information',
      timestamp: new Date().toISOString()
    });
  }
});

app.post('/api/extensions/execute', strictLimiter, async (req, res) => {
  try {
    const { extensionUrl, extension, user, userObjectId, extensionName } = req.body;
    
    let triggerUrl = extensionUrl;
    let extName = extensionName;
    
    if (extension) {
      triggerUrl = extension.triggerUrl || extension.extensionUrl;
      extName = extension.name || extensionName;
      
      if (!extension.executable) {
        return res.status(400).json({ 
          error: 'Extension is not executable',
          message: 'This extension was found via Microsoft Graph API but no corresponding Logic App was found.',
          extension: {
            name: extension.name,
            id: extension.id,
            matchSource: extension.matchSource
          }
        });
      }
    }
    
    // Support both new user object format and legacy userObjectId for backwards compatibility
    const targetUserId = user?.id || userObjectId;
    
    if (!triggerUrl || !targetUserId) {
      return res.status(400).json({ error: 'Missing required parameters: triggerUrl and user' });
    }

    const managedIdentityToken = await getManagedIdentityToken();
    
    // Build payload following Microsoft Learn Lifecycle Workflows custom extension schema
    // Reference: https://learn.microsoft.com/en-us/entra/id-governance/lifecycle-workflow-extensibility
    const payload = {
      data: {
        taskProcessingResult: {
          task: {
            displayName: extName || 'Custom Extension'
          }
        },
        subject: {
          id: targetUserId,
          userPrincipalName: user?.userPrincipalName || '',
          displayName: user?.displayName || '',
          mail: user?.mail || ''
        },
        auditContext: {
          executedBy: req.user.name,
          executedAt: new Date().toISOString(),
          applicationSource: 'CustomExtensionRunner',
          userContext: req.user.id
        }
      },
      source: '/LifecycleManagement/accessPackage/assignmentRequest',
      type: 'microsoft.graph.accessPackageCustomExtensionStage.request'
    };

    console.log(`Executing extension: ${extName} for user: ${targetUserId} (${user?.userPrincipalName || 'unknown'}) by: ${req.user.name}`);

    const response = await axios.post(triggerUrl, payload, {
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${managedIdentityToken}`
      }
    });

    console.log(`Executed extension: ${extName} for user: ${targetUserId} by: ${req.user.name}`);
    res.json({ success: true, result: response.data });
  } catch (error) {
    console.error(`Extension execution error for user ${req.user.name}:`, error.response?.data || error.message);
    res.status(500).json({ 
      error: 'Extension execution failed',
      message: 'An error occurred while executing the extension',
      timestamp: new Date().toISOString()
    });
  }
});

// Health check endpoints (both /health and /api/health for Azure App Service)
const healthCheckHandler = (req, res) => {
  res.json({ 
    status: 'healthy', 
    timestamp: new Date().toISOString(),
    authMethod: 'Managed Identity (Application Permissions)',
    environment: {
      subscriptionId: SUBSCRIPTION_ID ? 'configured' : 'missing',
      logicAppsResourceGroups: LOGIC_APPS_RESOURCE_GROUPS.length > 0 
        ? `${LOGIC_APPS_RESOURCE_GROUPS.length} configured: ${LOGIC_APPS_RESOURCE_GROUPS.join(', ')}` 
        : 'missing',
      port: PORT,
      nodeVersion: process.version,
      platform: process.platform
    }
  });
};

app.get('/health', healthCheckHandler);
app.get('/api/health', healthCheckHandler);

// serve the main page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, async () => {
  console.log(`Custom Extension Runner started on port ${PORT}`);
  console.log(`Authentication: Managed Identity (Application Permissions)`);
  console.log(`Health check: /health`);
  
  // Only show localhost URL in local development
  if (process.env.NODE_ENV !== 'production' && !process.env.WEBSITE_SITE_NAME) {
    console.log(`Web interface: http://localhost:${PORT}`);
  } else {
    console.log(`Running in Azure App Service: ${process.env.WEBSITE_SITE_NAME || 'Azure-hosted'}`);
  }
  
  // test tokens at startup
  try {
    await getManagedIdentityToken();
    console.log('Azure Resource Manager token acquired successfully');
  } catch (error) {
    console.warn('Managed identity check failed at startup');
  }

  try {
    await getGraphToken();
    console.log('Microsoft Graph token acquired successfully');
  } catch (error) {
    console.warn('Graph API token check failed at startup');
  }
});

// handle shutdown gracefully
process.on('SIGTERM', () => {
  console.log('SIGTERM received, shutting down gracefully');
  process.exit(0);
});

process.on('SIGINT', () => {
  console.log('SIGINT received, shutting down gracefully');
  process.exit(0);
});

module.exports = app;
