/**
 * Microsoft Graph API Helper
 * Uses official Microsoft Graph SDK with Azure Identity for managed identity auth
 * 
 * @author Christian Frohn
 */

const { DefaultAzureCredential } = require('@azure/identity');
const { Client } = require('@microsoft/microsoft-graph-client');

class GraphApiHelper {
    constructor() {
        this.credential = null;
        this.graphClient = null;
        this.tokenCache = null;
        this.tokenExpiry = null;
        
        console.log('Microsoft Graph API Helper initialized with Azure Identity SDK');
    }

    /**
     * Setup Graph client with managed identity
     */
    async initializeGraphClient() {
        try {
            if (this.graphClient) {
                return this.graphClient;
            }

            // use managed identity in App Service
            this.credential = new DefaultAzureCredential({
                managedIdentityClientId: process.env.AZURE_CLIENT_ID, // optional for user-assigned MI
                tenantId: process.env.AZURE_TENANT_ID // optional
            });

            // auth provider using access tokens
            const authProvider = {
                getAccessToken: async () => {
                    const tokenResponse = await this.credential.getToken('https://graph.microsoft.com/.default');
                    return tokenResponse.token;
                }
            };

            // setup Graph client
            this.graphClient = Client.initWithMiddleware({
                authProvider: authProvider,
                defaultVersion: 'v1.0', // Use stable v1.0 endpoint
                debugLogging: process.env.NODE_ENV === 'development'
            });

            console.log('Microsoft Graph client initialized successfully with managed identity');
            return this.graphClient;
        } catch (error) {
            console.error('Failed to initialize Microsoft Graph client:', error.message);
            throw new Error(`Graph client initialization failed: ${error.message}`);
        }
    }

    /**
     * Get Graph access token with caching
     */
    async getGraphToken() {
        try {
            // use cached token if still valid
            if (this.tokenCache && this.tokenExpiry && Date.now() < this.tokenExpiry - 60000) {
                console.log('Using cached Graph API token');
                return this.tokenCache;
            }

            if (!this.credential) {
                this.credential = new DefaultAzureCredential({
                    managedIdentityClientId: process.env.AZURE_CLIENT_ID,
                    tenantId: process.env.AZURE_TENANT_ID
                });
            }

            // get fresh token
            const tokenResponse = await this.credential.getToken('https://graph.microsoft.com/.default');
            
            if (!tokenResponse || !tokenResponse.token) {
                throw new Error('No access token received from Azure Identity');
            }

            // cache it
            this.tokenCache = tokenResponse.token;
            this.tokenExpiry = tokenResponse.expiresOnTimestamp;

            console.log('Successfully acquired Graph API token via managed identity');
            return tokenResponse.token;
        } catch (error) {
            console.error('Failed to get Graph API token via managed identity:', error.message);
            throw new Error(`Graph API token acquisition failed: ${error.message}`);
        }
    }

    /**
     * Get Graph client with lazy init
     */
    async getGraphClient() {
        if (!this.graphClient) {
            await this.initializeGraphClient();
        }
        return this.graphClient;
    }

    /**
     * Search for users in Graph
     */
    async searchUsers(searchTerm, top = 25) {
        try {
            const client = await this.getGraphClient();
            
            // use Graph search with proper headers
            const users = await client
                .api('/users')
                .header('ConsistencyLevel', 'eventual')
                .search(`"displayName:${searchTerm}" OR "mail:${searchTerm}" OR "userPrincipalName:${searchTerm}"`)
                .select(['id', 'displayName', 'mail', 'userPrincipalName', 'jobTitle', 'department'])
                .top(top)
                .count(true)
                .get();

            console.log(`Found ${users.value ? users.value.length : 0} users matching search term: ${searchTerm}`);
            return users.value || [];
        } catch (error) {
            console.error('User search failed:', error.message);
            throw new Error(`User search failed: ${error.message}`);
        }
    }

    /**
     * Get current user info
     */
    async getCurrentUser() {
        try {
            const client = await this.getGraphClient();
            
            const user = await client
                .api('/me')
                .select(['id', 'displayName', 'mail', 'userPrincipalName', 'jobTitle'])
                .get();

            console.log('Retrieved current user information');
            return user;
        } catch (error) {
            console.error('Failed to get current user:', error.message);
            throw new Error(`Get current user failed: ${error.message}`);
        }
    }

    /**
     * Get lifecycle workflows
     */
    async getLifecycleWorkflows() {
        try {
            const client = await this.getGraphClient();
            
            const workflows = await client
                .api('/identityGovernance/lifecycleWorkflows/workflows')
                .select(['id', 'displayName', 'description', 'isEnabled', 'category'])
                .get();

            console.log(`Retrieved ${workflows.value.length} lifecycle workflows`);
            return workflows.value;
        } catch (error) {
            console.error('Failed to get lifecycle workflows:', error.message);
            throw new Error(`Lifecycle workflows retrieval failed: ${error.message}`);
        }
    }

    /**
     * Get custom task extensions for lifecycle workflows
     * Note: Uses Beta API as customTaskExtensions endpoint requires it
     */
    async getCustomTaskExtensions() {
        try {
            const client = await this.getGraphClient();
            
            const extensions = await client
                .api('/identityGovernance/lifecycleWorkflows/customTaskExtensions')
                .version('beta')
                .select(['id', 'displayName', 'description', 'endpointConfiguration', 'authenticationConfiguration'])
                .get();

            console.log(`Retrieved ${extensions.value.length} custom task extensions`);
            return extensions.value;
        } catch (error) {
            console.error('Failed to get custom task extensions:', error.message);
            throw new Error(`Custom task extensions retrieval failed: ${error.message}`);
        }
    }

    /**
     * Get access packages from Entitlement Management
     */
    async getAccessPackages() {
        try {
            const client = await this.getGraphClient();
            
            const packages = await client
                .api('/identityGovernance/entitlementManagement/accessPackages')
                .select(['id', 'displayName', 'description', 'isHidden'])
                .expand('catalog($select=id,displayName)')
                .get();

            console.log(`Retrieved ${packages.value.length} access packages`);
            return packages.value;
        } catch (error) {
            console.error('Failed to get access packages:', error.message);
            throw new Error(`Access packages retrieval failed: ${error.message}`);
        }
    }

    /**
     * Execute a custom task extension for a specific user
     */
    async executeCustomTaskExtension(extensionId, userId, additionalData = {}) {
        try {
            const client = await this.getGraphClient();
            
            const executionData = {
                subject: {
                    id: userId
                },
                ...additionalData
            };

            // Note: This is a conceptual implementation - actual execution may depend on specific workflow setup
            const result = await client
                .api(`/identityGovernance/lifecycleWorkflows/customTaskExtensions/${extensionId}/execute`)
                .post(executionData);

            console.log(`Executed custom task extension ${extensionId} for user ${userId}`);
            return result;
        } catch (error) {
            console.error('Custom task extension execution failed:', error.message);
            throw new Error(`Extension execution failed: ${error.message}`);
        }
    }

    /**
     * Make a raw Graph API call with automatic authentication
     */
    async makeGraphCall(endpoint, method = 'GET', data = null) {
        try {
            const client = await this.getGraphClient();
            let request = client.api(endpoint);

            switch (method.toUpperCase()) {
                case 'GET':
                    return await request.get();
                case 'POST':
                    return await request.post(data);
                case 'PUT':
                    return await request.put(data);
                case 'PATCH':
                    return await request.patch(data);
                case 'DELETE':
                    return await request.delete();
                default:
                    throw new Error(`Unsupported HTTP method: ${method}`);
            }
        } catch (error) {
            console.error(`Graph API call failed [${method} ${endpoint}]:`, error.message);
            throw new Error(`Graph API call failed: ${error.message}`);
        }
    }

    /**
     * Clear cached tokens and reset client (useful for testing or error recovery)
     */
    resetClient() {
        this.credential = null;
        this.graphClient = null;
        this.tokenCache = null;
        this.tokenExpiry = null;
        console.log('Graph client reset completed');
    }
}

// Export singleton instance
module.exports = new GraphApiHelper();
