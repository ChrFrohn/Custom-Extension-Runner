// Get authenticated user from Easy Auth
async function getAuthenticatedUser() {
    try {
        const response = await fetch('/api/user/me');
        if (response.ok) {
            const user = await response.json();
            console.log('User authenticated:', user.name);
            currentUser = user;
            return user;
        } else {
            console.warn('User not authenticated');
            return {
                name: 'Not Authenticated',
                email: 'unknown@domain.com',
                id: 'unknown',
                authenticated: false
            };
        }
    } catch (error) {
        console.error('Failed to get user info:', error);
        return {
            name: 'Unknown User',
            email: 'unknown@domain.com',
            id: 'unknown',
            authenticated: false
        };
    }
}

// Log user activity for audit trail
async function logUserActivity(action, details) {
    try {
        const user = await getAuthenticatedUser();
        await fetch('/api/audit/log', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                user: user,
                action: action,
                details: details,
                timestamp: new Date().toISOString()
            })
        });
    } catch (error) {
        console.warn('Failed to log user activity:', error);
    }
}

// Application state
let selectedUser = null;
let selectedExtension = null;
let extensions = [];
let currentUser = null;

// Initialize application on page load
document.addEventListener('DOMContentLoaded', async function() {
    await initializeApp();
});

// Initialize the application
async function initializeApp() {
    try {
        // Get current user and update display
        const user = await getAuthenticatedUser();
        updateUserDisplay(user);
        
        // Load available extensions
        await loadExtensions();
        
        // Set up keyboard handlers
        setupSearchKeyHandler();
    } catch (error) {
        console.error('Application initialization failed:', error);
        showError('Failed to initialize application. Please refresh the page.');
    }
}

// Update user display in UI
function updateUserDisplay(user) {
    const userDisplayElement = document.getElementById('currentUser');
    if (userDisplayElement) {
        userDisplayElement.textContent = user.authenticated ? 
            `Logged in as: ${user.name}` : 
            'Not authenticated';
        userDisplayElement.className = 'user-display ' + (user.authenticated ? 'user-authenticated' : 'user-not-authenticated');
    }
}

// Show main extensions list view
function showExtensionsView() {
    document.getElementById('extensionsView').classList.add('active');
    document.getElementById('extensionDetailView').classList.remove('active');
    selectedUser = null;
    updateExecuteButton();
    
    document.getElementById('userResults').innerHTML = `
        <div class="empty-state">
            <div class="empty-state-icon">Search</div>
            <p>Search for a user to process with this extension</p>
        </div>
    `;
    
    document.getElementById('executionResults').innerHTML = `
        <div class="empty-state">
            <div class="empty-state-icon">Results</div>
            <p>Execution results will appear here</p>
        </div>
    `;
}

function showExtensionDetailView(extension) {
    selectedExtension = extension;
    
    const extensionType = extension.catalogType === 'lifecycle' 
        ? 'Lifecycle Workflow' 
        : 'Entitlement Management';
    
    document.getElementById('extensionDetailTitle').textContent = extension.name;
    document.getElementById('extensionDetailSubtitle').textContent = `Catalog: ${extension.catalog} | Type: ${extensionType}`;
    
    document.getElementById('extensionsView').classList.remove('active');
    document.getElementById('extensionDetailView').classList.add('active');
    
    document.getElementById('userSearch').value = '';
    updateExecuteButton();
}
// Load Custom Extensions from Logic Apps with matching tags
async function loadExtensions() {
    const container = document.getElementById('extensionResults');
    container.innerHTML = '<div class="loading"><div class="spinner"></div>Loading extensions...</div>';

    try {
        const response = await fetch('/api/extensions');
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.error || 'Failed to load extensions');
        }

        // Filter to only show executable extensions
        // Excludes Custom Extensions without Logic Apps and Logic Apps without Custom Extensions
        const executableExtensions = result.filter(ext => 
            ext.executable === true && 
            ext.triggerUrl && 
            ext.workflowName &&
            ext.matchSource !== 'logic-app-only' &&
            ext.source !== 'logic-apps'
        );
        extensions = executableExtensions;

        if (executableExtensions.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon"><i class="ms-Icon ms-Icon--PlugConnected" style="font-size: 48px; color: #605e5c;"></i></div>
                    <p>No Matching Custom Extensions Found</p>
                    <p>Extensions require BOTH a configured Custom Extension AND a corresponding Logic App to be executable.</p>
                    <p>Ensure your Custom Extensions are properly configured and have matching Logic Apps with correct tags.</p>
                </div>
            `;
            return;
        }

        container.innerHTML = `
            <div class="extension-grid">
                ${executableExtensions.map((extension, index) => `
                    <div class="extension-card" onclick="selectExtensionByIndex(${index})">
                        <div class="extension-icon">
                            <i class="ms-Icon ms-Icon--${extension.catalogType === 'lifecycle' ? 'WorkFlow' : 'Package'}" aria-hidden="true"></i>
                        </div>
                        <h3>${escapeHtml(extension.name)}</h3>
                        <p class="extension-catalog"><i class="ms-Icon ms-Icon--FabricFolder" aria-hidden="true"></i> ${escapeHtml(extension.catalog)}</p>
                        <p class="extension-description">${escapeHtml(extension.description)}</p>
                    </div>
                `).join('')}
            </div>
        `;

    } catch (error) {
        container.innerHTML = `
            <div class="error">
                <strong>Failed to load extensions:</strong> ${escapeHtml(error.message)}
            </div>
        `;
    }
}

function selectExtensionByIndex(index) {
    if (extensions[index]) {
        showExtensionDetailView(extensions[index]);
    }
}

// Looking up users in Entra ID using the search term
async function searchUsers() {
    const query = document.getElementById('userSearch').value.trim();
    if (!query) return;

    const container = document.getElementById('userResults');
    container.innerHTML = '<div class="loading"><div class="spinner"></div>Searching users...</div>';

    try {
        const response = await fetch(`/api/users/search?q=${encodeURIComponent(query)}`);
        const result = await response.json();
        
        if (!response.ok) {
            throw new Error(result.error || 'Search failed');
        }

        if (result.length === 0) {
            container.innerHTML = `
                <div class="empty-state">
                    <div class="empty-state-icon">No results</div>
                    <p>No users found matching "${query}"</p>
                    <p>Try a different search term</p>
                </div>
            `;
            return;
        }

        container.innerHTML = result.map(user => 
            `<div class="user-item" data-userid="${escapeHtml(user.id)}" data-upn="${escapeHtml(user.userPrincipalName)}" data-displayname="${escapeHtml(user.displayName)}" data-mail="${escapeHtml(user.mail || '')}" onclick="selectUserFromElement(this)">
                <div class="item-title">${escapeHtml(user.displayName)}</div>
                <div class="item-subtitle">${escapeHtml(user.mail || user.userPrincipalName)}</div>
            </div>`
        ).join('');

    } catch (error) {
        container.innerHTML = `
            <div class="error">
                <strong>Search failed:</strong> ${escapeHtml(error.message)}
            </div>
        `;
    }
}

// Helper to select user from element data attributes (safer than inline onclick params)
function selectUserFromElement(element) {
    const userObjectId = element.dataset.userid;
    const userPrincipalName = element.dataset.upn;
    const displayName = element.dataset.displayname;
    const mail = element.dataset.mail;
    selectUser(userObjectId, userPrincipalName, displayName, mail);
}

// When a user clicks on someone from the search results
function selectUser(userObjectId, userPrincipalName, displayName, mail) {
    selectedUser = { userObjectId, userPrincipalName, displayName, mail };
    
    document.querySelectorAll('.user-item').forEach(item => item.classList.remove('selected'));
    event.target.closest('.user-item').classList.add('selected');
    
    updateExecuteButton();
}

// Keeping the execute button state in sync with user selections
function updateExecuteButton() {
    const btn = document.getElementById('executeBtn');
    const selectedInfo = document.getElementById('selectedInfo');
    const noSelectionInfo = document.getElementById('noSelectionInfo');
    const userNameSpan = document.getElementById('selectedUserName');
    const extensionNameSpan = document.getElementById('selectedExtensionName');
    
    const canExecute = selectedUser && selectedExtension;
    const isExecutable = selectedExtension && selectedExtension.executable !== false;
    
    btn.disabled = !canExecute;
    
    if (canExecute) {
        selectedInfo.style.display = 'block';
        noSelectionInfo.style.display = 'none';
        userNameSpan.textContent = `${selectedUser.displayName} (${selectedUser.userPrincipalName})`;
        extensionNameSpan.textContent = selectedExtension.name;
        
        // Update button text and style based on executability
        if (isExecutable) {
            btn.textContent = 'Execute Extension';
            btn.className = 'btn btn-success';
            btn.disabled = false;
        } else {
            btn.textContent = 'Extension Not Executable';
            btn.className = 'btn btn-warning';
            btn.disabled = true;
        }
    } else {
        selectedInfo.style.display = 'none';
        noSelectionInfo.style.display = 'block';
        btn.textContent = 'Execute Extension';
        btn.className = 'btn btn-success';
    }
}

// Running the selected Custom Extension against the selected user
async function executeExtension() {
    if (!selectedUser || !selectedExtension) {
        showError('Please select both a user and an extension');
        return;
    }
    
    // Check if extension is executable
    if (!selectedExtension.executable) {
        showError(`
            <div class="error">
                <h3>Extension Not Executable</h3>
                <p><strong>Extension:</strong> ${escapeHtml(selectedExtension.name)}</p>
                <p><strong>Issue:</strong> No corresponding Logic App found for execution</p>
                <p><strong>Match Source:</strong> ${escapeHtml(selectedExtension.matchSource || 'unknown')}</p>
                <div style="margin-top: 15px; padding: 10px; background: #fff3cd; border-radius: 4px; border: 1px solid #ffeaa7;">
                    <strong>Solution:</strong> Ensure the Logic App exists in the configured resource group with proper tags:
                    <ul style="margin: 10px 0; padding-left: 20px;">
                        <li><code>Purpose: Azure AD Lifecycle Workflows</code> (for lifecycle extensions)</li>
                        <li><code>Purpose: Azure AD Entitlement Management</code> (for entitlement extensions)</li>
                        <li><code>DisplayName: [Extension Name]</code> (optional, for better matching)</li>
                    </ul>
                </div>
            </div>
        `);
        return;
    }
    
    // Log user activity before execution
    await logUserActivity('execute_extension', {
        extensionName: selectedExtension.name,
        extensionId: selectedExtension.id,
        targetUser: selectedUser.userPrincipalName,
        targetUserId: selectedUser.userObjectId
    });
    
    const btn = document.getElementById('executeBtn');
    const originalText = btn.textContent;
    
    btn.disabled = true;
    btn.innerHTML = '<div class="spinner" style="width: 20px; height: 20px; margin: 0 auto;"></div>';
    
    const resultsContainer = document.getElementById('executionResults');
    resultsContainer.innerHTML = '<div class="loading"><div class="spinner"></div>Executing custom extension...</div>';

    try {
        const response = await fetch('/api/extensions/execute', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
            },
            body: JSON.stringify({
                extension: selectedExtension,
                user: {
                    id: selectedUser.userObjectId,
                    userPrincipalName: selectedUser.userPrincipalName,
                    displayName: selectedUser.displayName,
                    mail: selectedUser.mail
                },
                extensionName: selectedExtension.name
            })
        });

        const result = await response.json();

        if (!response.ok) {
            throw new Error(result.error || 'Execution failed');
        }

        // Show successful execution result
        showResult(`
            <div class="result">
                <h3>Extension Executed Successfully</h3>
                <p><strong>User:</strong> ${escapeHtml(selectedUser.displayName)}</p>
                <p><strong>User ID:</strong> ${escapeHtml(selectedUser.userObjectId)}</p>
                <p><strong>Extension:</strong> ${escapeHtml(selectedExtension.name)}</p>
                <p><strong>Description:</strong> ${escapeHtml(selectedExtension.description)}</p>
                <p><strong>Catalog:</strong> ${escapeHtml(selectedExtension.catalog)}</p>
                <p><strong>Type:</strong> ${selectedExtension.catalogType === 'lifecycle' ? 'Lifecycle Workflow' : 'Entitlement Management'}</p>
                <p><strong>Execution Time:</strong> ${new Date().toLocaleString()}</p>
                ${selectedExtension.workflowName ? `<p><strong>Logic App:</strong> ${escapeHtml(selectedExtension.workflowName)}</p>` : ''}
                ${result.result ? `
                    <details style="margin-top: 15px;">
                        <summary style="cursor: pointer; font-weight: bold; color: #28a745;">View Execution Response</summary>
                        <pre style="background: #f8f9fa; padding: 15px; border-radius: 4px; overflow: auto; margin-top: 10px; border: 1px solid #dee2e6; font-size: 12px;">${JSON.stringify(result.result, null, 2)}</pre>
                    </details>
                ` : ''}
            </div>
        `);
    } catch (error) {
        showError(`
            <div class="error">
                <h3>Extension Execution Failed</h3>
                <p><strong>User:</strong> ${escapeHtml(selectedUser.displayName)}</p>
                <p><strong>Extension:</strong> ${escapeHtml(selectedExtension.name)}</p>
                <p><strong>Error:</strong> ${escapeHtml(error.message)}</p>
                <p><strong>Time:</strong> ${new Date().toLocaleString()}</p>
                ${selectedExtension.workflowName ? `<p><strong>Logic App:</strong> ${escapeHtml(selectedExtension.workflowName)}</p>` : ''}
            </div>
        `);
    } finally {
        btn.disabled = false;
        btn.textContent = originalText;
        updateExecuteButton();
    }
}

// Simple functions for showing results and errors to the user
function showResult(message) {
    document.getElementById('executionResults').innerHTML = message;
}

function showError(message) {
    // If message contains HTML tags, render as-is; otherwise wrap in error div
    if (typeof message === 'string' && message.includes('<div')) {
        document.getElementById('executionResults').innerHTML = message;
    } else {
        document.getElementById('executionResults').innerHTML = `
            <div class="error">
                <strong>Error:</strong> ${escapeHtml(message)}
            </div>
        `;
    }
}

// Basic HTML escaping to prevent XSS issues
function escapeHtml(text) {
    if (typeof text !== 'string') return '';
    const div = document.createElement('div');
    div.textContent = text;
    return div.innerHTML;
}

// Set up Enter key handler for user search
function setupSearchKeyHandler() {
    const userSearchInput = document.getElementById('userSearch');
    if (userSearchInput) {
        userSearchInput.addEventListener('keypress', function(e) {
            if (e.key === 'Enter') {
                searchUsers();
            }
        });
    }
}
