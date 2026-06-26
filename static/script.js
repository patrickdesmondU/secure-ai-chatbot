/**
 * =============================================================================
 * SECURE AI CHATBOT - FRONTEND JAVASCRIPT
 * =============================================================================
 * A security-hardened frontend with the following protections:
 *
 *   XSS PREVENTION:
 *     - All user-generated content is inserted using textContent, NEVER innerHTML.
 *     - This prevents script injection via malicious message content.
 *     - The DOMPurify library is not needed because we never parse HTML.
 *
 *   CSRF PROTECTION:
 *     - All requests include credentials (cookies) with SameSite=Lax policy.
 *     - The session cookie is HttpOnly, preventing JavaScript theft.
 *
 *   INPUT VALIDATION:
 *     - Client-side length checks before sending to server.
 *     - Character counter prevents exceeding the 2000-char limit.
 *
 *   ERROR HANDLING:
 *     - Graceful handling of rate limits (429), auth errors (401), and
 *       network failures with user-friendly toast notifications.
 *
 *   STATE MANAGEMENT:
 *     - Simple module pattern keeps all state encapsulated.
 *     - No external dependencies minimizes the attack surface.
 * =============================================================================
 */

(function() {
    'use strict';

    // =========================================================================
    // STATE MANAGEMENT
    // =========================================================================
    const AppState = {
        isAuthenticated: false,
        username: null,
        userId: null,
        isLoading: false,
        currentView: 'auth', // 'auth' or 'chat'

        setAuthenticated(userData) {
            this.isAuthenticated = true;
            this.username = userData.username;
            this.userId = userData.user_id || null;
            this.currentView = 'chat';
        },

        setUnauthenticated() {
            this.isAuthenticated = false;
            this.username = null;
            this.userId = null;
            this.currentView = 'auth';
        }
    };

    // =========================================================================
    // DOM ELEMENT REFERENCES
    // =========================================================================
    const DOM = {
        // Views
        authView: document.getElementById('auth-view'),
        chatView: document.getElementById('chat-view'),

        // Auth forms
        loginForm: document.getElementById('login-form'),
        registerForm: document.getElementById('register-form'),
        showRegisterBtn: document.getElementById('show-register'),
        showLoginBtn: document.getElementById('show-login'),

        // Auth inputs
        loginUsername: document.getElementById('login-username'),
        loginPassword: document.getElementById('login-password'),
        registerUsername: document.getElementById('register-username'),
        registerPassword: document.getElementById('register-password'),
        registerPasswordConfirm: document.getElementById('register-password-confirm'),

        // Auth errors
        loginError: document.getElementById('login-error'),
        registerError: document.getElementById('register-error'),

        // Chat elements
        messagesContainer: document.getElementById('messages-container'),
        chatForm: document.getElementById('chat-form'),
        messageInput: document.getElementById('message-input'),
        sendBtn: document.getElementById('send-btn'),
        charCount: document.getElementById('char-count'),
        rateIndicator: document.getElementById('rate-indicator'),

        // Sidebar
        sidebarUsername: document.getElementById('sidebar-username'),
        userAvatar: document.getElementById('user-avatar'),
        newChatBtn: document.getElementById('new-chat-btn'),
        logoutBtn: document.getElementById('logout-btn'),

        // Toast
        toastContainer: document.getElementById('toast-container'),
    };

    // =========================================================================
    // UTILITY FUNCTIONS
    // =========================================================================

    /**
     * Escapes HTML special characters to prevent XSS injection.
     * This is a defense-in-depth utility. The primary XSS prevention strategy
     * is using textContent (never innerHTML) for all dynamic DOM insertion.
     * This function is available for rare cases where HTML escaping is needed
     * for non-DOM contexts (e.g., setting CSS content attributes).
     */
    function escapeHtml(text) {
        if (!text) return '';
        const div = document.createElement('div');
        div.textContent = text;
        // Read back the HTML-escaped representation (e.g., "<" becomes "&lt;")
        return div.innerHTML;
    }

    /**
     * Format a timestamp into a human-readable time string.
     */
    function formatTime(date) {
        return date.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    }

    /**
     * Show a toast notification that auto-dismisses after a delay.
     */
    function showToast(message, type = 'error', duration = 5000) {
        const toast = document.createElement('div');
        toast.className = `toast ${type}`;
        // SECURITY: Use textContent to prevent HTML injection in toast messages
        toast.textContent = message;
        DOM.toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateX(100%)';
            toast.style.transition = 'all 300ms ease';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }

    /**
     * Show an error message in an auth form.
     */
    function showAuthError(element, message) {
        element.textContent = message;
        element.classList.add('visible');
    }

    /**
     * Clear an auth form error message.
     */
    function clearAuthError(element) {
        element.textContent = '';
        element.classList.remove('visible');
    }

    // =========================================================================
    // API CLIENT
    // =========================================================================

    /**
     * Make an authenticated API request with error handling.
     * All requests include credentials (cookies) for session authentication.
     */
    async function apiRequest(endpoint, options = {}) {
        const url = `/api${endpoint}`;
        const config = {
            credentials: 'same-origin', // Include session cookies
            headers: {
                'Content-Type': 'application/json',
                ...options.headers
            },
            ...options
        };

        if (config.body && typeof config.body === 'object') {
            config.body = JSON.stringify(config.body);
        }

        try {
            const response = await fetch(url, config);
            const data = await response.json().catch(() => ({}));

            // Handle authentication errors
            if (response.status === 401) {
                AppState.setUnauthenticated();
                switchView('auth');
                showToast('Session expired. Please log in again.', 'warning');
                return { success: false, status: 401, data };
            }

            // Handle rate limiting
            if (response.status === 429) {
                const retryAfter = data.retry_after || 60;
                showToast(
                    `Rate limit exceeded. Please wait ${retryAfter} seconds.`,
                    'warning',
                    8000
                );
                return { success: false, status: 429, data };
            }

            if (!response.ok) {
                const errorMsg = data.error || `Request failed (${response.status})`;
                return { success: false, status: response.status, data, error: errorMsg };
            }

            return { success: true, status: response.status, data };

        } catch (networkError) {
            showToast('Network error. Please check your connection.', 'error', 8000);
            return { success: false, status: 0, error: 'Network error' };
        }
    }

    // =========================================================================
    // VIEW MANAGEMENT
    // =========================================================================

    function switchView(viewName) {
        if (viewName === 'chat') {
            DOM.authView.classList.add('hidden');
            DOM.chatView.classList.remove('hidden');
            updateUserInfo();
            DOM.messageInput.focus();
        } else {
            DOM.chatView.classList.add('hidden');
            DOM.authView.classList.remove('hidden');
            // Clear auth forms
            DOM.loginForm.reset();
            DOM.registerForm.reset();
            clearAuthError(DOM.loginError);
            clearAuthError(DOM.registerError);
        }
    }

    function updateUserInfo() {
        if (AppState.username) {
            DOM.sidebarUsername.textContent = AppState.username;
            DOM.userAvatar.textContent = AppState.username.charAt(0).toUpperCase();
        }
    }

    // =========================================================================
    // AUTHENTICATION HANDLERS
    // =========================================================================

    async function handleLogin(event) {
        event.preventDefault();
        clearAuthError(DOM.loginError);

        const username = DOM.loginUsername.value.trim();
        const password = DOM.loginPassword.value;

        if (!username || !password) {
            showAuthError(DOM.loginError, 'Please enter both username and password.');
            return;
        }

        DOM.loginForm.querySelector('button[type="submit"]').disabled = true;

        const result = await apiRequest('/auth/login', {
            method: 'POST',
            body: { username, password }
        });

        DOM.loginForm.querySelector('button[type="submit"]').disabled = false;

        if (result.success) {
            AppState.setAuthenticated({
                username: result.data.username,
                user_id: result.data.user_id
            });
            switchView('chat');
            await loadHistory();
            showToast(`Welcome back, ${result.data.username}!`, 'success', 3000);
        } else {
            showAuthError(DOM.loginError, result.error || 'Login failed.');
        }
    }

    async function handleRegister(event) {
        event.preventDefault();
        clearAuthError(DOM.registerError);

        const username = DOM.registerUsername.value.trim();
        const password = DOM.registerPassword.value;
        const passwordConfirm = DOM.registerPasswordConfirm.value;

        // Client-side validation
        if (!username || !password || !passwordConfirm) {
            showAuthError(DOM.registerError, 'All fields are required.');
            return;
        }

        if (username.length < 3) {
            showAuthError(DOM.registerError, 'Username must be at least 3 characters.');
            return;
        }

        if (password.length < 8) {
            showAuthError(DOM.registerError, 'Password must be at least 8 characters.');
            return;
        }

        if (password !== passwordConfirm) {
            showAuthError(DOM.registerError, 'Passwords do not match.');
            return;
        }

        DOM.registerForm.querySelector('button[type="submit"]').disabled = true;

        const result = await apiRequest('/auth/register', {
            method: 'POST',
            body: { username, password }
        });

        DOM.registerForm.querySelector('button[type="submit"]').disabled = false;

        if (result.success) {
            AppState.setAuthenticated({
                username: result.data.username,
                user_id: result.data.user_id
            });
            switchView('chat');
            showWelcomeMessage();
            showToast('Account created successfully!', 'success', 3000);
        } else {
            showAuthError(DOM.registerError, result.error || 'Registration failed.');
        }
    }

    async function handleLogout() {
        const result = await apiRequest('/auth/logout', { method: 'POST' });
        AppState.setUnauthenticated();
        switchView('auth');
        clearChat();
        showToast('Logged out successfully.', 'success', 3000);
    }

    // =========================================================================
    // CHAT MESSAGE RENDERING (XSS-SAFE)
    // =========================================================================

    /**
     * Create and append a message element to the chat.
     * SECURITY CRITICAL: This function uses textContent for all dynamic content.
     * NEVER use innerHTML here - that would create an XSS vulnerability where
     * an AI response or user message could inject malicious scripts.
     */
    function appendMessage(role, content, timestamp = null) {
        const messageDiv = document.createElement('div');
        messageDiv.className = `message ${role}`;

        // Avatar
        const avatar = document.createElement('div');
        avatar.className = 'message-avatar';
        avatar.textContent = role === 'user' ? 'U' : role === 'assistant' ? 'AI' : 'i';

        // Content container
        const contentDiv = document.createElement('div');

        // Message text - SECURITY: Use textContent, NEVER innerHTML
        const textDiv = document.createElement('div');
        textDiv.className = 'message-content';
        textDiv.textContent = content; // XSS-safe: treats all content as plain text

        contentDiv.appendChild(textDiv);

        // Timestamp (optional)
        if (timestamp) {
            const timeDiv = document.createElement('div');
            timeDiv.className = 'message-time';
            timeDiv.textContent = formatTime(new Date(timestamp));
            contentDiv.appendChild(timeDiv);
        }

        messageDiv.appendChild(avatar);
        messageDiv.appendChild(contentDiv);
        DOM.messagesContainer.appendChild(messageDiv);

        // Auto-scroll to bottom
        DOM.messagesContainer.scrollTop = DOM.messagesContainer.scrollHeight;

        return messageDiv;
    }

    /**
     * Show a typing indicator while waiting for the AI response.
     * Uses DOM construction instead of innerHTML for XSS safety.
     */
    function showTypingIndicator() {
        const indicatorDiv = document.createElement('div');
        indicatorDiv.className = 'message assistant typing-message';
        indicatorDiv.id = 'typing-indicator';

        const avatar = document.createElement('div');
        avatar.className = 'message-avatar';
        avatar.textContent = 'AI';

        const contentDiv = document.createElement('div');
        contentDiv.className = 'message-content';

        const typingWrapper = document.createElement('div');
        typingWrapper.className = 'typing-indicator';

        // Create three animated dots using DOM (no innerHTML)
        for (let i = 0; i < 3; i++) {
            const dot = document.createElement('span');
            typingWrapper.appendChild(dot);
        }

        contentDiv.appendChild(typingWrapper);
        indicatorDiv.appendChild(avatar);
        indicatorDiv.appendChild(contentDiv);
        DOM.messagesContainer.appendChild(indicatorDiv);
        DOM.messagesContainer.scrollTop = DOM.messagesContainer.scrollHeight;
    }

    /**
     * Remove the typing indicator.
     */
    function hideTypingIndicator() {
        const indicator = document.getElementById('typing-indicator');
        if (indicator) {
            indicator.remove();
        }
    }

    /**
     * Show the initial welcome message for a new conversation.
     * Clears container using DOM removal for XSS-safe consistency.
     */
    function showWelcomeMessage() {
        clearChat(); // Reuse the DOM-safe clear function
        appendMessage(
            'system',
            'Welcome to Secure AI Chatbot. Your conversations are private and isolated. How can I help you today?'
        );
    }

    /**
     * Clear all messages from the chat.
     * Uses DOM removal instead of innerHTML for consistency with XSS-safe practices.
     */
    function clearChat() {
        while (DOM.messagesContainer.firstChild) {
            DOM.messagesContainer.removeChild(DOM.messagesContainer.firstChild);
        }
    }

    // =========================================================================
    // CHAT API HANDLERS
    // =========================================================================

    async function handleSendMessage(event) {
        event.preventDefault();

        if (AppState.isLoading) return;

        const message = DOM.messageInput.value.trim();
        if (!message) return;

        // Check length
        if (message.length > 2000) {
            showToast('Message exceeds 2000 character limit.', 'warning');
            return;
        }

        // Clear input and disable form
        DOM.messageInput.value = '';
        DOM.charCount.textContent = '0';
        DOM.sendBtn.disabled = true;
        AppState.isLoading = true;

        // Add user message to chat
        appendMessage('user', message);

        // Show typing indicator
        showTypingIndicator();

        // Send to API
        const result = await apiRequest('/chat', {
            method: 'POST',
            body: { message }
        });

        // Hide typing indicator
        hideTypingIndicator();

        DOM.sendBtn.disabled = false;
        AppState.isLoading = false;
        DOM.messageInput.focus();

        if (result.success) {
            appendMessage('assistant', result.data.response);
        } else {
            // Show error in chat
            const errorMsg = result.error || 'Failed to get response. Please try again.';
            appendMessage('system', `Error: ${errorMsg}`);

            if (result.status === 429) {
                DOM.rateIndicator.textContent = '(Rate limited)';
                setTimeout(() => {
                    DOM.rateIndicator.textContent = '';
                }, 60000);
            }
        }
    }

    async function loadHistory() {
        const result = await apiRequest('/history', { method: 'GET' });

        if (result.success && result.data.history) {
            clearChat();

            if (result.data.history.length === 0) {
                showWelcomeMessage();
                return;
            }

            result.data.history.forEach(msg => {
                if (msg.role !== 'system') { // Don't show system messages from DB
                    appendMessage(msg.role, msg.content, msg.created_at);
                }
            });
        } else {
            showWelcomeMessage();
        }
    }

    async function handleNewChat() {
        const result = await apiRequest('/history', { method: 'DELETE' });

        if (result.success) {
            clearChat();
            showWelcomeMessage();
            showToast('New conversation started.', 'success', 3000);
        } else {
            showToast(result.error || 'Failed to start new chat.', 'error');
        }
    }

    // =========================================================================
    // INPUT HANDLING
    // =========================================================================

    function handleInput() {
        const length = DOM.messageInput.value.length;
        DOM.charCount.textContent = length;

        // Auto-resize textarea
        DOM.messageInput.style.height = 'auto';
        DOM.messageInput.style.height = Math.min(DOM.messageInput.scrollHeight, 120) + 'px';
    }

    function handleKeyDown(event) {
        // Send on Enter (without Shift)
        if (event.key === 'Enter' && !event.shiftKey) {
            event.preventDefault();
            DOM.chatForm.dispatchEvent(new Event('submit'));
        }
    }

    // =========================================================================
    // AUTH FORM TOGGLE
    // =========================================================================

    function showRegisterForm() {
        DOM.loginForm.classList.add('hidden');
        DOM.registerForm.classList.remove('hidden');
        clearAuthError(DOM.loginError);
        DOM.registerUsername.focus();
    }

    function showLoginForm() {
        DOM.registerForm.classList.add('hidden');
        DOM.loginForm.classList.remove('hidden');
        clearAuthError(DOM.registerError);
        DOM.loginUsername.focus();
    }

    // =========================================================================
    // INITIALIZATION
    // =========================================================================

    /**
     * Check if the user already has a valid session on page load.
     */
    async function checkSession() {
        const result = await apiRequest('/auth/me', { method: 'GET' });

        if (result.success) {
            AppState.setAuthenticated({
                username: result.data.username,
                user_id: result.data.user_id
            });
            switchView('chat');
            await loadHistory();
        } else {
            AppState.setUnauthenticated();
            switchView('auth');
        }
    }

    /**
     * Attach all event listeners.
     */
    function initEventListeners() {
        // Auth forms
        DOM.loginForm.addEventListener('submit', handleLogin);
        DOM.registerForm.addEventListener('submit', handleRegister);
        DOM.showRegisterBtn.addEventListener('click', showRegisterForm);
        DOM.showLoginBtn.addEventListener('click', showLoginForm);

        // Chat
        DOM.chatForm.addEventListener('submit', handleSendMessage);
        DOM.messageInput.addEventListener('input', handleInput);
        DOM.messageInput.addEventListener('keydown', handleKeyDown);

        // Sidebar
        DOM.newChatBtn.addEventListener('click', handleNewChat);
        DOM.logoutBtn.addEventListener('click', handleLogout);
    }

    /**
     * Initialize the application.
     */
    function init() {
        initEventListeners();
        checkSession();
    }

    // Start the app when DOM is ready
    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', init);
    } else {
        init();
    }

})();
