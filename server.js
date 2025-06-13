const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const yaml = require('js-yaml');
const path = require('path');
const PlexAuthenticator = require('./lib/plex-authenticator');
const AccessControl = require('./lib/access-control');
const Logger = require('./lib/logger');

class PlexAuthProxy {
  constructor() {
    this.app = express();
    this.app.set('trust proxy', true);  // Fix for X-Forwarded-For header warning
    this.config = this.loadConfig();
    this.logger = new Logger(this.config.logging);
    this.plexAuth = new PlexAuthenticator(this.config, this.logger);
    this.accessControl = new AccessControl(this.config, this.logger);
    
    // Store for pending OAuth sessions
    this.pendingAuth = new Map(); // pinId -> { redirect, timestamp, pollingInterval }
    
    this.setupMiddleware();
    this.setupRoutes();
  }

  loadConfig() {
    try {
      const configPath = process.env.CONFIG_PATH || '/app/config/config.yaml';
      const fileContents = fs.readFileSync(configPath, 'utf8');
      return yaml.load(fileContents);
    } catch (error) {
      console.error('Failed to load config:', error);
      process.exit(1);
    }
  }

  setupMiddleware() {
    // Set trust proxy first
    this.app.set('trust proxy', ['192.168.10.0/24', '172.16.0.0/12', '10.0.0.0/8']);
    
    // Security middleware
    this.app.use(helmet({
      crossOriginEmbedderPolicy: false,
      contentSecurityPolicy: false
    }));

    // Rate limiting with specific proxy configuration
    const limiter = rateLimit({
      windowMs: this.config.security.rate_limit.window_ms,
      max: this.config.security.rate_limit.max_requests,
      message: 'Too many requests from this IP, please try again later.',
      trustProxy: ['192.168.10.0/24', '172.16.0.0/12', '10.0.0.0/8']
    });
    this.app.use(limiter);

    // CORS
    this.app.use(cors({
      origin: true,
      credentials: true
    }));

    // Body parsing
    this.app.use(express.json());
    this.app.use(express.urlencoded({ extended: true }));
    this.app.use(cookieParser());

    // Session management
    this.app.use(session({
      secret: this.config.app.session_secret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: this.config.security.require_https,
        maxAge: this.config.security.session_timeout * 1000,
        domain: this.config.app.cookie_domain
      }
    }));

    // Request logging
    this.app.use((req, res, next) => {
      this.logger.info(`${req.method} ${req.url} - ${req.ip}`);
      next();
    });
  }

  setupRoutes() {
    // Health check
    this.app.get('/health', (req, res) => {
      res.json({ status: 'healthy', timestamp: new Date().toISOString() });
    });

    // Main authentication endpoint
    this.app.get('/auth', async (req, res) => {
      try {
        await this.handleAuth(req, res);
      } catch (error) {
        this.logger.error('Authentication error:', error);
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    // Login page - creates PIN and shows Plex login with polling
    this.app.get('/login', async (req, res) => {
      try {
        const originalUrl = req.query.redirect || req.headers.referer || '/';
        
        // Create OAuth URL first
        const redirectUrl = `${req.protocol}://${req.get('host')}/auth/waiting`;
        const { authUrl, pinId } = await this.plexAuth.createAuthUrl(redirectUrl);
        
        // Store the pending auth session
        this.pendingAuth.set(pinId, {
          redirect: originalUrl,
          timestamp: Date.now()
        });
        
        // Clean up old pending auths
        this.cleanupPendingAuth();
        
        res.send(this.generateOAuthLoginPage(authUrl, pinId, originalUrl));
      } catch (error) {
        this.logger.error('Failed to create login page:', error);
        res.status(500).send('Authentication service temporarily unavailable');
      }
    });

    // Waiting page that polls for authentication completion
this.app.get('/auth/waiting', async (req, res) => {
  try {
    // The user just came back from Plex, but we need to find their PIN
    // Let's check all pending authentications to see if any completed
    for (const [pinId, pending] of this.pendingAuth.entries()) {
      const authResult = await this.plexAuth.checkAuthToken(pinId);
      
      if (authResult.success) {
        // Authentication successful!
        req.session.user = authResult.user;
        req.session.plexServers = authResult.servers;
        
        this.logger.info(`User ${authResult.user.email} authenticated successfully`);
        
        // Clean up and redirect
        this.pendingAuth.delete(pinId);
        return res.redirect(pending.redirect);
      }
    }
    
    // No successful auth found, show waiting page
    res.send(this.generateWaitingPage());
  } catch (error) {
    this.logger.error('Waiting page error:', error);
    res.send(this.generateWaitingPage());
  }
});
    // API endpoint to check auth status (polled by waiting page)
    this.app.get('/auth/check/:pinId', async (req, res) => {
      try {
        const pinId = req.params.pinId;
        
        const pending = this.pendingAuth.get(pinId);
        if (!pending) {
          return res.json({ status: 'expired', message: 'Authentication session expired' });
        }

        // Check for auth token
        const authResult = await this.plexAuth.checkAuthToken(pinId);
        
        if (authResult.success) {
          // Store user session
          req.session.user = authResult.user;
          req.session.plexServers = authResult.servers;
          
          this.logger.info(`User ${authResult.user.email} authenticated successfully via OAuth`);
          
          // Clean up pending auth
          this.pendingAuth.delete(pinId);
          
          // Return success with redirect URL
          res.json({ 
            status: 'success', 
            redirect: pending.redirect,
            user: authResult.user.email
          });
        } else {
          // Still waiting
          res.json({ status: 'waiting', message: 'Waiting for Plex authentication...' });
        }
      } catch (error) {
        this.logger.error('Auth check error:', error);
        res.json({ status: 'error', message: 'Authentication failed' });
      }
    });

    // Legacy login handler (for direct username/password - optional)
    this.app.post('/login', async (req, res) => {
      try {
        const { username, password, redirect } = req.body;
        const authResult = await this.plexAuth.authenticate(username, password);
        
        if (authResult.success) {
          req.session.user = authResult.user;
          req.session.plexServers = authResult.servers;
          
          this.logger.info(`User ${username} authenticated successfully`);
          
          if (redirect) {
            res.redirect(redirect);
          } else {
            res.json({ success: true, user: authResult.user });
          }
        } else {
          this.logger.warn(`Failed authentication attempt for ${username}`);
          res.status(401).json({ error: 'Invalid credentials' });
        }
      } catch (error) {
        this.logger.error('Login error:', error);
        res.status(500).json({ error: 'Authentication failed' });
      }
    });

    // Logout
    this.app.post('/logout', (req, res) => {
      req.session.destroy();
      res.json({ success: true });
    });

    // User info endpoint
    this.app.get('/user', (req, res) => {
      if (req.session.user) {
        res.json({
          user: req.session.user,
          servers: req.session.plexServers
        });
      } else {
        res.status(401).json({ error: 'Not authenticated' });
      }
    });
  }

  async handleAuth(req, res) {
    const originalUrl = req.headers['x-original-url'] || req.query.url;
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    
    this.logger.debug(`Auth request for host: ${host}, original URL: ${originalUrl}`);

    // Check if user is authenticated
    if (!req.session.user) {
      this.logger.debug('User not authenticated, returning 401');
      return res.status(401).json({ error: 'Not authenticated' });
    }

    // Check access control
    const accessResult = await this.accessControl.checkAccess(
      host,
      req.session.user,
      req.session.plexServers
    );

    if (!accessResult.allowed) {
      this.logger.warn(`Access denied for user ${req.session.user.email} to ${host}: ${accessResult.reason}`);
      return res.status(403).json({ 
        error: 'Access denied',
        reason: accessResult.reason 
      });
    }

    // Handle conditional redirects
    if (accessResult.redirect) {
      this.logger.info(`Redirecting user ${req.session.user.email} to ${accessResult.redirect}`);
      return res.redirect(accessResult.redirect);
    }

    // Set auth headers for upstream services
    res.set({
      'X-Auth-User': req.session.user.email,
      'X-Auth-Name': req.session.user.title,
      'X-Auth-Servers': JSON.stringify(req.session.plexServers),
      'X-Auth-Admin': req.session.user.admin ? 'true' : 'false'
    });

    this.logger.info(`Access granted for user ${req.session.user.email} to ${host}`);
    res.status(200).json({ 
      success: true,
      user: req.session.user.email,
      access_granted: true
    });
  }

  generateOAuthLoginPage(authUrl, pinId, redirectUrl) {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Plex Authentication</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
        }
        .login-container {
            background: white;
            padding: 3rem;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 450px;
            text-align: center;
        }
        .logo h2 {
            color: #333;
            margin: 0 0 2rem 0;
            font-size: 1.8rem;
        }
        .plex-btn {
            background: #e5a00d;
            color: white;
            padding: 1rem 2rem;
            border: none;
            border-radius: 8px;
            font-size: 1.1rem;
            font-weight: 600;
            cursor: pointer;
            transition: background 0.3s, transform 0.2s;
            text-decoration: none;
            display: inline-block;
            margin: 1rem 0;
            min-width: 250px;
        }
        .plex-btn:hover {
            background: #cc9900;
            transform: translateY(-2px);
        }
        .info-text {
            color: #666;
            margin: 1.5rem 0;
            line-height: 1.5;
        }
        .steps {
            text-align: left;
            margin: 2rem 0;
            padding: 1.5rem;
            background: #f8f9fa;
            border-radius: 8px;
        }
        .steps h4 {
            margin: 0 0 1rem 0;
            color: #333;
        }
        .steps ol {
            margin: 0;
            padding-left: 1.2rem;
        }
        .steps li {
            margin-bottom: 0.5rem;
            color: #555;
        }
        .status {
            margin-top: 2rem;
            padding: 1rem;
            border-radius: 8px;
            background: #e3f2fd;
            color: #1976d2;
            display: none;
        }
        .spinner {
            border: 3px solid #f3f3f3;
            border-top: 3px solid #e5a00d;
            border-radius: 50%;
            width: 20px;
            height: 20px;
            animation: spin 1s linear infinite;
            display: inline-block;
            margin-right: 10px;
        }
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h2>?? Plex Authentication</h2>
        </div>
        
        <div class="info-text">
            Sign in with your Plex account to access this service
        </div>
        
        <a href="${authUrl}" class="plex-btn" onclick="startPolling()" target="_blank">
            Sign in with Plex
        </a>
        
        <div class="status" id="status">
            <div class="spinner"></div>
            <span id="statusText">Waiting for Plex authentication...</span>
        </div>
        
        <div class="steps">
            <h4>How it works:</h4>
            <ol>
                <li>Click "Sign in with Plex" above</li>
                <li>Sign in to your Plex account on plex.tv</li>
                <li>Return to this tab - authentication will complete automatically</li>
                <li>You'll be redirected to your requested page</li>
            </ol>
        </div>
    </div>

    <script>
        const pinId = '${pinId}';  // Pass pinId to JavaScript
        let polling = false;
        let pollInterval;
        
        function startPolling() {
            if (polling) return;
            polling = true;
            
            document.getElementById('status').style.display = 'block';
            
            // Start polling after a short delay to let user get to Plex
            setTimeout(() => {
                pollInterval = setInterval(checkAuthStatus, 3000);
            }, 5000);
        }
        
        function checkAuthStatus() {
            fetch('/auth/check/' + pinId)
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        clearInterval(pollInterval);
                        document.getElementById('statusText').textContent = 'Authentication successful! Redirecting...';
                        setTimeout(() => {
                            window.location.href = data.redirect;
                        }, 1000);
                    } else if (data.status === 'expired' || data.status === 'error') {
                        clearInterval(pollInterval);
                        document.getElementById('statusText').textContent = data.message || 'Authentication failed';
                        setTimeout(() => {
                            window.location.reload();
                        }, 3000);
                    }
                    // Otherwise keep polling (status === 'waiting')
                })
                .catch(error => {
                    console.error('Auth check failed:', error);
                });
        }
        
        // Auto-start polling if user returns to this page
        window.addEventListener('focus', () => {
            if (!polling) {
                startPolling();
            }
        });
    </script>
</body>
</html>
    `;
  }

  generateWaitingPage() {
    return `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Authentication Complete</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            margin: 0;
        }
        .container {
            background: white;
            padding: 3rem;
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0,0,0,0.2);
            text-align: center;
            max-width: 400px;
        }
        .success {
            color: #4caf50;
            font-size: 3rem;
            margin-bottom: 1rem;
        }
        h2 {
            color: #333;
            margin-bottom: 1rem;
        }
        p {
            color: #666;
            line-height: 1.5;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="success">?</div>
        <h2>Authentication Successful!</h2>
        <p>You can close this window and return to the previous tab.</p>
    </div>
    
    <script>
        // Auto-close this window after a few seconds
        setTimeout(() => {
            window.close();
        }, 3000);
    </script>
</body>
</html>
    `;
  }

  cleanupPendingAuth() {
    const now = Date.now();
    const fifteenMinutes = 15 * 60 * 1000;
    
    for (const [pinId, data] of this.pendingAuth.entries()) {
      if (now - data.timestamp > fifteenMinutes) {
        this.pendingAuth.delete(pinId);
      }
    }
  }

  start() {
    const port = this.config.app.port || 3000;
    this.app.listen(port, () => {
      this.logger.info(`Plex Auth Proxy started on port ${port}`);
    });
  }
}

// Start the server
const proxy = new PlexAuthProxy();
proxy.start();
