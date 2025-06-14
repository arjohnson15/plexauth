const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const axios = require('axios');
const fs = require('fs');
const yaml = require('js-yaml');
const path = require('path');
const { XMLParser } = require('fast-xml-parser');

// Add Plex OAuth functionality
class PlexOAuth {
  constructor(clientInfo, logger) {
    this.clientInfo = clientInfo;
    this.logger = logger;
  }

  async requestHostedLoginURL() {
    try {
      // Step 1: Get PIN
      const pinResponse = await axios.post('https://plex.tv/api/v2/pins', {
        strong: true
      }, {
        headers: {
          'X-Plex-Product': this.clientInfo.product,
          'X-Plex-Version': this.clientInfo.version,
          'X-Plex-Client-Identifier': this.clientInfo.clientIdentifier,
          'Accept': 'application/json'
        }
      });

      const pinData = pinResponse.data;
      const pinId = pinData.id;
      const code = pinData.code;

      // Step 2: Generate auth URL
      const authUrl = `https://app.plex.tv/auth#?clientID=${this.clientInfo.clientIdentifier}&code=${code}&context%5Bdevice%5D%5Bproduct%5D=${this.clientInfo.product}`;

      this.logger.info(`Created Plex OAuth URL with PIN ID: ${pinId}`);
      
      return [authUrl, pinId];
    } catch (error) {
      this.logger.error('Failed to create Plex OAuth URL:', error);
      throw new Error('Failed to initiate Plex authentication');
    }
  }

  async checkForAuthToken(pinId) {
    try {
      const response = await axios.get(`https://plex.tv/api/v2/pins/${pinId}`, {
        headers: {
          'X-Plex-Client-Identifier': this.clientInfo.clientIdentifier,
          'Accept': 'application/json'
        }
      });

      const pinData = response.data;
      return pinData.authToken || null;
    } catch (error) {
      this.logger.debug('PIN not yet authenticated:', error.message);
      return null;
    }
  }
}

class PlexClient {
  constructor(logger) {
    this.logger = logger;
    this.xmlParser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_'
    });
  }

  async getAccessTier(serverIdentifier, accessToken) {
    try {
      const servers = await this.getServers(accessToken);
      const serverDetails = this.getServerDetails(servers);
      
      const accessLevel = serverDetails
        .filter(x => x.serverId === serverIdentifier)
        .map(x => x.accessTier)[0];
      
      return accessLevel || 'NoAccess';
    } catch (error) {
      this.logger.error('Retrieving access tier failed:', error);
      return 'Failure';
    }
  }

  async getUserInfo(accessToken) {
    try {
      const xml = await this.performGetRequest(accessToken, '/users/account');
      const xmlDoc = this.xmlParser.parse(xml);
      const user = xmlDoc.user || xmlDoc;

      return {
        username: user['@_username'] || user.username || '',
        email: user['@_email'] || user.email || '',
        thumbnail: user['@_thumb'] || user.thumb || ''
      };
    } catch (error) {
      this.logger.error('Failed to get user info:', error);
      throw error;
    }
  }

  async getServers(accessToken) {
    try {
      const xml = await this.performGetRequest(accessToken, '/api/resources');
      const xmlDoc = this.xmlParser.parse(xml);
      
      const devices = xmlDoc.MediaContainer?.Device || [];
      const deviceArray = Array.isArray(devices) ? devices : [devices];
      
      return deviceArray.map(device => ({
        clientIdentifier: device['@_clientIdentifier'],
        owned: device['@_owned'] || '0',
        home: device['@_home'] || '0'
      }));
    } catch (error) {
      this.logger.error('Failed to get servers:', error);
      return [];
    }
  }

  async performGetRequest(accessToken, path) {
    try {
      const response = await axios.get(`https://plex.tv${path}`, {
        headers: {
          'includeHttps': '1',
          'includeRelay': '1',
          'X-Plex-Product': 'PlexSSO',
          'X-Plex-Version': 'Plex OAuth',
          'X-Plex-Client-Identifier': 'PlexSSOv2',
          'X-Plex-Token': accessToken,
          'Accept': 'application/json'
        },
        timeout: 10000
      });

      this.logger.debug(`Request: ${path}\nResponse status: ${response.status}`);
      return response.data;
    } catch (error) {
      this.logger.error(`Request failed for ${path}:`, error.message);
      throw error;
    }
  }

  getServerDetails(servers) {
    return servers.map(server => {
      let accessTier = 'NormalUser';
      if (server.owned === '1') {
        accessTier = 'Owner';
      } else if (server.home === '1') {
        accessTier = 'HomeUser';
      }

      return {
        serverId: server.clientIdentifier,
        accessTier: accessTier
      };
    });
  }
}

class AccessController {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
  }

  checkAccess(host, user, userAccessTier, authenticatedServerId, userServers) {
    const rules = this.config.access_rules[host];
    
    if (!rules) {
      this.logger.warn(`No access rules found for host: ${host}`);
      return { 
        allowed: false, 
        reason: 'No access rules configured for this host',
        redirect: null 
      };
    }

    this.logger.debug(`Checking access for ${user.email} to ${host} with rule type: ${rules.type}`);

    switch (rules.type) {
      case 'user_whitelist':
        return this.checkUserWhitelist(rules, user, userAccessTier, authenticatedServerId, userServers);
      
      case 'any_member':
        return this.checkAnyMember(rules, user, userAccessTier, authenticatedServerId, userServers);
      
      case 'admin_only':
        return this.checkAdminOnly(rules, user, userAccessTier, authenticatedServerId, userServers);
      
      case 'conditional_redirect':
        return this.checkConditionalRedirect(rules, user, userAccessTier, authenticatedServerId, userServers);
      
      default:
        this.logger.error(`Unknown access rule type: ${rules.type}`);
        return { 
          allowed: false, 
          reason: 'Invalid access rule configuration',
          redirect: null 
        };
    }
  }

  checkUserWhitelist(rules, user, userAccessTier, authenticatedServerId, userServers) {
    // Check if user is in the whitelist
    if (!rules.allowed_users.includes(user.email) && !rules.allowed_users.includes(user.username)) {
      return { 
        allowed: false, 
        reason: 'User not in whitelist',
        redirect: null 
      };
    }

    // Check if user has access to any of the required servers
    const hasServerAccess = rules.allowed_servers.some(serverId => 
      userServers.hasOwnProperty(serverId)
    );

    if (!hasServerAccess) {
      return { 
        allowed: false, 
        reason: 'User does not have access to required Plex servers',
        redirect: null 
      };
    }

    return { 
      allowed: true, 
      reason: 'User whitelist access granted',
      redirect: rules.redirect_to 
    };
  }

  checkAnyMember(rules, user, userAccessTier, authenticatedServerId, userServers) {
    // Check if user has access to any of the allowed servers
    const hasServerAccess = rules.allowed_servers.some(serverId => 
      userServers.hasOwnProperty(serverId)
    );

    if (!hasServerAccess) {
      return { 
        allowed: false, 
        reason: 'User does not have access to any required Plex servers',
        redirect: null 
      };
    }

    return { 
      allowed: true, 
      reason: 'Any member access granted',
      redirect: rules.redirect_to 
    };
  }

  checkAdminOnly(rules, user, userAccessTier, authenticatedServerId, userServers) {
    // Check if user is admin on any of the allowed servers
    const isAdmin = Object.keys(userServers).some(serverId => {
      if (rules.allowed_servers.includes(serverId)) {
        return userServers[serverId].is_owner || userAccessTier === 'Owner';
      }
      return false;
    });

    if (!isAdmin) {
      return { 
        allowed: false, 
        reason: 'Admin access required',
        redirect: null 
      };
    }

    return { 
      allowed: true, 
      reason: 'Admin access granted',
      redirect: rules.redirect_to 
    };
  }

  checkConditionalRedirect(rules, user, userAccessTier, authenticatedServerId, userServers) {
    // Check each condition in order
    for (const condition of rules.conditions) {
      if (userServers.hasOwnProperty(condition.server)) {
        this.logger.info(`User ${user.email} matched condition for server ${condition.server}`);
        return { 
          allowed: true, 
          reason: `Conditional redirect for server ${condition.server}`,
          redirect: condition.redirect_to 
        };
      }
    }

    // If no conditions matched, check for fallback
    if (rules.fallback_redirect) {
      return { 
        allowed: true, 
        reason: 'Fallback redirect applied',
        redirect: rules.fallback_redirect 
      };
    }

    return { 
      allowed: false, 
      reason: 'User does not match any conditional redirect criteria',
      redirect: null 
    };
  }
}

class PlexAuthProxy {
  constructor() {
    this.app = express();
    this.app.set('trust proxy', true);
    this.config = this.loadConfig();
    this.logger = this.createLogger();
    this.plexClient = new PlexClient(this.logger);
    this.accessController = new AccessController(this.config, this.logger);
    
    // OAuth client configuration
    this.clientInfo = {
      clientIdentifier: this.config.app.client_identifier || 'plex-auth-proxy-' + Date.now(),
      product: 'Plex Auth Proxy',
      device: 'Auth Proxy Server',
      version: '2.0.0',
      platform: 'Web'
    };
    
    this.plexOAuth = new PlexOAuth(this.clientInfo, this.logger);
    
    // Store for pending OAuth sessions
    this.pendingAuth = new Map(); // pinId -> { redirect, timestamp }
    
    this.setupMiddleware();
    this.setupRoutes();
  }

  createLogger() {
    const level = this.config.logging?.level || 'info';
    return {
      debug: (msg, ...args) => level === 'debug' && console.log(`[DEBUG] ${msg}`, ...args),
      info: (msg, ...args) => ['debug', 'info'].includes(level) && console.log(`[INFO] ${msg}`, ...args),
      warn: (msg, ...args) => ['debug', 'info', 'warn'].includes(level) && console.warn(`[WARN] ${msg}`, ...args),
      error: (msg, ...args) => console.error(`[ERROR] ${msg}`, ...args)
    };
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
    // Security middleware
    this.app.use(helmet({
      crossOriginEmbedderPolicy: false,
      contentSecurityPolicy: false
    }));

    // Rate limiting with proper proxy configuration
    const limiter = rateLimit({
      windowMs: this.config.security?.rate_limit?.window_ms || 900000,
      max: this.config.security?.rate_limit?.max_requests || 100,
      message: 'Too many requests from this IP, please try again later.',
      // Fix the trust proxy issue
      trustProxy: ['192.168.0.0/16', '10.0.0.0/8', '172.16.0.0/12'],
      standardHeaders: true,
      legacyHeaders: false
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

    // Session management with better store warning handling
    this.app.use(session({
      secret: this.config.app.session_secret,
      resave: false,
      saveUninitialized: false,
      cookie: {
        secure: this.config.security?.require_https || false,
        maxAge: (this.config.security?.session_timeout || 3600) * 1000,
        domain: this.config.app.cookie_domain
      },
      // Suppress the memory store warning for now
      name: 'plex.auth.sid'
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

    // Main authentication endpoint (mimics PlexSSO's /api/v2/sso)
    this.app.get('/auth', async (req, res) => {
      try {
        await this.handleAuth(req, res);
      } catch (error) {
        this.logger.error('Authentication error:', error);
        res.status(500).json({ error: 'Internal server error' });
      }
    });

    // Login endpoint that accepts Plex token (mimics PlexSSO's /api/v2/login)
    this.app.post('/login', async (req, res) => {
      try {
        const { token } = req.body;
        
        if (!token) {
          return res.status(400).json({ error: 'Token required' });
        }

        // Check authentication against multiple servers (like PlexSSO)
        let authenticatedServer = null;
        let userAccessTier = 'NoAccess';
        let userInfo = null;
        let userServers = {};

        // Try each configured server
        for (const [serverId, serverConfig] of Object.entries(this.config.plex_servers)) {
          try {
            const accessTier = await this.plexClient.getAccessTier(serverConfig.machine_id, token);
            
            if (accessTier !== 'NoAccess' && accessTier !== 'Failure') {
              // User has access to this server
              userServers[serverId] = {
                name: serverConfig.name,
                url: serverConfig.url,
                access_level: accessTier,
                is_owner: accessTier === 'Owner',
                machine_id: serverConfig.machine_id
              };

              // Set primary authentication details from first successful server
              if (!authenticatedServer) {
                authenticatedServer = serverId;
                userAccessTier = accessTier;
                userInfo = await this.plexClient.getUserInfo(token);
              }
            }
          } catch (error) {
            this.logger.debug(`Authentication failed for server ${serverId}:`, error.message);
          }
        }

        if (!authenticatedServer || !userInfo) {
          this.logger.warn('Failed authentication attempt');
          return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Store user session
        req.session.user = {
          email: userInfo.email,
          username: userInfo.username,
          thumbnail: userInfo.thumbnail,
          accessTier: userAccessTier,
          authenticatedServer: authenticatedServer,
          token: token
        };

        // Store server access info
        req.session.userServers = userServers;

        this.logger.info(`User ${userInfo.email} authenticated successfully. Access to servers: ${Object.keys(userServers).join(', ')}`);
        
        res.json({ 
          success: true, 
          user: userInfo,
          accessTier: userAccessTier,
          servers: Object.keys(userServers),
          primaryServer: authenticatedServer
        });

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
          servers: req.session.userServers || {}
        });
      } else {
        res.status(401).json({ error: 'Not authenticated' });
      }
    });

    // Login page with OAuth
    this.app.get('/login', async (req, res) => {
      try {
        const redirectUrl = req.query.redirect || req.headers.referer || '/';
        
        // Check if user already has a pending auth for this session
        const existingPinId = req.session.pendingPinId;
        let authUrl, pinId;
        
        if (existingPinId && this.pendingAuth.has(existingPinId)) {
          // Reuse existing PIN
          pinId = existingPinId;
          // We'll need to recreate the auth URL, but that's okay
          [authUrl, ] = await this.plexOAuth.requestHostedLoginURL();
          this.pendingAuth.set(pinId, {
            redirect: redirectUrl,
            timestamp: Date.now()
          });
        } else {
          // Create new OAuth URL
          [authUrl, pinId] = await this.plexOAuth.requestHostedLoginURL();
          
          // Store the pending auth session
          this.pendingAuth.set(pinId, {
            redirect: redirectUrl,
            timestamp: Date.now()
          });
          
          // Store PIN in session to prevent multiple PINs
          req.session.pendingPinId = pinId;
        }
        
        // Clean up old pending auths
        this.cleanupPendingAuth();
        
        res.send(this.generateOAuthLoginPage(authUrl, pinId, redirectUrl));
      } catch (error) {
        this.logger.error('Failed to create login page:', error);
        res.status(500).send('Authentication service temporarily unavailable');
      }
    });

    // OAuth callback/polling endpoint
    this.app.get('/auth/check/:pinId', async (req, res) => {
      try {
        const pinId = req.params.pinId;
        
        const pending = this.pendingAuth.get(pinId);
        if (!pending) {
          return res.json({ status: 'expired', message: 'Authentication session expired' });
        }

        // Check for auth token
        const authToken = await this.plexOAuth.checkForAuthToken(pinId);
        
        if (authToken) {
          // Process the authentication like the old login endpoint
          let authenticatedServer = null;
          let userAccessTier = 'NoAccess';
          let userInfo = null;
          let userServers = {};

          // Try each configured server
          for (const [serverId, serverConfig] of Object.entries(this.config.plex_servers)) {
            try {
              const accessTier = await this.plexClient.getAccessTier(serverConfig.machine_id, authToken);
              
              if (accessTier !== 'NoAccess' && accessTier !== 'Failure') {
                userServers[serverId] = {
                  name: serverConfig.name,
                  url: serverConfig.url,
                  access_level: accessTier,
                  is_owner: accessTier === 'Owner',
                  machine_id: serverConfig.machine_id
                };

                if (!authenticatedServer) {
                  authenticatedServer = serverId;
                  userAccessTier = accessTier;
                  userInfo = await this.plexClient.getUserInfo(authToken);
                }
              }
            } catch (error) {
              this.logger.debug(`Authentication failed for server ${serverId}:`, error.message);
            }
          }

          if (!authenticatedServer || !userInfo) {
            this.logger.warn('Failed OAuth authentication attempt');
            return res.json({ status: 'error', message: 'Authentication failed' });
          }

          // Store user session in a temporary store (we'll need to handle this differently)
          // For now, return success with user data
          this.pendingAuth.set(pinId + '_user', {
            user: {
              email: userInfo.email,
              username: userInfo.username,
              thumbnail: userInfo.thumbnail,
              accessTier: userAccessTier,
              authenticatedServer: authenticatedServer,
              token: authToken
            },
            userServers: userServers,
            timestamp: Date.now()
          });

          // Clean up pending auth
          this.pendingAuth.delete(pinId);
          
          this.logger.info(`User ${userInfo.email} authenticated successfully via OAuth. Access to servers: ${Object.keys(userServers).join(', ')}`);
          
          // Return success with redirect URL
          res.json({ 
            status: 'success', 
            redirect: pending.redirect,
            user: userInfo.email,
            sessionKey: pinId + '_user'
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

    // Session establishment endpoint
    this.app.post('/auth/establish', (req, res) => {
      try {
        const { sessionKey } = req.body;
        this.logger.debug(`Attempting to establish session with key: ${sessionKey}`);
        
        const authData = this.pendingAuth.get(sessionKey);
        if (!authData) {
          this.logger.warn(`Invalid or expired session key: ${sessionKey}`);
          return res.status(400).json({ error: 'Invalid session key' });
        }

        // Store in actual session
        req.session.user = authData.user;
        req.session.userServers = authData.userServers;
        
        // Clear the pending PIN from session
        delete req.session.pendingPinId;

        // Clean up temporary storage
        this.pendingAuth.delete(sessionKey);

        this.logger.info(`Session established for user: ${authData.user.email}`);
        res.json({ success: true });
      } catch (error) {
        this.logger.error('Session establishment error:', error);
        res.status(500).json({ error: 'Failed to establish session' });
      }
    });
  }

  async handleAuth(req, res) {
    const originalUrl = req.headers['x-original-url'] || req.query.url;
    const host = req.headers['x-forwarded-host'] || req.headers.host;
    
    this.logger.debug(`Auth request for host: ${host}, original URL: ${originalUrl}`);

    // Check if user is authenticated
    if (!req.session.user || !req.session.userServers) {
      this.logger.debug('User not authenticated, returning 401');
      return res.status(401).json({ error: 'Not authenticated' });
    }

    // Check access control
    const accessResult = this.accessController.checkAccess(
      host,
      req.session.user,
      req.session.user.accessTier,
      req.session.user.authenticatedServer,
      req.session.userServers
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

    // Set auth headers for upstream services (like PlexSSO)
    res.set({
      'X-PlexSSO-Username': req.session.user.username,
      'X-PlexSSO-Email': req.session.user.email,
      'X-Auth-User': req.session.user.email,
      'X-Auth-Name': req.session.user.username,
      'X-Auth-Admin': req.session.user.accessTier === 'Owner' ? 'true' : 'false',
      'X-Auth-Servers': JSON.stringify(Object.keys(req.session.userServers))
    });

    this.logger.info(`Access granted for user ${req.session.user.email} to ${host}. Available servers: ${Object.keys(req.session.userServers).join(', ')}`);
    res.status(200).json({ 
      success: true,
      user: req.session.user.email,
      access_granted: true,
      servers: Object.keys(req.session.userServers)
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
        const pinId = '${pinId}';
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
                        document.getElementById('statusText').textContent = 'Authentication successful! Establishing session...';
                        
        // Establish session and redirect
                        fetch('/auth/establish', {
                            method: 'POST',
                            headers: {
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify({ sessionKey: data.sessionKey })
                        }).then(response => response.json()).then(result => {
                            if (result.success) {
                                window.location.href = data.redirect;
                            } else {
                                document.getElementById('statusText').textContent = 'Failed to establish session';
                            }
                        }).catch(error => {
                            console.error('Session establishment failed:', error);
                            document.getElementById('statusText').textContent = 'Session establishment failed';
                        });
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

  cleanupPendingAuth() {
    const now = Date.now();
    const fifteenMinutes = 15 * 60 * 1000;
    
    for (const [key, data] of this.pendingAuth.entries()) {
      if (now - data.timestamp > fifteenMinutes) {
        this.pendingAuth.delete(key);
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

// Export for use
if (typeof module !== 'undefined' && module.exports) {
  module.exports = { PlexAuthProxy, PlexClient, AccessController };
}

// Start the server if this file is run directly
if (require.main === module) {
  const proxy = new PlexAuthProxy();
  proxy.start();
}
