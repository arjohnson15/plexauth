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
    this.config = this.loadConfig();
    this.logger = new Logger(this.config.logging);
    this.plexAuth = new PlexAuthenticator(this.config, this.logger);
    this.accessControl = new AccessControl(this.config, this.logger);
    
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
    // Security middleware
    this.app.use(helmet({
      crossOriginEmbedderPolicy: false,
      contentSecurityPolicy: false // We'll handle CSP ourselves if needed
    }));

    // Rate limiting
    const limiter = rateLimit({
      windowMs: this.config.security.rate_limit.window_ms,
      max: this.config.security.rate_limit.max_requests,
      message: 'Too many requests from this IP, please try again later.'
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

    // Login page
    this.app.get('/login', (req, res) => {
      const originalUrl = req.query.redirect || req.headers.referer || '/';
      res.send(this.generateLoginPage(originalUrl));
    });

    // Login handler
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
      this.logger.debug('User not authenticated, redirecting to login');
      return res.redirect(`/login?redirect=${encodeURIComponent(originalUrl || '/')}`);
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

  generateLoginPage(redirectUrl) {
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
            padding: 2rem;
            border-radius: 10px;
            box-shadow: 0 10px 25px rgba(0,0,0,0.2);
            width: 100%;
            max-width: 400px;
        }
        .logo {
            text-align: center;
            margin-bottom: 2rem;
        }
        .logo img {
            width: 100px;
            height: auto;
        }
        .form-group {
            margin-bottom: 1rem;
        }
        label {
            display: block;
            margin-bottom: 0.5rem;
            font-weight: 500;
            color: #333;
        }
        input[type="text"], input[type="password"] {
            width: 100%;
            padding: 0.75rem;
            border: 2px solid #e1e1e1;
            border-radius: 5px;
            font-size: 1rem;
            transition: border-color 0.3s;
        }
        input[type="text"]:focus, input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
        }
        .btn {
            width: 100%;
            padding: 0.75rem;
            background: #667eea;
            color: white;
            border: none;
            border-radius: 5px;
            font-size: 1rem;
            cursor: pointer;
            transition: background 0.3s;
        }
        .btn:hover {
            background: #5a67d8;
        }
        .error {
            color: #e53e3e;
            margin-top: 0.5rem;
            font-size: 0.9rem;
        }
        .help-text {
            text-align: center;
            margin-top: 1rem;
            color: #666;
            font-size: 0.9rem;
        }
    </style>
</head>
<body>
    <div class="login-container">
        <div class="logo">
            <h2>🎬 Plex Authentication</h2>
        </div>
        
        <form id="loginForm" method="POST" action="/login">
            <input type="hidden" name="redirect" value="${redirectUrl}">
            
            <div class="form-group">
                <label for="username">Email or Username</label>
                <input type="text" id="username" name="username" required>
            </div>
            
            <div class="form-group">
                <label for="password">Password</label>
                <input type="password" id="password" name="password" required>
            </div>
            
            <button type="submit" class="btn">Sign In</button>
            
            <div id="error" class="error" style="display: none;"></div>
        </form>
        
        <div class="help-text">
            Use your Plex account credentials to sign in
        </div>
    </div>

    <script>
        document.getElementById('loginForm').addEventListener('submit', async function(e) {
            e.preventDefault();
            
            const formData = new FormData(this);
            const errorDiv = document.getElementById('error');
            
            try {
                const response = await fetch('/login', {
                    method: 'POST',
                    body: formData
                });
                
                if (response.ok) {
                    const data = await response.json();
                    if (data.success) {
                        window.location.href = formData.get('redirect') || '/';
                    }
                } else {
                    const data = await response.json();
                    errorDiv.textContent = data.error || 'Authentication failed';
                    errorDiv.style.display = 'block';
                }
            } catch (error) {
                errorDiv.textContent = 'Connection error. Please try again.';
                errorDiv.style.display = 'block';
            }
        });
    </script>
</body>
</html>
    `;
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