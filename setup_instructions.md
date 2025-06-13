# Plex Authentication Proxy Setup Instructions

## Overview
This Docker container provides Plex-based SSO authentication for your services behind Nginx Proxy Manager. It supports user whitelisting, conditional redirects, time-based access control, and more.

## Quick Start

### 1. Get Your Plex Server Information

First, you need to gather information about your Plex servers:

**Get Plex Token:**
1. Log into Plex Web App
2. Go to Settings > Account > Privacy
3. Show Advanced, then copy your Plex Token

**Get Machine ID:**
1. Visit `http://YOUR_PLEX_IP:32400/` in browser
2. View page source and look for `machineIdentifier="..."` 
3. Or use: `curl -H "X-Plex-Token: YOUR_TOKEN" http://YOUR_PLEX_IP:32400/ | grep machineIdentifier`

### 2. Setup Directory Structure

```bash
mkdir plex-auth-proxy
cd plex-auth-proxy
mkdir config logs

# Copy all the provided files to this directory
# Make sure config.yaml is in the config/ subdirectory
```

### 3. Configure Your Settings

Edit `config/config.yaml`:

```yaml
app:
  session_secret: "CHANGE-THIS-TO-RANDOM-STRING"
  jwt_secret: "CHANGE-THIS-TO-DIFFERENT-RANDOM-STRING"  
  cookie_domain: ".yourdomain.com"  # Change to your domain

plex_servers:
  plex1:
    name: "Main Plex Server"
    url: "http://192.168.1.100:32400"  # Your Plex server IP
    token: "YOUR_PLEX_TOKEN_HERE"
    machine_id: "YOUR_MACHINE_ID_HERE"
  plex2:
    name: "Secondary Plex Server"
    url: "http://192.168.1.101:32400"  # Your second Plex server IP  
    token: "YOUR_SECOND_PLEX_TOKEN_HERE"
    machine_id: "YOUR_SECOND_MACHINE_ID_HERE"

access_rules:
  "site1.yourdomain.com":
    type: "user_whitelist"
    allowed_users:
      - "arjohnson15@gmail.com"  # Change to your email
    allowed_servers:
      - "plex1"
      - "plex2"

  "site2.yourdomain.com":
    type: "any_member"
    allowed_servers:
      - "plex1"
      - "plex2"

  "site3.yourdomain.com":
    type: "conditional_redirect"
    conditions:
      - server: "plex1"
        redirect_to: "http://192.168.2.2:3232"
      - server: "plex2" 
        redirect_to: "http://192.168.2.2:3234"
```

### 4. Build and Run

```bash
# Build the container
docker-compose up -d

# Check logs
docker logs plex-auth-proxy -f
```

### 5. Configure Nginx Proxy Manager

Follow the detailed guide in `NPM-Setup-Guide.md` to configure NPM to use this authentication proxy.

## Configuration Options

### Access Rule Types

#### 1. User Whitelist
Only specific users can access:
```yaml
"admin.yourdomain.com":
  type: "user_whitelist"
  allowed_users:
    - "admin@example.com"
    - "user2@example.com"
  allowed_servers:
    - "plex1"
```

#### 2. Any Member
Any Plex user with access to specified servers:
```yaml
"public.yourdomain.com":
  type: "any_member"
  allowed_servers:
    - "plex1"
    - "plex2"
```

#### 3. Admin Only
Only Plex server owners/admins:
```yaml
"admin.yourdomain.com":
  type: "admin_only"
  allowed_servers:
    - "plex1"
```

#### 4. Friends Allowed
Plex friends (shared library users):
```yaml
"friends.yourdomain.com":
  type: "friends_allowed"
  allowed_servers:
    - "plex1"
```

#### 5. Time Restricted
Access only during specific times/days:
```yaml
"work.yourdomain.com":
  type: "time_restricted"
  allowed_hours:
    start: "09:00"
    end: "17:00"
  allowed_days: ["monday", "tuesday", "wednesday", "thursday", "friday"]
  allowed_servers:
    - "plex1"
```

#### 6. Conditional Redirect
Redirect to different services based on Plex server membership:
```yaml
"app.yourdomain.com":
  type: "conditional_redirect"
  conditions:
    - server: "plex1"
      redirect_to: "http://192.168.1.10:8080"
    - server: "plex2"
      redirect_to: "http://192.168.1.11:8080"
  fallback_redirect: "http://default.example.com"
```

## Security Features

### Rate Limiting
The proxy includes built-in rate limiting to prevent brute force attacks.

### Session Management
- Sessions expire automatically
- Secure cookie settings
- HTTPS enforcement (configurable)

### Trusted Proxies
Configure trusted proxy networks:
```yaml
security:
  trusted_proxies:
    - "192.168.1.0/24"
    - "10.0.0.0/8"
```

## Monitoring and Logging

### Log Levels
- `debug`: Detailed debugging information
- `info`: General information messages  
- `warn`: Warning messages
- `error`: Error messages only

### Health Checks
The container includes health checks accessible at `/health`

### Viewing Logs
```bash
# Follow logs
docker logs plex-auth-proxy -f

# View log file (if configured)
docker exec plex-auth-proxy tail -f /app/logs/auth.log
```

## Troubleshooting

### Common Issues

**Authentication fails:**
- Verify Plex tokens are correct and haven't expired
- Check Plex server URLs are accessible from container
- Ensure machine IDs match your servers

**Access denied:**
- Check access rules match your domain exactly
- Verify user has access to specified Plex servers
- Check logs for specific denial reasons

**NPM integration issues:**
- Ensure containers are on same Docker network
- Verify NPM advanced configuration is correct
- Check that auth endpoints are marked as `internal`

### Debug Mode
Enable debug logging:
```yaml
app:
  debug: true
logging:
  level: "debug"
```

### Testing Authentication
```bash
# Test health endpoint
curl http://localhost:3000/health

# Test authentication (should redirect to login)
curl -I http://localhost:3000/auth -H "X-Forwarded-Host: site1.yourdomain.com"
```

## Advanced Usage

### Custom Headers
The proxy sets these headers for your applications:
- `X-Auth-User`: User's email
- `X-Auth-Name`: User's display name  
- `X-Auth-Servers`: JSON array of accessible servers
- `X-Auth-Admin`: "true" if user is admin

### API Endpoints
- `GET /health` - Health check
- `GET /auth` - Main authentication endpoint (for NPM)
- `GET /login` - Login page
- `POST /login` - Login handler
- `POST /logout` - Logout
- `GET /user` - Current user info

### Environment Variables
- `CONFIG_PATH`: Path to config file (default: `/app/config/config.yaml`)
- `NODE_ENV`: Set to `production` for production use
- `PORT`: Override default port (3000)

## Security Best Practices

1. **Change default secrets** in config.yaml
2. **Use HTTPS** for all external connections
3. **Limit network access** to trusted sources
4. **Regular token rotation** for Plex tokens
5. **Monitor logs** for suspicious activity
6. **Keep container updated**

## Support

If you encounter issues:
1. Check the logs first
2. Verify your configuration syntax
3. Test Plex connectivity independently
4. Review NPM configuration

The proxy provides detailed error messages in both logs and HTTP responses to help diagnose issues.