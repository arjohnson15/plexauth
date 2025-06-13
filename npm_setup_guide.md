# Nginx Proxy Manager Setup Guide

This guide shows you how to configure Nginx Proxy Manager (NPM) to work with the Plex Authentication Proxy.

## Step 1: Configure Authentication Proxy in NPM

### For each domain you want to protect:

1. **Create/Edit Proxy Host in NPM**
   - Go to your NPM dashboard
   - Create a new Proxy Host or edit an existing one
   - Set your domain (e.g., `site1.me.com`)
   - Set the destination to your actual service

2. **Add Advanced Configuration**
   In the "Advanced" tab, add this configuration:

```nginx
# Send original request info to auth service
auth_request /auth;
auth_request_set $user $upstream_http_x_auth_user;
auth_request_set $name $upstream_http_x_auth_name;
auth_request_set $admin $upstream_http_x_auth_admin;
auth_request_set $servers $upstream_http_x_auth_servers;

# Pass auth headers to your application
proxy_set_header X-Auth-User $user;
proxy_set_header X-Auth-Name $name;
proxy_set_header X-Auth-Admin $admin;
proxy_set_header X-Auth-Servers $servers;

# Auth endpoint configuration
location = /auth {
    internal;
    proxy_pass http://plex-auth-proxy:3000/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URL $request_uri;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
}

# Handle authentication redirects
error_page 401 = @error401;
location @error401 {
    return 302 http://plex-auth-proxy:3000/login?redirect=$request_uri;
}
```

## Step 2: Create Auth Proxy Host in NPM

Create a separate proxy host for the authentication service:

- **Domain**: `auth.me.com` (or your preferred auth subdomain)
- **Forward Hostname/IP**: `plex-auth-proxy` (container name)
- **Forward Port**: `3000`
- **SSL**: Enable if desired

## Step 3: Network Configuration

Make sure both NPM and the Plex Auth Proxy are on the same Docker network:

```bash
# Create a shared network if you don't have one
docker network create proxy-network

# Make sure NPM is using this network
# Update your docker-compose.yml networks section
```

## Step 4: Example Complete NPM Advanced Configuration

Here's a complete example for a protected service:

```nginx
# Authentication
auth_request /auth;
auth_request_set $user $upstream_http_x_auth_user;
auth_request_set $name $upstream_http_x_auth_name;
auth_request_set $admin $upstream_http_x_auth_admin;

# Pass authenticated user info to your app
proxy_set_header X-Auth-User $user;
proxy_set_header X-Auth-Name $name;
proxy_set_header X-Auth-Admin $admin;

# Standard proxy headers
proxy_set_header Host $host;
proxy_set_header X-Real-IP $remote_addr;
proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
proxy_set_header X-Forwarded-Proto $scheme;

# Auth endpoint
location = /auth {
    internal;
    proxy_pass http://plex-auth-proxy:3000/auth;
    proxy_pass_request_body off;
    proxy_set_header Content-Length "";
    proxy_set_header X-Original-URL $request_uri;
    proxy_set_header X-Forwarded-Host $host;
    proxy_set_header X-Forwarded-Proto $scheme;
}

# Redirect unauthorized users to login
error_page 401 = @error401;
location @error401 {
    return 302 https://auth.me.com/login?redirect=https://$host$request_uri;
}

# Optional: Provide logout endpoint
location /logout {
    proxy_pass http://plex-auth-proxy:3000/logout;
    proxy_set_header Host $host;
}
```

## Step 5: Testing

1. **Start the Auth Proxy**: `docker-compose up -d`
2. **Update NPM configurations** for your protected domains
3. **Test access**:
   - Visit `site1.me.com` - should redirect to login
   - Login with Plex credentials
   - Should be redirected back to your site
   - Check that auth headers are passed to your application

## Troubleshooting

### Common Issues:

1. **502 Bad Gateway**: Check that containers can communicate
   ```bash
   docker exec -it nginx-proxy-manager ping plex-auth-proxy
   ```

2. **Auth loop**: Make sure the auth endpoint is marked as `internal`

3. **SSL issues**: If using HTTPS, make sure redirect URLs use HTTPS

4. **Network issues**: Verify both containers are on the same network
   ```bash
   docker network ls
   docker network inspect proxy-network
   ```

### Debug Mode:

Enable debug logging in your config.yaml:
```yaml
app:
  debug: true
logging:
  level: "debug"
```

Then check logs:
```bash
docker logs plex-auth-proxy -f
```

## Advanced Features

### Custom Error Pages
You can create custom error pages by adding them to your NPM configuration:

```nginx
error_page 403 /403.html;
location = /403.html {
    root /data/nginx/error_pages;
    internal;
}
```

### Rate Limiting
Add rate limiting to protect against brute force:

```nginx
limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;

location /login {
    limit_req zone=login burst=3 nodelay;
    proxy_pass http://plex-auth-proxy:3000/login;
}
```