const axios = require('axios');
const { XMLParser } = require('fast-xml-parser');
const { PlexOauth } = require('plex-oauth');

class PlexAuthenticator {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
    this.xmlParser = new XMLParser({
      ignoreAttributes: false,
      attributeNamePrefix: '@_'
    });
    
    // OAuth client configuration
    this.clientInfo = {
      clientIdentifier: config.app.client_identifier || 'plex-auth-proxy-' + Date.now(),
      product: 'Plex Auth Proxy',
      device: 'Auth Proxy Server',
      version: '1.0.0',
      platform: 'Web'
    };
  }

  async createAuthUrl(redirectUrl) {
    try {
      const clientConfig = {
        ...this.clientInfo,
        forwardUrl: redirectUrl
      };
      
      const plexOauth = new PlexOauth(clientConfig);
      const [hostedUILink, pinId] = await plexOauth.requestHostedLoginURL();
      
      this.logger.info('Created Plex OAuth URL', { pinId });
      
      return {
        authUrl: hostedUILink,
        pinId: pinId
      };
    } catch (error) {
      this.logger.error('Failed to create Plex OAuth URL:', error);
      throw new Error('Failed to initiate Plex authentication');
    }
  }

  async checkAuthToken(pinId) {
    try {
      const plexOauth = new PlexOauth(this.clientInfo);
      const authToken = await plexOauth.checkForAuthToken(pinId);
      
      if (!authToken) {
        return { success: false, error: 'Authentication not completed' };
      }

      // Get user info with the token
      const userInfo = await this.getPlexUserInfo(authToken);
      if (!userInfo) {
        return { success: false, error: 'Failed to get user info' };
      }

      // Check server access
      const serverAccess = await this.checkServerAccess(authToken, userInfo);

      return {
        success: true,
        user: {
          id: userInfo.id,
          email: userInfo.email,
          username: userInfo.username,
          title: userInfo.title,
          admin: userInfo.admin === '1',
          token: authToken
        },
        servers: serverAccess
      };

    } catch (error) {
      this.logger.error('Failed to check auth token:', error);
      return { success: false, error: 'Authentication failed' };
    }
  }

  async authenticate(username, password) {
    // Legacy method - we'll keep this for backwards compatibility
    // but the main flow should use OAuth
    try {
      const authToken = await this.getPlexToken(username, password);
      if (!authToken) {
        return { success: false, error: 'Invalid credentials' };
      }

      const userInfo = await this.getPlexUserInfo(authToken);
      if (!userInfo) {
        return { success: false, error: 'Failed to get user info' };
      }

      const serverAccess = await this.checkServerAccess(authToken, userInfo);

      return {
        success: true,
        user: {
          id: userInfo.id,
          email: userInfo.email,
          username: userInfo.username,
          title: userInfo.title,
          admin: userInfo.admin === '1',
          token: authToken
        },
        servers: serverAccess
      };

    } catch (error) {
      this.logger.error('Authentication failed:', error);
      return { success: false, error: 'Authentication failed' };
    }
  }

  async getPlexToken(username, password) {
    try {
      const response = await axios.post('https://plex.tv/users/sign_in.xml', null, {
        headers: {
          'X-Plex-Client-Identifier': this.clientInfo.clientIdentifier,
          'X-Plex-Product': this.clientInfo.product,
          'X-Plex-Version': this.clientInfo.version,
          'X-Plex-Device': this.clientInfo.device,
          'X-Plex-Device-Name': 'Authentication Proxy',
          'Authorization': `Basic ${Buffer.from(`${username}:${password}`).toString('base64')}`
        },
        timeout: 10000
      });

      const parsed = this.xmlParser.parse(response.data);
      if (parsed.user && parsed.user['@_authToken']) {
        return parsed.user['@_authToken'];
      }
      
      return null;
    } catch (error) {
      this.logger.error('Failed to get Plex token:', error.message);
      return null;
    }
  }

  async getPlexUserInfo(token) {
    try {
      const response = await axios.get('https://plex.tv/users/account.xml', {
        headers: {
          'X-Plex-Token': token,
          'X-Plex-Client-Identifier': this.clientInfo.clientIdentifier,
          'X-Plex-Product': this.clientInfo.product
        },
        timeout: 10000
      });

      const parsed = this.xmlParser.parse(response.data);
      if (parsed.user) {
        return {
          id: parsed.user['@_id'],
          email: parsed.user['@_email'],
          username: parsed.user['@_username'],
          title: parsed.user['@_title'],
          admin: parsed.user['@_admin']
        };
      }
      
      return null;
    } catch (error) {
      this.logger.error('Failed to get user info:', error.message);
      return null;
    }
  }

  async checkServerAccess(token, userInfo) {
    const serverAccess = {};

    for (const [serverId, serverConfig] of Object.entries(this.config.plex_servers)) {
      try {
        const hasAccess = await this.checkUserServerAccess(token, serverConfig, userInfo);
        
        if (hasAccess) {
          serverAccess[serverId] = {
            name: serverConfig.name,
            url: serverConfig.url,
            access_level: hasAccess.level,
            is_owner: hasAccess.isOwner
          };
        }
      } catch (error) {
        this.logger.warn(`Failed to check access for server ${serverId}:`, error.message);
      }
    }

    return serverAccess;
  }

  async checkUserServerAccess(token, serverConfig, userInfo) {
    try {
      // First, try to connect directly to the server to check ownership
      const serverResponse = await axios.get(`${serverConfig.url}/`, {
        headers: {
          'X-Plex-Token': serverConfig.token
        },
        timeout: 5000
      });

      const serverInfo = this.xmlParser.parse(serverResponse.data);
      const machineId = serverInfo.MediaContainer['@_machineIdentifier'];

      // Check if this user is the owner of the server
      if (machineId === serverConfig.machine_id) {
        try {
          const userServerResponse = await axios.get(`${serverConfig.url}/`, {
            headers: {
              'X-Plex-Token': token
            },
            timeout: 5000
          });
          
          if (userServerResponse.status === 200) {
            return { level: 'owner', isOwner: true };
          }
        } catch (ownerError) {
          // Not the owner, continue to check shared access
        }
      }

      // Check shared libraries via Plex.tv
      const sharedServers = await this.getSharedServers(token);
      const hasSharedAccess = sharedServers.some(server => 
        server.machineIdentifier === machineId
      );

      if (hasSharedAccess) {
        return { level: 'friend', isOwner: false };
      }

      return null;

    } catch (error) {
      this.logger.debug(`Server access check failed for ${serverConfig.name}:`, error.message);
      return null;
    }
  }

  async getSharedServers(token) {
    try {
      const response = await axios.get('https://plex.tv/pms/servers.xml', {
        headers: {
          'X-Plex-Token': token,
          'X-Plex-Product': this.clientInfo.product
        },
        timeout: 10000
      });

      const parsed = this.xmlParser.parse(response.data);
      const servers = [];

      if (parsed.MediaContainer && parsed.MediaContainer.Server) {
        const serverList = Array.isArray(parsed.MediaContainer.Server) 
          ? parsed.MediaContainer.Server 
          : [parsed.MediaContainer.Server];

        serverList.forEach(server => {
          servers.push({
            name: server['@_name'],
            machineIdentifier: server['@_machineIdentifier'],
            owned: server['@_owned'] === '1',
            accessToken: server['@_accessToken']
          });
        });
      }

      return servers;
    } catch (error) {
      this.logger.error('Failed to get shared servers:', error.message);
      return [];
    }
  }

  async validateToken(token) {
    try {
      const response = await axios.get('https://plex.tv/users/account.xml', {
        headers: {
          'X-Plex-Token': token,
          'X-Plex-Product': this.clientInfo.product
        },
        timeout: 5000
      });

      return response.status === 200;
    } catch (error) {
      return false;
    }
  }
}

module.exports = PlexAuthenticator;
