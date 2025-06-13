class AccessControl {
  constructor(config, logger) {
    this.config = config;
    this.logger = logger;
  }

  async checkAccess(host, user, userServers) {
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
        return this.checkUserWhitelist(rules, user, userServers);
      
      case 'any_member':
        return this.checkAnyMember(rules, user, userServers);
      
      case 'conditional_redirect':
        return this.checkConditionalRedirect(rules, user, userServers);
      
      case 'admin_only':
        return this.checkAdminOnly(rules, user, userServers);
      
      case 'friends_allowed':
        return this.checkFriendsAllowed(rules, user, userServers);
      
      case 'time_restricted':
        return this.checkTimeRestricted(rules, user, userServers);
      
      default:
        this.logger.error(`Unknown access rule type: ${rules.type}`);
        return { 
          allowed: false, 
          reason: 'Invalid access rule configuration',
          redirect: null 
        };
    }
  }

  checkUserWhitelist(rules, user, userServers) {
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

  checkAnyMember(rules, user, userServers) {
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

  checkConditionalRedirect(rules, user, userServers) {
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

  checkAdminOnly(rules, user, userServers) {
    // Check if user is admin on any of the allowed servers
    const isAdmin = Object.keys(userServers).some(serverId => {
      if (rules.allowed_servers.includes(serverId)) {
        return userServers[serverId].is_owner || user.admin;
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

  checkFriendsAllowed(rules, user, userServers) {
    // Check if user has friend access to any of the allowed servers
    const hasFriendAccess = rules.allowed_servers.some(serverId => {
      const serverAccess = userServers[serverId];
      return serverAccess && (serverAccess.access_level === 'friend' || serverAccess.is_owner);
    });

    if (!hasFriendAccess) {
      return { 
        allowed: false, 
        reason: 'Friend access required',
        redirect: null 
      };
    }

    return { 
      allowed: true, 
      reason: 'Friend access granted',
      redirect: rules.redirect_to 
    };
  }

  checkTimeRestricted(rules, user, userServers) {
    const now = new Date();
    const currentHour = now.getHours();
    const currentMinute = now.getMinutes();
    const currentTime = currentHour * 60 + currentMinute;
    const currentDay = now.toLocaleDateString('en-US', { weekday: 'long' }).toLowerCase();

    // Check day restriction
    if (rules.allowed_days && !rules.allowed_days.includes(currentDay)) {
      return { 
        allowed: false, 
        reason: 'Access not allowed on this day',
        redirect: null 
      };
    }

    // Check time restriction
    if (rules.allowed_hours) {
      const [startHour, startMinute] = rules.allowed_hours.start.split(':').map(Number);
      const [endHour, endMinute] = rules.allowed_hours.end.split(':').map(Number);
      const startTime = startHour * 60 + startMinute;
      const endTime = endHour * 60 + endMinute;

      if (currentTime < startTime || currentTime > endTime) {
        return { 
          allowed: false, 
          reason: 'Access not allowed at this time',
          redirect: null 
        };
      }
    }

    // Check server access
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
      reason: 'Time-restricted access granted',
      redirect: rules.redirect_to 
    };
  }

  // Helper method to check if user has specific server access
  hasServerAccess(userServers, allowedServers) {
    return allowedServers.some(serverId => userServers.hasOwnProperty(serverId));
  }

  // Method to get user's access level for a specific server
  getUserServerAccessLevel(userServers, serverId) {
    const serverAccess = userServers[serverId];
    if (!serverAccess) return null;
    
    return {
      level: serverAccess.access_level,
      isOwner: serverAccess.is_owner,
      serverName: serverAccess.name
    };
  }
}

module.exports = AccessControl;