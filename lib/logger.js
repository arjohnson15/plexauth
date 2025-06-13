const fs = require('fs');
const path = require('path');

class Logger {
  constructor(config) {
    this.config = config;
    this.levels = {
      debug: 0,
      info: 1,
      warn: 2,
      error: 3
    };
    this.currentLevel = this.levels[config.level] || this.levels.info;
    
    // Ensure log directory exists
    if (config.log_file) {
      const logDir = path.dirname(config.log_file);
      if (!fs.existsSync(logDir)) {
        fs.mkdirSync(logDir, { recursive: true });
      }
    }
  }

  log(level, message, ...args) {
    if (this.levels[level] < this.currentLevel) {
      return;
    }

    const timestamp = new Date().toISOString();
    const logMessage = `[${timestamp}] [${level.toUpperCase()}] ${message}`;
    
    // Console output
    console.log(logMessage, ...args);
    
    // File output
    if (this.config.log_file) {
      try {
        const fileMessage = args.length > 0 
          ? `${logMessage} ${JSON.stringify(args)}\n`
          : `${logMessage}\n`;
        fs.appendFileSync(this.config.log_file, fileMessage);
      } catch (error) {
        console.error('Failed to write to log file:', error);
      }
    }
  }

  debug(message, ...args) {
    this.log('debug', message, ...args);
  }

  info(message, ...args) {
    this.log('info', message, ...args);
  }

  warn(message, ...args) {
    this.log('warn', message, ...args);
  }

  error(message, ...args) {
    this.log('error', message, ...args);
  }
}

module.exports = Logger;