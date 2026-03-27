const fs = require('fs');
const path = require('path');

// Load .env file
const envFile = path.join(__dirname, '.env');
const envVars = {};
if (fs.existsSync(envFile)) {
  const lines = fs.readFileSync(envFile, 'utf8').split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (trimmed && !trimmed.startsWith('#')) {
      const [key, ...rest] = trimmed.split('=');
      envVars[key.trim()] = rest.join('=').trim();
    }
  }
}

module.exports = {
  apps: [{
    name: 'cmmc-exposure',
    script: 'npm',
    args: 'start',
    cwd: __dirname,
    env: {
      PORT: 3003,
      NODE_ENV: 'production',
      ...envVars,
    },
  }],
};
