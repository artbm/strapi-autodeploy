#!/usr/bin/env node

const { execSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");
const dotenv = require("dotenv");

class StrapiDeployer {
  constructor(envPath = ".env") {
    // Load and validate environment configuration
    this.loadEnvironmentConfig(envPath);
  }

  loadEnvironmentConfig(envPath) {
    if (!fs.existsSync(envPath)) {
      console.error(`Environment file not found: ${envPath}`);
      process.exit(1);
    }

    dotenv.config({ path: envPath });

    const requiredVars = ["DOMAIN", "EMAIL", "STRAPI_DIR"];
    const missingVars = requiredVars.filter((varName) => !process.env[varName]);

    if (missingVars.length > 0) {
      console.error(
        "Missing required environment variables:",
        missingVars.join(", ")
      );
      process.exit(1);
    }

    this.domain = process.env.DOMAIN;
    this.email = process.env.EMAIL;
    this.strapiDir = process.env.STRAPI_DIR;
    this.strapiUser = process.env.STRAPI_USER || "strapi";
    this.strapiGroup = process.env.STRAPI_GROUP || "strapi";
    this.dbConfig = {
      host: process.env.DB_HOST || "localhost",
      port: parseInt(process.env.DB_PORT) || 5432,
      database: process.env.DB_NAME || "strapi",
      user: process.env.DB_USER || "strapi_db",
      password: process.env.DB_PASSWORD || this.generatePassword(),
    };
    this.sshConfig = {
      maxRetries: parseInt(process.env.SSH_RATE_LIMIT_ATTEMPTS) || 3,
      findTime: parseInt(process.env.SSH_RATE_LIMIT_TIME) || 300,
      banTime: parseInt(process.env.SSH_BAN_TIME) || 3600,
    };
  }

  generatePassword(length = 32) {
    return crypto.randomBytes(length).toString("base64");
  }

  runCommand(command, options = {}) {
    try {
      execSync(command, {
        stdio: ["pipe", "pipe", "pipe"],
        ...options,
      });
    } catch (error) {
      console.error(`Error executing command: ${command}`);
      console.error(`Error output: ${error.stderr?.toString()}`);
      process.exit(1);
    }
  }

  createStrapiUser() {
    console.log("Creating dedicated Strapi user...");
    try {
      this.runCommand(`id -u ${this.strapiUser}`);
    } catch {
      this.runCommand(
        `useradd -r -d ${this.strapiDir} -s /bin/bash ${this.strapiUser}`
      );
      this.runCommand(`groupadd ${this.strapiGroup}`);
      this.runCommand(`usermod -a -G ${this.strapiGroup} ${this.strapiUser}`);
    }
  }

  async setupFirewall() {
    console.log("Configuring firewall with enhanced security...");

    this.runCommand("apt-get install -y ufw");
    this.runCommand("ufw --force reset");
    this.runCommand("ufw default deny incoming");
    this.runCommand("ufw default allow outgoing");
    this.runCommand("ufw limit ssh");
    this.runCommand("ufw allow http");
    this.runCommand("ufw allow https");
    this.runCommand("ufw allow from 127.0.0.1 to any port 5432");
    this.runCommand("ufw allow from 127.0.0.1 to any port 1337");

    const sysctlConfig = `
# Port scanning protection
net.ipv4.tcp_syncookies = 1
net.ipv4.tcp_max_syn_backlog = 2048
net.ipv4.tcp_synack_retries = 2
net.ipv4.tcp_syn_retries = 5

# Connection tracking
net.netfilter.nf_conntrack_max = 2000000
net.netfilter.nf_conntrack_tcp_timeout_time_wait = 30

# General network security
net.ipv4.ip_forward = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.tcp_timestamps = 0
`;

    fs.writeFileSync("/etc/sysctl.d/99-security.conf", sysctlConfig);
    this.runCommand("sysctl -p /etc/sysctl.d/99-security.conf");

    this.runCommand('echo "y" | ufw enable');
    this.runCommand("ufw status verbose");

    console.log("Installing and configuring fail2ban...");
    this.runCommand("apt-get install -y fail2ban");

    const fail2banConfig = `
[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = ${this.sshConfig.maxRetries}
findtime = ${this.sshConfig.findTime}
bantime = ${this.sshConfig.banTime}
`;

    fs.writeFileSync("/etc/fail2ban/jail.local", fail2banConfig);
    this.runCommand("systemctl enable fail2ban");
    this.runCommand("systemctl restart fail2ban");
  }

  async installDependencies() {
    console.log("Installing system dependencies...");
    this.runCommand("apt-get update");
    this.runCommand("apt-get install -y curl git build-essential");

    console.log("Installing Node.js...");
    const nodeVersion = process.env.NODE_VERSION || "18";
    this.runCommand(
      `curl -fsSL https://deb.nodesource.com/setup_${nodeVersion}.x -o /tmp/nodesource_setup.sh`
    );
    this.runCommand("bash /tmp/nodesource_setup.sh");
    this.runCommand("apt-get install -y nodejs");
  }

  async setupPostgres() {
    console.log("Setting up PostgreSQL...");
    const pgVersion = process.env.PG_VERSION || "16";

    this.runCommand(
      "sh -c 'echo \"deb https://apt.postgresql.org/pub/repos/apt $(lsb_release -cs)-pgdg main\" > /etc/apt/sources.list.d/pgdg.list'"
    );

    this.runCommand(
      "wget --quiet -O - https://www.postgresql.org/media/keys/ACCC4CF8.asc | apt-key add -"
    );

    this.runCommand("apt-get update");
    this.runCommand(`apt-get install -y postgresql-${pgVersion}`);

    console.log("Configuring PostgreSQL...");
    this.runCommand(
      `su - postgres -c "psql -c \\"CREATE USER ${this.dbConfig.user} WITH PASSWORD '${this.dbConfig.password}';\\""`
    );
    this.runCommand(
      `su - postgres -c "psql -c \\"CREATE DATABASE ${this.dbConfig.database};\\""`
    );
    this.runCommand(
      `su - postgres -c "psql -c \\"GRANT ALL PRIVILEGES ON DATABASE ${this.dbConfig.database} TO ${this.dbConfig.user};\\""`
    );

    const dbEnvConfig = {
      DATABASE_PASSWORD: this.dbConfig.password,
      DATABASE_USERNAME: this.dbConfig.user,
      DATABASE_NAME: this.dbConfig.database,
      DATABASE_PORT: this.dbConfig.port,
      DATABASE_HOST: this.dbConfig.host,
    };

    fs.writeFileSync(
      path.join(this.strapiDir, ".env"),
      Object.entries(dbEnvConfig)
        .map(([k, v]) => `${k}=${v}`)
        .join("\n"),
      { mode: 0o600 }
    );
  }

  async installCaddy() {
    console.log("Installing Caddy...");
    this.runCommand(
      "apt-get install -y debian-keyring debian-archive-keyring apt-transport-https"
    );

    this.runCommand(
      "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/gpg.key' | gpg --dearmor -o /usr/share/keyrings/caddy-stable-archive-keyring.gpg"
    );

    this.runCommand(
      "curl -1sLf 'https://dl.cloudsmith.io/public/caddy/stable/debian.deb.txt' | tee /etc/apt/sources.list.d/caddy-stable.list"
    );

    this.runCommand("apt-get update");
    this.runCommand("apt-get install -y caddy");

    const caddyfileContent = `
${this.domain} {
    reverse_proxy localhost:${process.env.STRAPI_PORT || 1337}
    tls ${this.email}
}`;

    fs.writeFileSync("/etc/caddy/Caddyfile", caddyfileContent);
    this.runCommand("systemctl restart caddy");
  }

  async setupStrapi() {
    console.log("Setting up Strapi...");

    this.runCommand(`mkdir -p ${this.strapiDir}`);
    this.runCommand(
      `chown -R ${this.strapiUser}:${this.strapiGroup} ${this.strapiDir}`
    );
    this.runCommand(`chmod 750 ${this.strapiDir}`);

    const envContent = fs.readFileSync(
      path.join(this.strapiDir, ".env"),
      "utf8"
    );
    const dbConfig = Object.fromEntries(
      envContent.split("\n").map((line) => {
        const [key, value] = line.split("=");
        return [key.replace("DATABASE_", "").toLowerCase(), value];
      })
    );

    process.chdir(this.strapiDir);
    this.runCommand(
      `su - ${this.strapiUser} -c "cd ${this.strapiDir} && ` +
        `npx create-strapi-app@latest . --no-run ` +
        `--dbclient=postgres ` +
        `--dbhost=${dbConfig.host} ` +
        `--dbport=${dbConfig.port} ` +
        `--dbname=${dbConfig.name} ` +
        `--dbusername=${dbConfig.username} ` +
        `--dbpassword='${dbConfig.password}' ` +
        `--quiet"`
    );

    const serviceContent = `[Unit]
Description=Strapi
After=network.target postgresql.service

[Service]
Type=simple
User=${this.strapiUser}
Group=${this.strapiGroup}
WorkingDirectory=${this.strapiDir}
ExecStart=/usr/bin/npm run start
Restart=always
Environment=NODE_ENV=production

[Install]
WantedBy=multi-user.target`;

    fs.writeFileSync("/etc/systemd/system/strapi.service", serviceContent);
    this.runCommand("systemctl enable strapi");
    this.runCommand("systemctl start strapi");
  }

  async deploy() {
    console.log("Starting Strapi deployment...");

    await this.createStrapiUser();
    await this.installDependencies();
    await this.setupFirewall();
    await this.setupPostgres();
    await this.installCaddy();
    await this.setupStrapi();

    console.log(`
Deployment completed successfully!
Strapi admin URL: https://${this.domain}/admin

Security Configuration Summary:
1. Firewall (UFW) is enabled with:
   - Rate-limited SSH access (${this.sshConfig.maxRetries} attempts per ${this.sshConfig.findTime}s)
   - HTTP/HTTPS allowed
   - PostgreSQL and Strapi ports restricted to localhost
2. Fail2ban configured with ${this.sshConfig.banTime}s ban time
3. System hardening parameters set via sysctl
4. Database credentials stored in ${this.strapiDir}/.env
5. Strapi running as dedicated system user
6. File permissions properly restricted

Security Recommendations:
1. Monitor auth.log and fail2ban.log for unauthorized access attempts
2. Set up regular security updates (unattended-upgrades)
3. Create your admin user through the Strapi admin interface
4. Implement regular backup procedures
5. Monitor system resources and logs regularly
`);
  }
}

const validateEnvironmentFile = () => {
  const envPath = path.join(process.cwd(), ".env");
  if (!fs.existsSync(envPath)) {
    console.error("Error: .env file not found in current directory");
    process.exit(1);
  }
  return envPath;
};

if (require.main === module) {
  const envPath = validateEnvironmentFile();
  const deployer = new StrapiDeployer(envPath);
  deployer.deploy().catch((error) => {
    console.error("Deployment failed:", error);
    process.exit(1);
  });
}

module.exports = StrapiDeployer;
