#!/usr/bin/env node

import { Command } from "commander";
import chalk from "chalk";
import Table from "cli-table3";
import inquirer from "inquirer";
import fs from "fs-extra";
import { spawn, exec } from "child_process";
import { promisify } from "util";
import path from "path";
import os from "os";

const execAsync = promisify(exec);

// Configuration directory and file
const CONFIG_DIR = path.join(os.homedir(), ".server-manager");
const CONFIG_FILE = path.join(CONFIG_DIR, "servers.json");

// Track temp files for cleanup
const tempFiles = new Set();

// Cleanup function
function cleanupTempFiles() {
  tempFiles.forEach((file) => {
    try {
      if (fs.existsSync(file)) {
        fs.removeSync(file);
      }
    } catch (error) {
      // Ignore cleanup errors
    }
  });
  tempFiles.clear();
}

// Add signal handlers for cleanup
process.on("SIGINT", () => {
  console.log(chalk.yellow("\n\nReceived SIGINT, cleaning up..."));
  cleanupTempFiles();
  process.exit(0);
});

process.on("SIGTERM", () => {
  console.log(chalk.yellow("\n\nReceived SIGTERM, cleaning up..."));
  cleanupTempFiles();
  process.exit(0);
});

process.on("exit", () => {
  cleanupTempFiles();
});

// Default configuration
const DEFAULT_CONFIG = {
  servers: {},
  settings: {
    defaultLocalPort: 8090,
  },
};

// Ensure configuration directory exists
await fs.ensureDir(CONFIG_DIR);

// Load or create configuration
let config = DEFAULT_CONFIG;
if (await fs.pathExists(CONFIG_FILE)) {
  try {
    config = await fs.readJson(CONFIG_FILE);
  } catch (error) {
    console.error(
      chalk.red("Error reading configuration file:"),
      error.message
    );
    process.exit(1);
  }
}

// Save configuration
async function saveConfig() {
  try {
    await fs.writeJson(CONFIG_FILE, config, { spaces: 2 });
  } catch (error) {
    console.error(chalk.red("Error saving configuration:"), error.message);
    process.exit(1);
  }
}

// Get server by name
function getServer(name) {
  if (!config.servers[name]) {
    console.error(
      chalk.red(
        `Server '${name}' not found. Use 'bun sm.js ls' to see available servers.`
      )
    );
    process.exit(1);
  }
  return config.servers[name];
}

// Generate SSH key pair
async function generateSSHKey(serverName) {
  const keyPath = path.join(CONFIG_DIR, `${serverName}_key`);
  const pubKeyPath = `${keyPath}.pub`;

  try {
    await execAsync(`ssh-keygen -t rsa -b 2048 -f "${keyPath}" -N "" -q`);
    const publicKey = await fs.readFile(pubKeyPath, "utf8");
    return {
      privateKeyPath: keyPath,
      publicKeyPath: pubKeyPath,
      publicKey: publicKey.trim(),
    };
  } catch (error) {
    console.error(chalk.red("Error generating SSH key:"), error.message);
    throw error;
  }
}

// Install SSH key on server
async function installSSHKey(server, keyInfo) {
  const { ip, username, password, port } = server;
  const { publicKey } = keyInfo;

  try {
    console.log(chalk.blue("Installing SSH key on server..."));

    // Use sshpass if available, otherwise prompt user
    const sshCommand = password
      ? `sshpass -p '${password}' ssh -o StrictHostKeyChecking=no -p ${port} ${username}@${ip}`
      : `ssh -o StrictHostKeyChecking=no -p ${port} ${username}@${ip}`;

    const installCommand = `echo '${publicKey}' >> ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys && chmod 700 ~/.ssh`;

    await execAsync(`${sshCommand} "${installCommand}"`);
    console.log(chalk.green("SSH key installed successfully!"));
  } catch (error) {
    console.warn(
      chalk.yellow("Warning: Could not automatically install SSH key.")
    );
    console.log(
      chalk.blue("Please manually add this public key to your server:")
    );
    console.log(chalk.cyan(keyInfo.publicKey));
  }
}

// Create SSH connection
function createSSHConnection(server, options = {}) {
  const { ip, username, port, keyPath, password } = server;
  const { localPort, remotePort, dynamicPort } = options;

  let args = ["-o", "StrictHostKeyChecking=no"];

  if (keyPath && fs.existsSync(keyPath)) {
    args.push("-i", keyPath);
  }

  args.push("-p", port.toString());

  if (dynamicPort) {
    args.push("-C", "-N", "-D", `0.0.0.0:${dynamicPort}`);
  }

  if (localPort && remotePort) {
    args.push("-L", `${localPort}:localhost:${remotePort}`);
  }

  args.push(`${username}@${ip}`);

  return spawn("ssh", args, { stdio: "inherit" });
}

// Program setup
const program = new Command();

program
  .name("sm")
  .description("SSH Server Manager - Manage SSH servers and tunnels")
  .version("1.0.0");

// Add server command
program
  .command("add")
  .description("Add a new SSH server")
  .action(async () => {
    try {
      const answers = await inquirer.prompt([
        {
          type: "input",
          name: "serverName",
          message: "Server name:",
          validate: (input) => {
            if (!input.trim()) return "Server name is required";
            if (config.servers[input.trim()])
              return "Server name already exists";
            return true;
          },
        },
        {
          type: "input",
          name: "ip",
          message: "Server IP:",
          validate: (input) => (input.trim() ? true : "Server IP is required"),
        },
        {
          type: "input",
          name: "username",
          message: "Username:",
          default: "root",
        },
        {
          type: "input",
          name: "port",
          message: "SSH Port:",
          default: "22",
          validate: (input) => {
            const port = parseInt(input);
            return port > 0 && port <= 65535
              ? true
              : "Port must be between 1 and 65535";
          },
        },
        {
          type: "list",
          name: "authMethod",
          message: "Authentication method:",
          choices: [
            { name: "Generate SSH Key (recommended)", value: "key" },
            { name: "Use existing SSH Key", value: "existing_key" },
            { name: "Password", value: "password" },
          ],
        },
        {
          type: "input",
          name: "keyPath",
          message: "SSH key path:",
          default: "~/.ssh/id_rsa",
          when: (answers) => answers.authMethod === "existing_key",
          validate: (input) => {
            const resolvedPath = input.startsWith("~")
              ? path.join(os.homedir(), input.slice(1))
              : path.resolve(input);
            return fs.existsSync(resolvedPath)
              ? true
              : "SSH key file does not exist";
          },
        },
        {
          type: "password",
          name: "password",
          message: "Password:",
          when: (answers) => answers.authMethod === "password",
        },
        {
          type: "password",
          name: "singPassword",
          message: "Sing-box password (optional, for shadowsocks):",
          default: "",
        },
        {
          type: "input",
          name: "xrayId",
          message: "Xray UUID (optional, for VLESS):",
          default: "",
        },
      ]);

      const serverName = answers.serverName.trim();
      const serverConfig = {
        ip: answers.ip.trim(),
        username: answers.username.trim(),
        port: parseInt(answers.port),
        createdAt: new Date().toISOString(),
        singPassword: answers.singPassword?.trim() || "",
        xrayId: answers.xrayId?.trim() || "",
      };

      if (answers.authMethod === "key") {
        console.log(chalk.blue("Generating SSH key pair..."));
        const keyInfo = await generateSSHKey(serverName);
        serverConfig.keyPath = keyInfo.privateKeyPath;
        serverConfig.publicKeyPath = keyInfo.publicKeyPath;

        // Ask if user wants to install key automatically
        const { installKey } = await inquirer.prompt([
          {
            type: "confirm",
            name: "installKey",
            message:
              "Would you like to automatically install the SSH key on the server?",
            default: true,
          },
        ]);

        if (installKey) {
          const { tempPassword } = await inquirer.prompt([
            {
              type: "password",
              name: "tempPassword",
              message: "Enter server password for key installation:",
            },
          ]);

          await installSSHKey(
            { ...serverConfig, password: tempPassword },
            keyInfo
          );
        }
      } else if (answers.authMethod === "existing_key") {
        // Resolve the SSH key path
        const keyPath = answers.keyPath.startsWith("~")
          ? path.join(os.homedir(), answers.keyPath.slice(1))
          : path.resolve(answers.keyPath);

        serverConfig.keyPath = keyPath;
        console.log(chalk.green(`Using existing SSH key: ${keyPath}`));
      } else {
        serverConfig.password = answers.password;
      }

      config.servers[serverName] = serverConfig;
      await saveConfig();

      console.log(chalk.green(`✅ Server '${serverName}' added successfully!`));
    } catch (error) {
      console.error(chalk.red("Error adding server:"), error.message);
      process.exit(1);
    }
  });

// Delete server command
program
  .command("delete")
  .description("Delete a server")
  .action(async () => {
    try {
      const serverNames = Object.keys(config.servers);

      if (serverNames.length === 0) {
        console.log(chalk.yellow("No servers found."));
        return;
      }

      const { serverName } = await inquirer.prompt([
        {
          type: "list",
          name: "serverName",
          message: "Select server to delete:",
          choices: serverNames,
        },
      ]);

      const { confirm } = await inquirer.prompt([
        {
          type: "confirm",
          name: "confirm",
          message: `Are you sure you want to delete server '${serverName}'?`,
          default: false,
        },
      ]);

      if (confirm) {
        const server = config.servers[serverName];

        // Remove SSH key files if they exist
        if (server.keyPath && fs.existsSync(server.keyPath)) {
          await fs.remove(server.keyPath);
        }
        if (server.publicKeyPath && fs.existsSync(server.publicKeyPath)) {
          await fs.remove(server.publicKeyPath);
        }

        delete config.servers[serverName];
        await saveConfig();

        console.log(
          chalk.green(`✅ Server '${serverName}' deleted successfully!`)
        );
      } else {
        console.log(chalk.yellow("Delete cancelled."));
      }
    } catch (error) {
      console.error(chalk.red("Error deleting server:"), error.message);
      process.exit(1);
    }
  });

// Update server command
program
  .command("update")
  .description("Update server configuration")
  .action(async () => {
    try {
      const serverNames = Object.keys(config.servers);

      if (serverNames.length === 0) {
        console.log(chalk.yellow("No servers found."));
        return;
      }

      const { serverName } = await inquirer.prompt([
        {
          type: "list",
          name: "serverName",
          message: "Select server to update:",
          choices: serverNames,
        },
      ]);

      const server = config.servers[serverName];

      // Ask which properties to update
      const { propertiesToUpdate } = await inquirer.prompt([
        {
          type: "checkbox",
          name: "propertiesToUpdate",
          message: "Select properties to update:",
          choices: [
            { name: "IP Address", value: "ip" },
            { name: "Username", value: "username" },
            { name: "SSH Port", value: "port" },
            { name: "Authentication", value: "auth" },
            { name: "Sing-box Password", value: "singPassword" },
            { name: "Xray UUID", value: "xrayId" },
            { name: "Proxy Port", value: "proxyPort" },
          ],
        },
      ]);

      if (propertiesToUpdate.length === 0) {
        console.log(chalk.yellow("No properties selected for update."));
        return;
      }

      const updatePrompts = [];

      if (propertiesToUpdate.includes("ip")) {
        updatePrompts.push({
          type: "input",
          name: "ip",
          message: "New IP address:",
          default: server.ip,
          validate: (input) => (input.trim() ? true : "IP address is required"),
        });
      }

      if (propertiesToUpdate.includes("username")) {
        updatePrompts.push({
          type: "input",
          name: "username",
          message: "New username:",
          default: server.username,
        });
      }

      if (propertiesToUpdate.includes("port")) {
        updatePrompts.push({
          type: "input",
          name: "port",
          message: "New SSH port:",
          default: server.port.toString(),
          validate: (input) => {
            const port = parseInt(input);
            return port > 0 && port <= 65535
              ? true
              : "Port must be between 1 and 65535";
          },
        });
      }

      if (propertiesToUpdate.includes("auth")) {
        updatePrompts.push({
          type: "list",
          name: "authMethod",
          message: "New authentication method:",
          choices: [
            { name: "Generate SSH Key", value: "key" },
            { name: "Use existing SSH Key", value: "existing_key" },
            { name: "Password", value: "password" },
          ],
        });

        updatePrompts.push({
          type: "input",
          name: "keyPath",
          message: "SSH key path:",
          default: "~/.ssh/id_rsa",
          when: (answers) => answers.authMethod === "existing_key",
          validate: (input) => {
            const resolvedPath = input.startsWith("~")
              ? path.join(os.homedir(), input.slice(1))
              : path.resolve(input);
            return fs.existsSync(resolvedPath)
              ? true
              : "SSH key file does not exist";
          },
        });

        updatePrompts.push({
          type: "password",
          name: "password",
          message: "New password:",
          when: (answers) => answers.authMethod === "password",
        });
      }

      if (propertiesToUpdate.includes("singPassword")) {
        updatePrompts.push({
          type: "password",
          name: "singPassword",
          message: "New Sing-box password:",
          default: server.singPassword || "",
        });
      }

      if (propertiesToUpdate.includes("xrayId")) {
        updatePrompts.push({
          type: "input",
          name: "xrayId",
          message: "New Xray UUID:",
          default: server.xrayId || "",
        });
      }

      if (propertiesToUpdate.includes("proxyPort")) {
        updatePrompts.push({
          type: "input",
          name: "proxyPort",
          message: "New proxy port:",
          default: server.proxyPort ? server.proxyPort.toString() : "8090",
          validate: (input) => {
            const port = parseInt(input);
            return port > 0 && port <= 65535
              ? true
              : "Port must be between 1 and 65535";
          },
        });
      }

      const updates = await inquirer.prompt(updatePrompts);

      // Apply updates
      if (updates.ip) server.ip = updates.ip.trim();
      if (updates.username) server.username = updates.username.trim();
      if (updates.port) server.port = parseInt(updates.port);
      if (updates.singPassword !== undefined)
        server.singPassword = updates.singPassword.trim();
      if (updates.xrayId !== undefined) server.xrayId = updates.xrayId.trim();
      if (updates.proxyPort) server.proxyPort = parseInt(updates.proxyPort);
      if (updates.xrayBasePort) {
        server.xrayPorts = {
          socks: parseInt(updates.xrayBasePort),
          http: parseInt(updates.xrayBasePort) + 1,
        };
      }

      // Handle authentication updates
      if (updates.authMethod) {
        if (updates.authMethod === "key") {
          console.log(chalk.blue("Generating new SSH key pair..."));
          const keyInfo = await generateSSHKey(serverName);
          server.keyPath = keyInfo.privateKeyPath;
          server.publicKeyPath = keyInfo.publicKeyPath;
          delete server.password;

          const { installKey } = await inquirer.prompt([
            {
              type: "confirm",
              name: "installKey",
              message:
                "Would you like to automatically install the SSH key on the server?",
              default: true,
            },
          ]);

          if (installKey) {
            const { tempPassword } = await inquirer.prompt([
              {
                type: "password",
                name: "tempPassword",
                message: "Enter server password for key installation:",
              },
            ]);

            await installSSHKey({ ...server, password: tempPassword }, keyInfo);
          }
        } else if (updates.authMethod === "existing_key") {
          const keyPath = updates.keyPath.startsWith("~")
            ? path.join(os.homedir(), updates.keyPath.slice(1))
            : path.resolve(updates.keyPath);

          server.keyPath = keyPath;
          delete server.password;
          console.log(chalk.green(`Using existing SSH key: ${keyPath}`));
        } else if (updates.authMethod === "password") {
          server.password = updates.password;
          delete server.keyPath;
          delete server.publicKeyPath;
        }
      }

      server.updatedAt = new Date().toISOString();
      await saveConfig();

      console.log(
        chalk.green(`✅ Server '${serverName}' updated successfully!`)
      );
    } catch (error) {
      console.error(chalk.red("Error updating server:"), error.message);
      process.exit(1);
    }
  });

// List servers command
program
  .command("ls")
  .description("List all servers")
  .action(() => {
    const serverNames = Object.keys(config.servers);

    if (serverNames.length === 0) {
      console.log(
        chalk.yellow('No servers found. Use "bun sm.js add" to add a server.')
      );
      return;
    }

    const table = new Table({
      head: [
        "Name",
        "IP",
        "Username",
        "Port",
        "Auth",
        "Sing-box",
        "Xray",
        "Created",
      ].map((h) => chalk.cyan(h)),
      style: { head: [], border: [] },
    });

    serverNames.forEach((name) => {
      const server = config.servers[name];
      table.push([
        chalk.white(name),
        chalk.yellow(server.ip),
        chalk.blue(server.username),
        chalk.magenta(server.port),
        server.keyPath ? chalk.green("SSH Key") : chalk.red("Password"),
        server.singPassword ? chalk.green("✓") : chalk.gray("✗"),
        server.xrayId ? chalk.green("✓") : chalk.gray("✗"),
        server.createdAt
          ? new Date(server.createdAt).toLocaleDateString()
          : "Unknown",
      ]);
    });

    console.log(table.toString());
  });

// SSH command
program
  .command("ssh")
  .description("Connect to server via SSH")
  .argument("<serverName>", "Server name")
  .action((serverName) => {
    const server = getServer(serverName);

    console.log(
      chalk.blue(
        `Connecting to ${server.username}@${server.ip}:${server.port}...`
      )
    );

    const sshProcess = createSSHConnection(server);

    sshProcess.on("error", (error) => {
      console.error(chalk.red("SSH connection error:"), error.message);
      process.exit(1);
    });

    sshProcess.on("close", (code) => {
      console.log(chalk.blue(`SSH connection closed with code ${code}`));
    });
  });

// SOCKS5 command
program
  .command("socks5")
  .description("Create SOCKS5 proxy tunnel")
  .argument("<serverName>", "Server name")
  .option("-p, --port <port>", "Local port for SOCKS5 proxy")
  .action(async (serverName, options) => {
    const server = getServer(serverName);
    let localPort;

    // Check if port is provided via option
    if (options.port) {
      localPort = parseInt(options.port);
    } else if (server.proxyPort) {
      // Use stored port preference
      localPort = server.proxyPort;
    } else {
      // Ask for port and store preference
      const { port } = await inquirer.prompt([
        {
          type: "input",
          name: "port",
          message: "Enter local port for SOCKS5 proxy:",
          default: "8090",
          validate: (input) => {
            const port = parseInt(input);
            return port > 0 && port <= 65535
              ? true
              : "Port must be between 1 and 65535";
          },
        },
      ]);

      localPort = parseInt(port);

      // Store port preference
      server.proxyPort = localPort;
      await saveConfig();
    }

    console.log(chalk.blue(`Creating SOCKS5 proxy tunnel...`));
    console.log(chalk.green(`SOCKS5 proxy will be available at:`));
    console.log(chalk.cyan(`  socks5://127.0.0.1:${localPort}`));

    // Try to get network IP
    try {
      const networkInterface = os.networkInterfaces();
      const networkIP = Object.values(networkInterface)
        .flat()
        .find((iface) => iface.family === "IPv4" && !iface.internal)?.address;

      if (networkIP) {
        console.log(chalk.cyan(`  socks5://${networkIP}:${localPort}`));
      }
    } catch (error) {
      // Ignore network IP detection errors
    }

    const sshProcess = createSSHConnection(server, { dynamicPort: localPort });

    sshProcess.on("error", (error) => {
      console.error(chalk.red("SOCKS5 tunnel error:"), error.message);
      process.exit(1);
    });

    sshProcess.on("close", (code) => {
      console.log(chalk.blue(`SOCKS5 tunnel closed with code ${code}`));
    });
  });

// Sing-box command
program
  .command("sing-box")
  .description("Start sing-box with server configuration")
  .argument("<serverName>", "Server name")
  .action(async (serverName) => {
    const server = getServer(serverName);

    // Check if sing-box is installed
    try {
      await execAsync("which sing-box");
    } catch (error) {
      console.error(chalk.red("Error: sing-box is not installed."));
      console.log(chalk.blue("Please install sing-box first:"));
      console.log(chalk.cyan("  https://sing-box.sagernet.org/installation/"));
      process.exit(1);
    }

    // Get sing-box password
    let singPassword = server.singPassword;

    if (!singPassword) {
      console.log(chalk.red("No sing-box password found for this server."));
      console.log(chalk.blue("Please set it first using: assh update"));
      process.exit(1);
    }

    // Create temporary config file
    const tempConfigPath = path.join(
      os.tmpdir(),
      `assh_${serverName}_sing_${Date.now()}.json`
    );
    const singConfig = {
      experimental: {
        clash_api: {
          external_controller: "127.0.0.1:9090",
        },
      },
      log: {
        level: "error",
      },
      dns: {
        fakeip: {
          enabled: true,
          inet4_range: "198.18.0.0/15",
          inet6_range: "fc00::/18",
        },
        servers: [
          {
            tag: "google",
            address: "tls://94.140.14.14",
            detour: "proxy",
          },
          {
            tag: "tx",
            address: "1.1.1.1",
            detour: "direct",
          },
          {
            tag: "fakeip",
            address: "fakeip",
          },
          {
            tag: "block",
            address: "rcode://success",
          },
        ],
        rules: [
          {
            outbound: "any",
            server: "google",
          },
          {
            clash_mode: "global",
            server: "google",
          },
        ],
        final: "google",
        independent_cache: false,
        strategy: "prefer_ipv4",
      },
      inbounds: [
        {
          domain_strategy: "prefer_ipv4",
          endpoint_independent_nat: true,
          address: ["172.16.0.1/30"],
          mtu: 1500,
          sniff: true,
          sniff_override_destination: true,
          auto_route: true,
          strict_route: true,
          type: "tun",
        },
      ],
      outbounds: [
        {
          type: "direct",
          tag: "direct",
        },
        {
          type: "dns",
          tag: "dns-out",
        },
        {
          tag: "proxy",
          type: "shadowsocks",
          server: server.ip,
          server_port: 8080,
          method: "2022-blake3-aes-128-gcm",
          password: singPassword,
        },
      ],
      route: {
        auto_detect_interface: true,
        final: "proxy",
        rules: [
          {
            domain_suffix: [".ir"],
            outbound: "direct",
          },
          {
            type: "logical",
            mode: "or",
            rules: [
              {
                port: 53,
              },
              {
                protocol: "dns",
              },
            ],
            outbound: "dns-out",
          },
          {
            ip_is_private: true,
            outbound: "direct",
          },
        ],
      },
    };

    try {
      await fs.writeJson(tempConfigPath, singConfig, { spaces: 2 });

      // Track temp file for cleanup
      tempFiles.add(tempConfigPath);

      console.log(chalk.blue("Starting sing-box..."));
      console.log(
        chalk.yellow("Note: This requires sudo privileges for TUN interface.")
      );

      const singProcess = spawn(
        "sudo",
        ["sing-box", "run", "-c", tempConfigPath],
        { stdio: "inherit" }
      );

      singProcess.on("error", (error) => {
        console.error(chalk.red("Sing-box error:"), error.message);
        // Cleanup temp file on error
        tempFiles.delete(tempConfigPath);
        try {
          fs.removeSync(tempConfigPath);
        } catch (e) {
          // Ignore cleanup errors
        }
        process.exit(1);
      });

      singProcess.on("close", (code) => {
        console.log(chalk.blue(`Sing-box closed with code ${code}`));
        // Cleanup temp file on close
        tempFiles.delete(tempConfigPath);
        try {
          fs.removeSync(tempConfigPath);
        } catch (e) {
          // Ignore cleanup errors
        }
      });
    } catch (error) {
      console.error(chalk.red("Error starting sing-box:"), error.message);
      process.exit(1);
    }
  });

// Xray command
program
  .command("xray")
  .description("Start Xray with server configuration")
  .argument("<serverName>", "Server name")
  .action(async (serverName) => {
    const server = getServer(serverName);

    // Check if xray is installed
    try {
      await execAsync("which xray");
    } catch (error) {
      console.error(chalk.red("Error: xray is not installed."));
      console.log(chalk.blue("Please install xray first:"));
      console.log(
        chalk.cyan("  https://xtls.github.io/en/document/install.html")
      );
      process.exit(1);
    }

    // Get xray UUID
    let xrayId = server.xrayId;

    if (!xrayId) {
      console.log(chalk.red("No Xray UUID found for this server."));
      console.log(chalk.blue("Please set it first using: assh update"));
      process.exit(1);
    }

    // Get port preferences
    let socksPort, httpPort;

    if (server.proxyPort) {
      socksPort = server.proxyPort;
      httpPort = server.proxyPort + 1;
    } else {
      const { mixedPort } = await inquirer.prompt([
        {
          type: "input",
          name: "mixedPort",
          message: "Enter base port for SOCKS5 and HTTP proxy:",
          default: "8090",
          validate: (input) => {
            const port = parseInt(input);
            return port > 0 && port <= 65533
              ? true
              : "Port must be between 1 and 65533";
          },
        },
      ]);

      socksPort = parseInt(mixedPort);
      httpPort = socksPort + 1;

      // Store port preferences
      server.proxyPort = socksPort;
      await saveConfig();
    }

    const xrayConfig = {
      log: {
        loglevel: "none",
      },
      outbounds: [
        {
          protocol: "vless",
          settings: {
            vnext: [
              {
                address: server.ip,
                port: 443,
                users: [
                  {
                    id: xrayId,
                    alterId: 0,
                    encryption: "none",
                  },
                ],
              },
            ],
          },
        },
      ],
      inbounds: [
        {
          port: socksPort,
          protocol: "socks",
          settings: {
            auth: "noauth",
            udp: true,
          },
        },
        {
          port: httpPort,
          protocol: "http",
        },
      ],
    };

    try {
      console.log(chalk.blue("Starting Xray..."));
      console.log(
        chalk.green(
          `SOCKS5 proxy available at: socks5://127.0.0.1:${socksPort}`
        )
      );
      console.log(
        chalk.green(`HTTP proxy available at: http://127.0.0.1:${httpPort}`)
      );

      const xrayProcess = spawn("xray", ["run"], {
        stdio: ["pipe", "inherit", "inherit"],
        input: JSON.stringify(xrayConfig),
      });

      xrayProcess.stdin.write(JSON.stringify(xrayConfig));
      xrayProcess.stdin.end();

      xrayProcess.on("error", (error) => {
        console.error(chalk.red("Xray error:"), error.message);
        process.exit(1);
      });

      xrayProcess.on("close", (code) => {
        console.log(chalk.blue(`Xray closed with code ${code}`));
      });
    } catch (error) {
      console.error(chalk.red("Error starting Xray:"), error.message);
      process.exit(1);
    }
  });

// Ping command
program
  .command("ping")
  .description("Ping server to check connectivity")
  .argument("<serverName>", "Server name")
  .action(async (serverName) => {
    const server = getServer(serverName);

    console.log(chalk.blue(`Pinging ${server.ip}...`));

    try {
      const pingCommand =
        process.platform === "win32"
          ? `ping -n 4 ${server.ip}`
          : `ping -c 4 ${server.ip}`;

      const { stdout } = await execAsync(pingCommand);
      console.log(stdout);

      console.log(chalk.green(`✅ Server ${server.ip} is reachable`));
    } catch (error) {
      console.error(chalk.red(`❌ Failed to ping ${server.ip}`));
      console.error(chalk.red(error.message));
      process.exit(1);
    }
  });

// Parse command line arguments
program.parse();
