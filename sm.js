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
      ]);

      const serverName = answers.serverName.trim();
      const serverConfig = {
        ip: answers.ip.trim(),
        username: answers.username.trim(),
        port: parseInt(answers.port),
        createdAt: new Date().toISOString(),
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
      head: ["Name", "IP", "Username", "Port", "Auth", "Created"].map((h) =>
        chalk.cyan(h)
      ),
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
  .option(
    "-p, --port <port>",
    "Local port for SOCKS5 proxy",
    config.settings.defaultLocalPort.toString()
  )
  .action((serverName, options) => {
    const server = getServer(serverName);
    const localPort = parseInt(options.port);

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
    const { singPassword } = await inquirer.prompt([
      {
        type: "password",
        name: "singPassword",
        message: "Enter sing-box password for shadowsocks:",
      },
    ]);

    // Create temporary config file
    const tempConfigPath = path.join(
      CONFIG_DIR,
      `${serverName}_sing_temp.json`
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

      console.log(chalk.blue("Starting sing-box..."));
      console.log(
        chalk.yellow("Note: This requires sudo privileges for TUN interface.")
      );

      const singProcess = spawn(
        "sudo",
        ["sing-box", "run", "-c", tempConfigPath],
        { stdio: "inherit" }
      );

      // Cleanup temp file on exit
      process.on("exit", () => {
        try {
          fs.removeSync(tempConfigPath);
        } catch (e) {
          // Ignore cleanup errors
        }
      });

      singProcess.on("error", (error) => {
        console.error(chalk.red("Sing-box error:"), error.message);
        process.exit(1);
      });

      singProcess.on("close", (code) => {
        console.log(chalk.blue(`Sing-box closed with code ${code}`));
        // Cleanup temp file
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
    const { xrayId } = await inquirer.prompt([
      {
        type: "input",
        name: "xrayId",
        message: "Enter Xray UUID:",
        validate: (input) => (input.trim() ? true : "Xray UUID is required"),
      },
    ]);

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
          port: 8090,
          protocol: "socks",
          settings: {
            auth: "noauth",
            udp: true,
          },
        },
        {
          port: 8091,
          protocol: "http",
        },
      ],
    };

    try {
      console.log(chalk.blue("Starting Xray..."));
      console.log(
        chalk.green("SOCKS5 proxy available at: socks5://127.0.0.1:8090")
      );
      console.log(
        chalk.green("HTTP proxy available at: http://127.0.0.1:8091")
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
