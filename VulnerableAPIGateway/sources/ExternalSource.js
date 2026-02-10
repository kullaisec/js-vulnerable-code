/**
 * External Source - Data from external APIs and services
 * Data from external sources that may be attacker-controlled
 */

const axios = require('axios');
const dns = require('dns');
const net = require('net');

/**
 * Custom Source: External API Response
 * Data received from external APIs is tainted if URL is user-controlled
 */
class ExternalApiSource {

    // SOURCE: Fetch data from user-specified URL (SSRF vector)
    static async fetchFromUrl(url) {
        const response = await axios.get(url, {
            timeout: 10000,
            maxRedirects: 5  // VULNERABLE: Follows redirects
        });

        return {
            data: response.data,           // TAINTED: External response
            headers: response.headers,     // TAINTED: Response headers
            status: response.status
        };
    }

    // SOURCE: Fetch with custom headers (header injection possible)
    static async fetchWithHeaders(url, customHeaders) {
        const response = await axios.get(url, {
            headers: customHeaders,  // VULNERABLE: User-controlled headers
            timeout: 10000
        });

        return response.data;
    }

    // SOURCE: POST to external URL with user data
    static async postToUrl(url, data) {
        const response = await axios.post(url, data, {
            timeout: 10000
        });

        return response.data;
    }

    // SOURCE: Webhook callback - data from external system
    static parseWebhookPayload(payload, signature) {
        // VULNERABLE: No signature validation by default
        return {
            event: payload.event,
            data: payload.data,
            timestamp: payload.timestamp,
            source: payload.source
        };
    }
}

/**
 * Custom Source: DNS Resolution Results
 * DNS responses can be manipulated
 */
class DnsSource {

    // SOURCE: Resolve hostname to IP
    static async resolveHostname(hostname) {
        return new Promise((resolve, reject) => {
            dns.lookup(hostname, (err, address) => {
                if (err) reject(err);
                else resolve(address);  // TAINTED: Could be poisoned DNS
            });
        });
    }

    // SOURCE: Reverse DNS lookup
    static async reverseLookup(ip) {
        return new Promise((resolve, reject) => {
            dns.reverse(ip, (err, hostnames) => {
                if (err) reject(err);
                else resolve(hostnames);  // TAINTED: Reverse DNS response
            });
        });
    }

    // SOURCE: TXT record lookup (often contains configuration data)
    static async getTxtRecords(domain) {
        return new Promise((resolve, reject) => {
            dns.resolveTxt(domain, (err, records) => {
                if (err) reject(err);
                else resolve(records);  // TAINTED: TXT records
            });
        });
    }
}

/**
 * Custom Source: Socket Data
 * Data received from network sockets
 */
class SocketSource {

    // SOURCE: Read data from TCP socket
    static async readFromSocket(host, port, message) {
        return new Promise((resolve, reject) => {
            const client = new net.Socket();
            let response = '';

            client.connect(port, host, () => {
                client.write(message);
            });

            client.on('data', (data) => {
                response += data.toString();  // TAINTED: Socket response
            });

            client.on('close', () => {
                resolve(response);
            });

            client.on('error', reject);
        });
    }
}

/**
 * Custom Source: Environment Variables
 * Some env vars may be attacker-influenced
 */
class EnvironmentSource {

    // SOURCE: Get environment variable
    static getEnvVar(name) {
        return process.env[name];  // TAINTED: May be externally controlled
    }

    // SOURCE: Get all matching env vars
    static getEnvVarsMatching(pattern) {
        const regex = new RegExp(pattern);
        const matching = {};

        for (const [key, value] of Object.entries(process.env)) {
            if (regex.test(key)) {
                matching[key] = value;
            }
        }

        return matching;  // TAINTED
    }
}

/**
 * Custom Source: File System
 * Data read from files that may be externally controlled
 */
class FileSource {

    // SOURCE: Read file contents
    static async readFile(filePath) {
        const fs = require('fs').promises;
        const content = await fs.readFile(filePath, 'utf8');
        return content;  // TAINTED: File contents
    }

    // SOURCE: Parse JSON file
    static async readJsonFile(filePath) {
        const content = await this.readFile(filePath);
        return JSON.parse(content);  // TAINTED: Parsed JSON
    }

    // SOURCE: Read directory listing
    static async listDirectory(dirPath) {
        const fs = require('fs').promises;
        const entries = await fs.readdir(dirPath);
        return entries;  // TAINTED: Directory contents
    }
}

module.exports = {
    ExternalApiSource,
    DnsSource,
    SocketSource,
    EnvironmentSource,
    FileSource
};
