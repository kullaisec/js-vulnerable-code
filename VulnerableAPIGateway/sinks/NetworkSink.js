/**
 * Network Sink - SSRF and Network-based Vulnerabilities
 * Server-Side Request Forgery and related network attacks
 */

const axios = require('axios');
const http = require('http');
const https = require('https');
const net = require('net');
const dns = require('dns');
const { URL } = require('url');

class SsrfSink {

    /**
     * SINK: Basic SSRF via axios
     * User-controlled URL with no validation
     */
    static async fetchUrl(url) {
        // VULNERABLE: No URL validation
        const response = await axios.get(url);
        return response.data;
    }

    /**
     * SINK: SSRF with POST data
     */
    static async postToUrl(url, data) {
        // VULNERABLE: URL and data from user
        const response = await axios.post(url, data);
        return response.data;
    }

    /**
     * SINK: SSRF via URL construction
     */
    static async fetchFromService(serviceHost, endpoint) {
        // VULNERABLE: Host and endpoint user-controlled
        const url = `http://${serviceHost}/${endpoint}`;
        const response = await axios.get(url);
        return response.data;
    }

    /**
     * SINK: SSRF with redirect following
     */
    static async fetchWithRedirects(url) {
        // VULNERABLE: Follows redirects to internal hosts
        const response = await axios.get(url, {
            maxRedirects: 10,
            validateStatus: () => true
        });
        return response;
    }

    /**
     * SINK: SSRF via native http module
     */
    static fetchNative(url) {
        return new Promise((resolve, reject) => {
            // VULNERABLE: Direct http.get with user URL
            const req = http.get(url, (res) => {
                let data = '';
                res.on('data', chunk => data += chunk);
                res.on('end', () => resolve(data));
            });
            req.on('error', reject);
        });
    }

    /**
     * SINK: SSRF with authentication bypass
     */
    static async fetchWithAuth(url, authHeader) {
        // VULNERABLE: Can leak auth to attacker server
        const response = await axios.get(url, {
            headers: { 'Authorization': authHeader }
        });
        return response.data;
    }

    /**
     * SINK: SSRF in image/file processing
     */
    static async fetchRemoteImage(imageUrl) {
        // VULNERABLE: Common in image processing
        const response = await axios.get(imageUrl, {
            responseType: 'arraybuffer'
        });
        return Buffer.from(response.data);
    }

    /**
     * SINK: SSRF via URL parser bypass
     */
    static async fetchParsedUrl(userUrl) {
        // VULNERABLE: URL parsing can be bypassed
        const parsed = new URL(userUrl);
        const target = `${parsed.protocol}//${parsed.host}${parsed.pathname}`;
        return await axios.get(target);
    }

    /**
     * SINK: SSRF in webhook/callback URL
     */
    static async sendWebhook(callbackUrl, payload) {
        // VULNERABLE: Webhook to user-specified URL
        const response = await axios.post(callbackUrl, payload, {
            headers: { 'Content-Type': 'application/json' }
        });
        return response.status;
    }

    /**
     * SINK: SSRF via DNS rebinding susceptible code
     */
    static async fetchWithDnsCheck(hostname) {
        // VULNERABLE: Time-of-check to time-of-use (TOCTOU)
        const ip = await this.resolveHostname(hostname);

        // Check if internal (this check can be bypassed via DNS rebinding)
        if (this.isInternalIp(ip)) {
            throw new Error('Internal IP not allowed');
        }

        // By the time we make the request, DNS could resolve to different IP
        const response = await axios.get(`http://${hostname}/`);
        return response.data;
    }

    static resolveHostname(hostname) {
        return new Promise((resolve, reject) => {
            dns.lookup(hostname, (err, address) => {
                if (err) reject(err);
                else resolve(address);
            });
        });
    }

    static isInternalIp(ip) {
        // Simple check - can be bypassed with IPv6, decimal IPs, etc.
        return ip.startsWith('10.') ||
               ip.startsWith('192.168.') ||
               ip.startsWith('172.') ||
               ip === '127.0.0.1';
    }
}

/**
 * Custom Sink: TCP/Socket Connection
 */
class SocketSink {

    /**
     * SINK: Direct TCP connection to user-specified host
     */
    static connectToHost(host, port, data) {
        return new Promise((resolve, reject) => {
            const client = new net.Socket();
            let response = '';

            // VULNERABLE: Connect to arbitrary host:port
            client.connect(port, host, () => {
                client.write(data);
            });

            client.on('data', (chunk) => response += chunk);
            client.on('close', () => resolve(response));
            client.on('error', reject);
        });
    }

    /**
     * SINK: SMTP relay
     */
    static async sendEmail(smtpHost, from, to, message) {
        // VULNERABLE: Connect to user-specified SMTP
        const response = await this.connectToHost(smtpHost, 25,
            `HELO localhost\r\n` +
            `MAIL FROM:<${from}>\r\n` +
            `RCPT TO:<${to}>\r\n` +
            `DATA\r\n${message}\r\n.\r\n` +
            `QUIT\r\n`
        );
        return response;
    }
}

/**
 * Custom Sink: DNS Operations
 */
class DnsSink {

    /**
     * SINK: DNS exfiltration via lookup
     */
    static async exfiltrateViaDns(data, domain) {
        // VULNERABLE: Data in subdomain
        const encoded = Buffer.from(data).toString('hex');
        const hostname = `${encoded}.${domain}`;

        return new Promise((resolve, reject) => {
            dns.lookup(hostname, (err, address) => {
                if (err) reject(err);
                else resolve(address);
            });
        });
    }

    /**
     * SINK: DNS TXT record query with user domain
     */
    static async queryTxtRecord(domain) {
        return new Promise((resolve, reject) => {
            // VULNERABLE: Query user-controlled domain
            dns.resolveTxt(domain, (err, records) => {
                if (err) reject(err);
                else resolve(records);
            });
        });
    }
}

module.exports = {
    SsrfSink,
    SocketSink,
    DnsSink
};
