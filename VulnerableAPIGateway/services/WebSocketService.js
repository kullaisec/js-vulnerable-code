/**
 * WebSocket Service - Real-time Communication Vulnerabilities
 * Custom source: WebSocket messages
 * Demonstrates cross-file taint from WebSocket to various sinks
 */

const { CommandSink } = require('../sinks/CommandSink');
const { SsrfSink } = require('../sinks/NetworkSink');
const { PathTraversalSink } = require('../sinks/FileSink');
const { TemplateSink } = require('../sinks/TemplateSink');
const { QueryBuilder, AuditLogger } = require('../config/database');

class WebSocketService {
    constructor(wss) {
        this.wss = wss;
        this.clients = new Map();
    }

    initialize() {
        this.wss.on('connection', (ws, req) => {
            // VULNERABLE: No origin validation
            const clientId = this.extractClientId(req);
            this.clients.set(clientId, ws);

            ws.on('message', async (message) => {
                try {
                    // SOURCE: WebSocket message is user-controlled
                    const data = JSON.parse(message);
                    await this.handleMessage(ws, data);
                } catch (error) {
                    ws.send(JSON.stringify({ error: error.message }));
                }
            });

            ws.on('close', () => {
                this.clients.delete(clientId);
            });
        });
    }

    // SOURCE: Extract client ID from request (tainted)
    extractClientId(req) {
        // VULNERABLE: Client ID from query string
        const url = new URL(req.url, 'ws://localhost');
        return url.searchParams.get('clientId') || 'anonymous';
    }

    // Handle incoming WebSocket messages (tainted data)
    async handleMessage(ws, data) {
        const { action, payload } = data;

        switch (action) {
            case 'execute_command':
                // SINK: Command injection via WebSocket
                await this.executeRemoteCommand(ws, payload);
                break;

            case 'fetch_url':
                // SINK: SSRF via WebSocket
                await this.fetchRemoteUrl(ws, payload);
                break;

            case 'read_file':
                // SINK: Path traversal via WebSocket
                await this.readRemoteFile(ws, payload);
                break;

            case 'render_template':
                // SINK: SSTI via WebSocket
                await this.renderTemplate(ws, payload);
                break;

            case 'query_database':
                // SINK: SQL injection via WebSocket
                await this.queryDatabase(ws, payload);
                break;

            case 'broadcast':
                // SINK: Stored XSS via broadcast
                this.broadcastMessage(payload);
                break;

            default:
                ws.send(JSON.stringify({ error: 'Unknown action' }));
        }
    }

    // Cross-file: WebSocket source -> Command sink
    async executeRemoteCommand(ws, payload) {
        const { command, args } = payload;

        // SINK: Command injection (cross-file from WebSocket)
        const result = await CommandSink.executeWithArgs(command, args);

        ws.send(JSON.stringify({ result }));
    }

    // Cross-file: WebSocket source -> SSRF sink
    async fetchRemoteUrl(ws, payload) {
        const { url, headers } = payload;

        // SINK: SSRF (cross-file from WebSocket)
        const result = await SsrfSink.fetchUrl(url);

        ws.send(JSON.stringify({ data: result }));
    }

    // Cross-file: WebSocket source -> File sink
    async readRemoteFile(ws, payload) {
        const { filename } = payload;

        // SINK: Path traversal (cross-file from WebSocket)
        const content = PathTraversalSink.readFile(filename);

        ws.send(JSON.stringify({ content }));
    }

    // Cross-file: WebSocket source -> Template sink
    async renderTemplate(ws, payload) {
        const { template, context } = payload;

        // SINK: SSTI (cross-file from WebSocket)
        const rendered = TemplateSink.renderNunjucks(template, context);

        ws.send(JSON.stringify({ html: rendered }));
    }

    // Cross-file: WebSocket source -> SQL sink
    async queryDatabase(ws, payload) {
        const { table, field, value } = payload;

        // SINK: SQL injection (cross-file from WebSocket)
        const queryBuilder = new QueryBuilder(global.dbConnection);
        const results = await queryBuilder.findByField(table, field, value);

        ws.send(JSON.stringify({ results }));
    }

    // Broadcast message to all clients (stored XSS)
    broadcastMessage(payload) {
        const { message, sender } = payload;

        // VULNERABLE: No sanitization, XSS when rendered
        const broadcastData = JSON.stringify({
            type: 'broadcast',
            sender: sender,  // TAINTED
            message: message,  // TAINTED
            timestamp: Date.now()
        });

        for (const client of this.clients.values()) {
            client.send(broadcastData);
        }
    }

    // Send to specific client (XSS via client ID)
    sendToClient(clientId, message) {
        // VULNERABLE: clientId could be XSS payload
        const client = this.clients.get(clientId);
        if (client) {
            client.send(JSON.stringify(message));
        }
    }
}

/**
 * WebSocket Event Handler - Additional attack vectors
 */
class WebSocketEventHandler {

    // Multi-chain: WebSocket -> Database -> File
    static async processAndStore(ws, payload, dbConnection) {
        const { userId, data, exportPath } = payload;

        // Step 1: SQL injection - store user data
        const auditLogger = new AuditLogger(dbConnection);
        await auditLogger.logAction(userId, 'data_received', JSON.stringify(data));

        // Step 2: Retrieve stored data
        const logs = await auditLogger.getLogsForUser(userId);

        // Step 3: Path traversal - write to file
        PathTraversalSink.writeFile(exportPath, JSON.stringify(logs));

        ws.send(JSON.stringify({ status: 'processed' }));
    }

    // Multi-chain: WebSocket -> SSRF -> Command
    static async fetchAndExecute(ws, payload) {
        const { configUrl, defaultCommand } = payload;

        // Step 1: SSRF - fetch remote config
        const config = await SsrfSink.fetchUrl(configUrl);

        // Step 2: Command injection with fetched config
        const command = config.command || defaultCommand;
        const result = await CommandSink.executeCommand(command);

        ws.send(JSON.stringify({ result }));
    }

    // Multi-chain: WebSocket -> Template -> Response (stored XSS)
    static async renderAndBroadcast(wss, payload) {
        const { template, context } = payload;

        // Step 1: Template injection
        const rendered = TemplateSink.renderEjs(template, context);

        // Step 2: Broadcast to all clients (stored XSS propagation)
        for (const client of wss.clients) {
            client.send(JSON.stringify({
                type: 'rendered_content',
                html: rendered  // TAINTED HTML
            }));
        }
    }
}

module.exports = WebSocketService;
module.exports.WebSocketEventHandler = WebSocketEventHandler;
