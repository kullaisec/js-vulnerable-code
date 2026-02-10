/**
 * Admin Routes - Privileged Endpoints with Escalated Vulnerabilities
 * Demonstrates vulnerabilities in admin functionality
 */

const express = require('express');
const router = express.Router();

const { CommandSink, DockerSink, SshSink } = require('../sinks/CommandSink');
const { PathTraversalSink, FileUploadSink, LogSink } = require('../sinks/FileSink');
const { SsrfSink, SocketSink, DnsSink } = require('../sinks/NetworkSink');
const { TemplateSink, XssSink } = require('../sinks/TemplateSink');
const { QueryBuilder, AuditLogger } = require('../config/database');

/**
 * MULTI-CHAIN: Admin Panel XSS via User Data
 * Source: Database (stored) -> XssSink
 */
router.get('/dashboard', async (req, res) => {
    try {
        // Fetch user list (contains tainted stored data)
        const queryBuilder = new QueryBuilder(global.dbConnection);
        const users = await queryBuilder.findByField('users', '1', '1');  // Get all

        // SINK: Stored XSS via user display
        let html = '<html><body><h1>Admin Dashboard</h1><ul>';
        for (const user of users) {
            // SINK: XSS via stored user data
            html += `<li>User: ${user.name} - Email: ${user.email} - Bio: ${user.bio}</li>`;
        }
        html += '</ul></body></html>';

        res.send(html);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: System Management with Command Injection
 * Source: req.body -> CommandSink (multiple vectors)
 */
router.post('/system/manage', async (req, res) => {
    try {
        const { action, serviceName, configPath, logFile } = req.body;

        let result;

        switch (action) {
            case 'restart':
                // SINK: Command injection in service management
                result = await CommandSink.runSystemCommand('restart', serviceName);
                break;

            case 'reload-config':
                // SINK: Path traversal + command injection
                result = await CommandSink.executeWithArgs('cat', configPath);
                break;

            case 'view-logs':
                // SINK: Command injection in log viewing
                result = await CommandSink.executeWithArgs('tail -100', logFile);
                break;

            case 'clear-cache':
                // SINK: Command injection
                result = await CommandSink.executeCommand(`rm -rf /var/cache/${serviceName}/*`);
                break;

            default:
                return res.status(400).json({ error: 'Unknown action' });
        }

        res.json({ result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: Container Management
 * Source: req.body -> DockerSink
 */
router.post('/containers/manage', async (req, res) => {
    try {
        const { action, containerId, image, command, dockerfile } = req.body;

        let result;

        switch (action) {
            case 'exec':
                // SINK: Docker exec command injection
                result = await DockerSink.dockerExec(containerId, command);
                break;

            case 'run':
                // SINK: Docker run with arbitrary image
                result = await DockerSink.dockerRun(image, command);
                break;

            case 'build':
                // SINK: Docker build with arbitrary Dockerfile
                result = await DockerSink.dockerBuild(dockerfile, image);
                break;

            default:
                return res.status(400).json({ error: 'Unknown action' });
        }

        res.json({ output: result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: Remote Server Management via SSH
 * Source: req.body -> SshSink
 */
router.post('/servers/ssh', async (req, res) => {
    try {
        const { host, user, command, localPath, remotePath } = req.body;

        let result;

        if (localPath && remotePath) {
            // SINK: SCP path traversal + command injection
            result = await SshSink.scpTransfer(localPath, `${user}@${host}`, remotePath);
        } else {
            // SINK: SSH command injection
            result = await SshSink.sshExecute(host, user, command);
        }

        res.json({ output: result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: Database Administration with SQL Injection
 * Source: req.body -> QueryBuilder
 */
router.post('/database/query', async (req, res) => {
    try {
        const { table, conditions, orderBy, orderDir, rawQuery } = req.body;

        const queryBuilder = new QueryBuilder(global.dbConnection);

        let results;

        if (rawQuery) {
            // SINK: Direct SQL injection via raw query
            const [rows] = await global.dbConnection.execute(rawQuery);
            results = rows;
        } else {
            // SINK: SQL injection via dynamic query
            results = await queryBuilder.dynamicQuery(table, conditions);
        }

        res.json({ results });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: File System Management
 * Source: req.body -> PathTraversalSink
 */
router.post('/filesystem/manage', async (req, res) => {
    try {
        const { action, path, content, destination } = req.body;

        let result;

        switch (action) {
            case 'read':
                // SINK: Arbitrary file read
                result = PathTraversalSink.readFile(path);
                break;

            case 'write':
                // SINK: Arbitrary file write
                result = PathTraversalSink.writeFile(path, content);
                break;

            case 'delete':
                // SINK: Arbitrary file delete
                result = PathTraversalSink.deleteFile(path);
                break;

            case 'copy':
                // SINK: Arbitrary file copy
                result = PathTraversalSink.copyFile(path, destination);
                break;

            case 'move':
                // SINK: Arbitrary file move
                result = PathTraversalSink.moveFile(path, destination);
                break;

            case 'list':
                // SINK: Directory traversal
                result = PathTraversalSink.listDirectory(path);
                break;

            default:
                return res.status(400).json({ error: 'Unknown action' });
        }

        res.json({ result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: Log Management
 * Source: req.body -> LogSink
 */
router.post('/logs/manage', async (req, res) => {
    try {
        const { action, logFile, pattern, message } = req.body;

        let result;

        switch (action) {
            case 'read':
                // SINK: Log file path traversal
                result = require('../middleware/loggingMiddleware').LoggingMiddleware.readLog(logFile);
                break;

            case 'search':
                // SINK: Command injection in log search
                result = await require('../middleware/loggingMiddleware').LoggingMiddleware.searchLogs(pattern, logFile);
                break;

            case 'write':
                // SINK: Log injection + path traversal
                LogSink.writeLog(logFile, message);
                result = 'Log entry written';
                break;

            case 'rotate':
                // SINK: Command injection in rotation
                await require('../middleware/loggingMiddleware').LoggingMiddleware.rotateLog(logFile);
                result = 'Log rotated';
                break;

            default:
                return res.status(400).json({ error: 'Unknown action' });
        }

        res.json({ result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: Network Diagnostics with SSRF
 * Source: req.body -> SsrfSink + SocketSink + DnsSink
 */
router.post('/network/diagnose', async (req, res) => {
    try {
        const { action, target, port, data, domain } = req.body;

        let result;

        switch (action) {
            case 'http':
                // SINK: SSRF via HTTP request
                result = await SsrfSink.fetchUrl(target);
                break;

            case 'tcp':
                // SINK: Arbitrary TCP connection
                result = await SocketSink.connectToHost(target, port, data);
                break;

            case 'dns':
                // SINK: DNS query to arbitrary domain
                result = await DnsSink.queryTxtRecord(domain);
                break;

            case 'exfil':
                // SINK: DNS exfiltration
                result = await DnsSink.exfiltrateViaDns(data, domain);
                break;

            default:
                return res.status(400).json({ error: 'Unknown action' });
        }

        res.json({ result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: Template Administration
 * Source: req.body -> TemplateSink
 */
router.post('/templates/manage', async (req, res) => {
    try {
        const { template, engine, context, code, expression } = req.body;

        let result;

        switch (engine) {
            case 'ejs':
                // SINK: EJS SSTI
                result = TemplateSink.renderEjs(template, context);
                break;

            case 'pug':
                // SINK: Pug SSTI
                result = TemplateSink.renderPug(template, context);
                break;

            case 'handlebars':
                // SINK: Handlebars SSTI
                result = TemplateSink.renderHandlebars(template, context);
                break;

            case 'nunjucks':
                // SINK: Nunjucks SSTI
                result = TemplateSink.renderNunjucks(template, context);
                break;

            case 'eval':
                // SINK: Direct code evaluation
                result = TemplateSink.evaluateExpression(expression, context);
                break;

            case 'function':
                // SINK: Dynamic function execution
                result = TemplateSink.createAndExecuteFunction(code, context);
                break;

            case 'vm':
                // SINK: VM sandbox escape
                result = TemplateSink.runInSandbox(code, context);
                break;

            default:
                return res.status(400).json({ error: 'Unknown engine' });
        }

        res.json({ result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: Audit Log Export
 * Source: req.body -> SQL Injection -> File Write
 */
router.post('/audit/export', async (req, res) => {
    try {
        const { userId, startDate, endDate, outputPath } = req.body;

        // Step 1: SQL injection in audit query
        const auditLogger = new AuditLogger(global.dbConnection);
        const logs = await auditLogger.getLogsForUser(userId);

        // Step 2: Path traversal in export
        PathTraversalSink.writeFile(outputPath, JSON.stringify(logs, null, 2));

        res.json({ exported: logs.length, path: outputPath });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: Backup and Restore
 * Source: req.body -> Command Injection + Path Traversal
 */
router.post('/backup/manage', async (req, res) => {
    try {
        const { action, backupPath, restorePath, archiveName } = req.body;

        let result;

        switch (action) {
            case 'create':
                // SINK: Command injection in backup creation
                result = await CommandSink.executeCommand(
                    `tar -czvf ${backupPath}/${archiveName}.tar.gz /var/app/data`
                );
                break;

            case 'restore':
                // SINK: Command injection + path traversal in restore
                result = await CommandSink.executeCommand(
                    `tar -xzvf ${backupPath}/${archiveName}.tar.gz -C ${restorePath}`
                );
                break;

            case 'list':
                // SINK: Command injection in listing
                result = await CommandSink.executeCommand(`ls -la ${backupPath}`);
                break;

            default:
                return res.status(400).json({ error: 'Unknown action' });
        }

        res.json({ result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
