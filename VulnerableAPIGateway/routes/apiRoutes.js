/**
 * API Routes - Main API Endpoints with Various Vulnerabilities
 * Demonstrates cross-file taint flow from HTTP source to multiple sinks
 */

const express = require('express');
const router = express.Router();

const { HttpSource, JwtSource } = require('../sources/HttpSource');
const { ExternalApiSource, FileSource } = require('../sources/ExternalSource');
const { DataTransformService, QueryService, IntegrationService } = require('../services/DataTransformService');
const { CommandSink, DockerSink, SshSink } = require('../sinks/CommandSink');
const { TemplateSink, XssSink, EmailSink } = require('../sinks/TemplateSink');
const { SsrfSink, SocketSink } = require('../sinks/NetworkSink');
const { PathTraversalSink, FileUploadSink, ArchiveSink } = require('../sinks/FileSink');
const { QueryBuilder, AuditLogger } = require('../config/database');

/**
 * MULTI-CHAIN ATTACK: HTTP Body -> SQL Injection
 * Source: req.body (HttpSource) -> QueryBuilder sink
 */
router.post('/users/search', async (req, res) => {
    try {
        // SOURCE: HTTP body
        const { field, value, orderBy, direction } = req.body;

        // Cross-file taint propagation to service layer
        const queryService = new QueryService(global.dbConnection);
        const results = await queryService.searchUsers({
            field,      // TAINTED -> SQL injection
            value,      // TAINTED -> SQL injection
            orderBy,    // TAINTED -> SQL injection
            orderDir: direction  // TAINTED -> SQL injection
        });

        res.json({ results });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN ATTACK: HTTP Body -> Command Injection
 * Source: req.body -> CommandSink
 */
router.post('/system/execute', async (req, res) => {
    try {
        // SOURCE: HTTP body
        const { command, target, options } = req.body;

        // Cross-file taint propagation to service layer
        const result = await DataTransformService.processSystemAction({
            command,  // TAINTED -> Command injection
            target,   // TAINTED -> Command injection
            options   // TAINTED -> Command injection
        });

        res.json({ output: result.stdout });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN ATTACK: HTTP Body -> SSRF
 * Source: req.body.url -> SsrfSink
 */
router.post('/proxy/fetch', async (req, res) => {
    try {
        // SOURCE: HTTP body
        const { url, method, headers, body } = req.body;

        // Cross-file taint propagation to service layer
        const result = await DataTransformService.processExternalRequest({
            url,       // TAINTED -> SSRF
            method,
            headers,   // TAINTED -> Header injection
            body
        });

        res.json({ data: result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN ATTACK: HTTP Body -> Template Injection (SSTI)
 * Source: req.body.template -> TemplateSink
 */
router.post('/render', async (req, res) => {
    try {
        // SOURCE: HTTP body
        const { template, context, engine } = req.body;

        // Cross-file taint propagation to service layer
        const rendered = await DataTransformService.processTemplateRender({
            template,  // TAINTED -> SSTI
            context,   // TAINTED -> SSTI
            engine
        });

        // SINK: XSS via response
        res.send(rendered);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN ATTACK: HTTP Body -> Path Traversal (File Read)
 * Source: req.body.filename -> PathTraversalSink
 */
router.post('/files/read', async (req, res) => {
    try {
        // SOURCE: HTTP body
        const { filename } = req.body;

        // Cross-file taint propagation
        const content = await DataTransformService.processFileOperation({
            filename,  // TAINTED -> Path traversal
            operation: 'read'
        });

        res.json({ content });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN ATTACK: HTTP Body -> Path Traversal (File Write)
 * Source: req.body -> PathTraversalSink
 */
router.post('/files/write', async (req, res) => {
    try {
        // SOURCE: HTTP body
        const { filename, content } = req.body;

        // Cross-file taint propagation
        const path = await DataTransformService.processFileOperation({
            filename,  // TAINTED -> Path traversal
            content,   // TAINTED -> Arbitrary file write
            operation: 'write'
        });

        res.json({ path });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN ATTACK: File Upload -> Path Traversal + Command Injection
 * Source: req.files -> FileUploadSink -> CommandSink
 */
router.post('/files/upload', async (req, res) => {
    try {
        // SOURCE: Uploaded file
        const file = req.files?.document;

        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // TAINTED: filename from user
        const filename = file.name;

        // SINK: Path traversal via filename
        const savedPath = FileUploadSink.saveUpload(file, '/var/app/uploads');

        // SINK: Command injection to process uploaded file
        const processResult = await CommandSink.processFile(filename, 'file');

        res.json({ path: savedPath, type: processResult });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN ATTACK: Query Param -> XSS (Reflected)
 * Source: req.query -> XssSink
 */
router.get('/search', (req, res) => {
    // SOURCE: Query parameter
    const { q, page } = req.query;

    // SINK: Reflected XSS via query parameter
    const html = `
        <html>
            <body>
                <h1>Search Results for: ${q}</h1>
                <p>Page: ${page}</p>
            </body>
        </html>
    `;

    res.send(html);
});

/**
 * MULTI-CHAIN ATTACK: URL Param -> SQL Injection
 * Source: req.params -> QueryBuilder sink
 */
router.get('/users/:userId', async (req, res) => {
    try {
        // SOURCE: URL parameter
        const { userId } = req.params;

        // SINK: SQL injection via URL parameter
        const queryBuilder = new QueryBuilder(global.dbConnection);
        const results = await queryBuilder.findByField('users', 'id', userId);

        res.json({ user: results[0] });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN ATTACK: Header -> Command Injection
 * Source: req.headers -> CommandSink
 */
router.post('/debug/run', async (req, res) => {
    try {
        // SOURCE: Custom header
        const debugCommand = req.headers['x-debug-command'];
        const debugHost = req.headers['x-debug-host'];

        if (!debugCommand) {
            return res.status(400).json({ error: 'Missing debug command' });
        }

        // SINK: Command injection via header
        let result;
        if (debugHost) {
            // SINK: SSH command injection
            result = await SshSink.sshExecute(debugHost, 'admin', debugCommand);
        } else {
            result = await CommandSink.executeCommand(debugCommand);
        }

        res.json({ output: result.stdout });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN ATTACK: HTTP Body -> Docker Command Injection
 * Source: req.body -> DockerSink
 */
router.post('/containers/exec', async (req, res) => {
    try {
        // SOURCE: HTTP body
        const { containerId, command } = req.body;

        // SINK: Docker command injection
        const result = await DockerSink.dockerExec(containerId, command);

        res.json({ output: result.stdout });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN ATTACK: HTTP Body -> Email Header Injection
 * Source: req.body -> EmailSink
 */
router.post('/email/send', (req, res) => {
    try {
        // SOURCE: HTTP body
        const { to, from, subject, message } = req.body;

        // SINK: Email header injection
        const headers = EmailSink.createEmailHeaders(to, subject, from);

        // SINK: XSS in HTML email
        const htmlBody = EmailSink.createHtmlEmail(to.split('@')[0], message);

        res.json({ headers, body: htmlBody, status: 'sent' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN ATTACK: HTTP Body -> Archive Extraction (Zip Slip)
 * Source: req.files -> ArchiveSink
 */
router.post('/archive/extract', async (req, res) => {
    try {
        // SOURCE: Uploaded file
        const archive = req.files?.archive;
        const extractTo = req.body.extractTo || '/var/app/extracted';

        if (!archive) {
            return res.status(400).json({ error: 'No archive uploaded' });
        }

        // Save archive temporarily
        const archivePath = `/tmp/${archive.name}`;
        await archive.mv(archivePath);

        // SINK: Zip slip vulnerability
        const result = await ArchiveSink.extractZip(archivePath, extractTo);

        res.json({ extractedTo: result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * COMPLEX MULTI-CHAIN: HTTP -> SSRF -> Command Injection
 * Source: req.body -> SsrfSink -> CommandSink
 */
router.post('/integration/webhook-execute', async (req, res) => {
    try {
        // SOURCE: HTTP body
        const { callbackUrl, commandToRun } = req.body;

        // MULTI-SINK: SSRF + Command injection chain
        const result = await IntegrationService.processWebhookAndExecute({
            callbackUrl,    // TAINTED -> SSRF
            commandToRun    // TAINTED -> Command injection
        });

        res.json({ result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * COMPLEX MULTI-CHAIN: HTTP -> Template -> File Write
 * Source: req.body -> TemplateSink -> PathTraversalSink
 */
router.post('/integration/render-save', async (req, res) => {
    try {
        // SOURCE: HTTP body
        const { template, context, outputPath } = req.body;

        // MULTI-SINK: Template injection + Path traversal chain
        const result = await IntegrationService.renderAndSave({
            template,    // TAINTED -> SSTI
            context,     // TAINTED -> SSTI
            outputPath   // TAINTED -> Path traversal
        });

        res.json({ rendered: result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * COMPLEX MULTI-CHAIN: HTTP -> File Read -> Template -> XSS
 * Source: req.body -> PathTraversalSink -> TemplateSink -> Response
 */
router.post('/integration/template-from-file', async (req, res) => {
    try {
        // SOURCE: HTTP body
        const { templatePath, context } = req.body;

        // MULTI-SINK: Path traversal + SSTI + XSS chain
        await IntegrationService.processTemplateFile(
            templatePath,  // TAINTED -> Path traversal
            context,       // TAINTED -> SSTI
            res           // Response object for XSS output
        );
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
