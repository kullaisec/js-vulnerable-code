/**
 * Webhook Routes - External Integration Vulnerabilities
 * Demonstrates cross-file taint from external sources
 */

const express = require('express');
const router = express.Router();

const { ExternalApiSource } = require('../sources/ExternalSource');
const { XmlSource } = require('../sources/HttpSource');
const { CommandSink } = require('../sinks/CommandSink');
const { SsrfSink } = require('../sinks/NetworkSink');
const { PathTraversalSink } = require('../sinks/FileSink');
const { TemplateSink, XssSink } = require('../sinks/TemplateSink');
const { QueryBuilder, AuditLogger } = require('../config/database');

/**
 * MULTI-CHAIN: External Webhook -> SQL Injection
 * Source: External webhook payload -> QueryBuilder
 */
router.post('/github', async (req, res) => {
    try {
        // SOURCE: Webhook payload (external, potentially attacker-controlled)
        const payload = ExternalApiSource.parseWebhookPayload(req.body, req.headers['x-hub-signature']);

        const { repository, sender, commits } = payload.data;

        // SINK: SQL injection via webhook data
        const queryBuilder = new QueryBuilder(global.dbConnection);

        // Store repository data (second-order injection)
        await queryBuilder.dynamicQuery('repositories', {
            name: repository.name,      // TAINTED from external source
            owner: sender.login,        // TAINTED
            url: repository.html_url    // TAINTED
        });

        // Store commits
        for (const commit of commits || []) {
            // SINK: SQL injection in loop
            await queryBuilder.dynamicQuery('commits', {
                sha: commit.id,          // TAINTED
                message: commit.message, // TAINTED
                author: commit.author.name  // TAINTED
            });
        }

        res.json({ status: 'processed' });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: External Webhook -> Command Injection
 * Source: CI/CD webhook -> CommandSink
 */
router.post('/cicd', async (req, res) => {
    try {
        // SOURCE: CI/CD webhook payload
        const { event, project, branch, commit, buildScript } = req.body;

        // SINK: Command injection via CI/CD webhook
        let result;

        switch (event) {
            case 'push':
                // SINK: Git clone with user-controlled URL
                result = await CommandSink.gitClone(
                    project.git_url,  // TAINTED
                    `/var/builds/${project.name}`  // TAINTED
                );
                break;

            case 'build':
                // SINK: Build script execution
                result = await CommandSink.executeCommand(
                    `cd /var/builds/${project.name} && git checkout ${branch} && ${buildScript}`
                );
                break;

            case 'deploy':
                // SINK: Deployment command injection
                result = await CommandSink.executeCommand(
                    `deploy --project=${project.name} --commit=${commit} --branch=${branch}`
                );
                break;

            default:
                result = 'Event ignored';
        }

        res.json({ status: 'processed', result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: External Webhook -> SSRF
 * Source: Payment webhook -> SsrfSink
 */
router.post('/payment', async (req, res) => {
    try {
        // SOURCE: Payment webhook payload
        const { event, data, callback_url } = req.body;

        // Process payment event
        const result = {
            event,
            transactionId: data.transaction_id,
            amount: data.amount,
            status: data.status
        };

        // SINK: SSRF via callback URL
        if (callback_url) {
            await SsrfSink.sendWebhook(callback_url, result);
        }

        // SINK: SSRF to fetch additional data
        if (data.receipt_url) {
            const receipt = await SsrfSink.fetchUrl(data.receipt_url);
            result.receipt = receipt;
        }

        res.json(result);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: SOAP/XML Webhook -> XXE + SQL Injection
 * Source: SOAP envelope -> XmlSource -> QueryBuilder
 */
router.post('/soap', async (req, res) => {
    try {
        // Get raw XML body
        const xmlBody = req.body.toString();

        // SOURCE + SINK: XXE vulnerability in XML parsing
        const soapBody = await XmlSource.extractSoapBody(xmlBody);

        if (!soapBody) {
            return res.status(400).json({ error: 'Invalid SOAP envelope' });
        }

        // Extract operation and data from SOAP body
        const operation = Object.keys(soapBody)[0];
        const params = soapBody[operation];

        // SINK: SQL injection with data from XXE-vulnerable parsing
        const queryBuilder = new QueryBuilder(global.dbConnection);

        let result;
        switch (operation) {
            case 'GetUser':
                result = await queryBuilder.findByField('users', 'id', params.userId);
                break;

            case 'SearchUsers':
                result = await queryBuilder.searchByPattern('users', params.field, params.pattern);
                break;

            case 'CreateUser':
                result = await queryBuilder.dynamicQuery('users', params);
                break;

            default:
                result = 'Unknown operation';
        }

        // Return SOAP response
        res.type('application/xml');
        res.send(`
            <?xml version="1.0" encoding="UTF-8"?>
            <soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">
                <soap:Body>
                    <Response>${JSON.stringify(result)}</Response>
                </soap:Body>
            </soap:Envelope>
        `);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: External Webhook -> File Write + Command Injection
 * Source: Deployment webhook -> PathTraversalSink + CommandSink
 */
router.post('/deploy', async (req, res) => {
    try {
        // SOURCE: Deployment webhook payload
        const { artifact_url, deploy_path, post_deploy_script, config } = req.body;

        // Step 1: SSRF - Download artifact from external URL
        const artifactContent = await SsrfSink.fetchUrl(artifact_url);

        // Step 2: Path traversal - Write artifact to specified path
        const artifactPath = PathTraversalSink.writeFile(
            `${deploy_path}/artifact.tar.gz`,
            artifactContent
        );

        // Step 3: Command injection - Extract artifact
        await CommandSink.extractArchive(artifactPath, deploy_path);

        // Step 4: Path traversal - Write config file
        if (config) {
            PathTraversalSink.writeFile(
                `${deploy_path}/config.json`,
                JSON.stringify(config)
            );
        }

        // Step 5: Command injection - Run post-deploy script
        if (post_deploy_script) {
            await CommandSink.executeCommand(
                `cd ${deploy_path} && ${post_deploy_script}`
            );
        }

        res.json({ status: 'deployed', path: deploy_path });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: Slack Webhook -> XSS + Command Injection
 * Source: Slack slash command -> XssSink + CommandSink
 */
router.post('/slack', async (req, res) => {
    try {
        // SOURCE: Slack slash command payload
        const { command, text, user_name, channel_name, response_url } = req.body;

        // Parse command arguments
        const args = text.split(' ');
        const action = args[0];
        const target = args.slice(1).join(' ');

        let result;

        switch (action) {
            case 'status':
                // SINK: Command injection via Slack command
                result = await CommandSink.executeCommand(`systemctl status ${target}`);
                break;

            case 'logs':
                // SINK: Path traversal via Slack command
                result = PathTraversalSink.readFile(`/var/log/${target}`);
                break;

            case 'exec':
                // SINK: Direct command injection
                result = await CommandSink.executeCommand(target);
                break;

            default:
                result = 'Unknown command';
        }

        // SINK: XSS in response (when rendered in Slack app)
        const response = {
            response_type: 'in_channel',
            text: `*Command:* ${command} ${text}\n*User:* ${user_name}\n*Result:*\n\`\`\`${result}\`\`\``
        };

        // SINK: SSRF to Slack response URL
        if (response_url) {
            await SsrfSink.postToUrl(response_url, response);
        }

        res.json(response);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: Generic Webhook -> Template Injection
 * Source: Webhook with template -> TemplateSink
 */
router.post('/template', async (req, res) => {
    try {
        // SOURCE: Webhook with template data
        const { template, data, engine, output_url } = req.body;

        // SINK: Template injection via webhook
        let rendered;

        switch (engine) {
            case 'ejs':
                rendered = TemplateSink.renderEjs(template, data);
                break;
            case 'nunjucks':
                rendered = TemplateSink.renderNunjucks(template, data);
                break;
            default:
                rendered = TemplateSink.renderHandlebars(template, data);
        }

        // SINK: SSRF to send rendered output
        if (output_url) {
            await SsrfSink.postToUrl(output_url, { html: rendered });
        }

        // SINK: XSS in response
        res.send(rendered);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: Notification Webhook -> Stored XSS + SQL
 * Source: Notification service -> Storage -> Display
 */
router.post('/notification', async (req, res) => {
    try {
        // SOURCE: Notification webhook payload
        const { type, title, message, user_id, metadata } = req.body;

        // SINK: SQL injection - Store notification
        const query = `INSERT INTO notifications (type, title, message, user_id, metadata, created_at)
                       VALUES ('${type}', '${title}', '${message}', '${user_id}', '${JSON.stringify(metadata)}', NOW())`;

        await global.dbConnection.execute(query);

        // SINK: Stored XSS - The stored data will be displayed later without escaping
        res.json({
            status: 'stored',
            notification: {
                type,      // TAINTED - stored for XSS
                title,     // TAINTED - stored for XSS
                message,   // TAINTED - stored for XSS
                user_id
            }
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
