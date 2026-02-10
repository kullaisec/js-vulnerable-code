/**
 * Data Transform Service - Cross-File Taint Propagation
 * This service receives data from sources and passes to sinks
 * Demonstrates how tainted data flows across files
 */

const { CommandSink } = require('../sinks/CommandSink');
const { SsrfSink } = require('../sinks/NetworkSink');
const { PathTraversalSink } = require('../sinks/FileSink');
const { TemplateSink, XssSink } = require('../sinks/TemplateSink');
const { QueryBuilder } = require('../config/database');

class DataTransformService {

    /**
     * TAINT PROPAGATION: Transforms data and passes to multiple sinks
     * Source: HTTP request body -> This service -> Multiple sinks
     */

    // Cross-file propagation: receives tainted data, passes to command sink
    static async processSystemAction(actionData) {
        // Data received from route handler (tainted)
        const { command, target, options } = actionData;

        // Transform data (taint preserved)
        const fullCommand = this.buildCommand(command, target, options);

        // SINK: Pass to command execution (cross-file)
        return await CommandSink.executeCommand(fullCommand);
    }

    // Helper that preserves taint
    static buildCommand(cmd, target, opts) {
        let fullCmd = cmd;
        if (target) fullCmd += ` ${target}`;
        if (opts) fullCmd += ` ${opts}`;
        return fullCmd;  // Still tainted
    }

    // Cross-file propagation: HTTP source -> file sink
    static async processFileOperation(fileData) {
        const { filename, content, operation } = fileData;

        switch (operation) {
            case 'read':
                // SINK: Path traversal (cross-file)
                return PathTraversalSink.readFile(filename);

            case 'write':
                // SINK: Arbitrary file write (cross-file)
                return PathTraversalSink.writeFile(filename, content);

            case 'delete':
                // SINK: Arbitrary file delete (cross-file)
                return PathTraversalSink.deleteFile(filename);

            default:
                throw new Error('Unknown operation');
        }
    }

    // Cross-file propagation: HTTP source -> SSRF sink
    static async processExternalRequest(requestData) {
        const { url, method, headers, body } = requestData;

        // SINK: SSRF via cross-file call
        if (method === 'GET') {
            return await SsrfSink.fetchUrl(url);
        } else {
            return await SsrfSink.postToUrl(url, body);
        }
    }

    // Cross-file propagation: HTTP source -> template sink
    static async processTemplateRender(templateData) {
        const { template, context, engine } = templateData;

        switch (engine) {
            case 'ejs':
                // SINK: EJS SSTI (cross-file)
                return TemplateSink.renderEjs(template, context);

            case 'pug':
                // SINK: Pug SSTI (cross-file)
                return TemplateSink.renderPug(template, context);

            case 'handlebars':
                // SINK: Handlebars SSTI (cross-file)
                return TemplateSink.renderHandlebars(template, context);

            default:
                // SINK: Nunjucks SSTI (cross-file)
                return TemplateSink.renderNunjucks(template, context);
        }
    }
}

/**
 * User Data Service - Demonstrates stored taint
 * Data stored in session/database and later used in sinks
 */
class UserDataService {

    // Store user data (will be retrieved later as tainted)
    static storeUserPreferences(session, preferences) {
        // Store tainted data in session
        session.userPrefs = {
            theme: preferences.theme,
            customCss: preferences.customCss,  // TAINTED: Will cause XSS later
            callbackUrl: preferences.callbackUrl,  // TAINTED: Will cause SSRF later
            exportPath: preferences.exportPath  // TAINTED: Will cause path traversal later
        };
    }

    // Retrieve and use stored tainted data
    static async applyUserPreferences(session, res) {
        const prefs = session.userPrefs;

        if (!prefs) return;

        // SINK: Stored XSS via CSS injection (cross-file taint)
        if (prefs.customCss) {
            res.write(`<style>${prefs.customCss}</style>`);
        }

        // SINK: Stored SSRF via callback (cross-file taint)
        if (prefs.callbackUrl) {
            await SsrfSink.sendWebhook(prefs.callbackUrl, { action: 'preferences_loaded' });
        }
    }

    // Export user data to path (stored taint -> path traversal)
    static async exportUserData(session, userData) {
        const exportPath = session.userPrefs?.exportPath || 'default.json';

        // SINK: Path traversal with stored tainted data
        PathTraversalSink.writeFile(exportPath, JSON.stringify(userData));
    }
}

/**
 * Query Service - Demonstrates SQL injection propagation
 */
class QueryService {
    constructor(dbConnection) {
        this.queryBuilder = new QueryBuilder(dbConnection);
    }

    // Cross-file SQL injection: HTTP source -> QueryBuilder sink
    async searchUsers(searchParams) {
        const { field, value, orderBy, orderDir } = searchParams;

        // SINK: SQL injection via cross-file call
        let results = await this.queryBuilder.findByField('users', field, value);

        if (orderBy) {
            // SINK: ORDER BY injection
            results = await this.queryBuilder.findAllOrdered('users', orderBy, orderDir);
        }

        return results;
    }

    // Cross-file SQL injection with dynamic query
    async advancedSearch(tableName, conditions) {
        // SINK: Table name and conditions from user
        return await this.queryBuilder.dynamicQuery(tableName, conditions);
    }

    // Cross-file SQL injection via ID list
    async getUsersByIds(idList) {
        // SINK: IN clause injection
        return await this.queryBuilder.findByIds('users', idList);
    }
}

/**
 * Integration Service - Chains multiple vulnerabilities
 */
class IntegrationService {

    // Multi-chain: HTTP -> SSRF -> Command injection
    static async processWebhookAndExecute(webhookData) {
        const { callbackUrl, commandToRun } = webhookData;

        // Step 1: SSRF - Fetch from user URL
        const externalData = await SsrfSink.fetchUrl(callbackUrl);

        // Step 2: Command injection with data from external source
        // This is a multi-chain attack: HTTP source -> SSRF -> Command sink
        const command = `process_data "${externalData}" && ${commandToRun}`;
        return await CommandSink.executeCommand(command);
    }

    // Multi-chain: HTTP -> Template -> File write
    static async renderAndSave(renderData) {
        const { template, context, outputPath } = renderData;

        // Step 1: Template injection
        const rendered = TemplateSink.renderEjs(template, context);

        // Step 2: Path traversal with rendered output
        PathTraversalSink.writeFile(outputPath, rendered);

        return rendered;
    }

    // Multi-chain: File read -> Template -> XSS
    static async processTemplateFile(filePath, context, res) {
        // Step 1: Path traversal to read template
        const templateContent = PathTraversalSink.readFile(filePath);

        // Step 2: Template injection with file content
        const rendered = TemplateSink.renderEjs(templateContent, context);

        // Step 3: XSS via response
        XssSink.sendHtml(res, rendered);
    }
}

module.exports = {
    DataTransformService,
    UserDataService,
    QueryService,
    IntegrationService
};
