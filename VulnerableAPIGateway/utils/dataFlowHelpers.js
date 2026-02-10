/**
 * Data Flow Helpers - Functions that propagate taint across the application
 * These helpers receive tainted data and pass it to sinks
 */

const { CommandSink } = require('../sinks/CommandSink');
const { SsrfSink } = require('../sinks/NetworkSink');
const { PathTraversalSink } = require('../sinks/FileSink');
const { TemplateSink, XssSink } = require('../sinks/TemplateSink');
const { QueryBuilder } = require('../config/database');

/**
 * Relay Functions - Pass tainted data unchanged
 * These create longer taint paths for testing cross-file analysis
 */
class TaintRelay {

    // Simple relay - returns input unchanged
    static passthrough(data) {
        return data;  // Taint preserved
    }

    // Array relay - wraps and unwraps
    static arrayRelay(data) {
        const arr = [data];
        return arr[0];  // Taint preserved
    }

    // Object relay - stores and retrieves
    static objectRelay(data) {
        const obj = { value: data };
        return obj.value;  // Taint preserved
    }

    // Promise relay - async passthrough
    static async asyncRelay(data) {
        return new Promise(resolve => {
            setTimeout(() => resolve(data), 0);  // Taint preserved
        });
    }

    // Callback relay - callback with data
    static callbackRelay(data, callback) {
        callback(data);  // Taint preserved
    }

    // Multiple hop relay
    static multiHopRelay(data) {
        const step1 = this.passthrough(data);
        const step2 = this.arrayRelay(step1);
        const step3 = this.objectRelay(step2);
        return step3;  // Taint preserved through all hops
    }
}

/**
 * Transform Functions - Modify data while preserving taint
 */
class TaintTransform {

    // String concatenation (preserves taint)
    static concat(prefix, taintedData, suffix) {
        return `${prefix}${taintedData}${suffix}`;  // Still tainted
    }

    // String interpolation
    static interpolate(template, values) {
        let result = template;
        for (const [key, value] of Object.entries(values)) {
            result = result.replace(`{${key}}`, value);  // Taint propagates
        }
        return result;
    }

    // JSON stringify/parse (preserves taint)
    static jsonRoundTrip(data) {
        const json = JSON.stringify(data);
        return JSON.parse(json);  // Taint preserved
    }

    // Base64 encode/decode
    static base64RoundTrip(data) {
        const encoded = Buffer.from(data).toString('base64');
        return Buffer.from(encoded, 'base64').toString();  // Taint preserved
    }

    // Array operations
    static arrayOperations(taintedArray) {
        return taintedArray
            .map(item => item)           // Taint preserved
            .filter(item => item)        // Taint preserved
            .reduce((acc, item) => [...acc, item], []);  // Taint preserved
    }

    // Object spread
    static objectSpread(taintedObj) {
        return { ...taintedObj };  // Taint preserved
    }

    // Destructuring
    static destructure(taintedObj) {
        const { a, b, c } = taintedObj;
        return { a, b, c };  // Individual properties still tainted
    }
}

/**
 * Sink Dispatcher - Routes tainted data to appropriate sinks
 */
class SinkDispatcher {

    // Dispatch to command sink based on action
    static async dispatchCommand(action, data) {
        switch (action) {
            case 'execute':
                return await CommandSink.executeCommand(data.command);
            case 'system':
                return CommandSink.runSystemCommand(data.action, data.target);
            case 'process':
                return await CommandSink.processFile(data.filename, data.operation);
            default:
                throw new Error('Unknown action');
        }
    }

    // Dispatch to network sink
    static async dispatchNetwork(action, data) {
        switch (action) {
            case 'fetch':
                return await SsrfSink.fetchUrl(data.url);
            case 'post':
                return await SsrfSink.postToUrl(data.url, data.body);
            case 'webhook':
                return await SsrfSink.sendWebhook(data.callbackUrl, data.payload);
            default:
                throw new Error('Unknown action');
        }
    }

    // Dispatch to file sink
    static dispatchFile(action, data) {
        switch (action) {
            case 'read':
                return PathTraversalSink.readFile(data.path);
            case 'write':
                return PathTraversalSink.writeFile(data.path, data.content);
            case 'delete':
                return PathTraversalSink.deleteFile(data.path);
            case 'list':
                return PathTraversalSink.listDirectory(data.path);
            default:
                throw new Error('Unknown action');
        }
    }

    // Dispatch to template sink
    static dispatchTemplate(engine, template, context) {
        switch (engine) {
            case 'ejs':
                return TemplateSink.renderEjs(template, context);
            case 'pug':
                return TemplateSink.renderPug(template, context);
            case 'handlebars':
                return TemplateSink.renderHandlebars(template, context);
            case 'nunjucks':
                return TemplateSink.renderNunjucks(template, context);
            case 'eval':
                return TemplateSink.evaluateExpression(template, context);
            default:
                throw new Error('Unknown engine');
        }
    }

    // Dispatch to SQL sink
    static async dispatchSQL(action, data, connection) {
        const queryBuilder = new QueryBuilder(connection);

        switch (action) {
            case 'findByField':
                return await queryBuilder.findByField(data.table, data.field, data.value);
            case 'findAll':
                return await queryBuilder.findAllOrdered(data.table, data.orderBy, data.orderDir);
            case 'search':
                return await queryBuilder.searchByPattern(data.table, data.field, data.pattern);
            case 'dynamic':
                return await queryBuilder.dynamicQuery(data.table, data.conditions);
            default:
                throw new Error('Unknown action');
        }
    }
}

/**
 * Chain Builder - Create complex multi-sink chains
 */
class ChainBuilder {

    // Chain: Source -> Transform -> Sink
    static async simpleChain(source, transformer, sink) {
        const transformed = transformer(source);
        return await sink(transformed);
    }

    // Chain: Source -> Multiple Sinks (parallel)
    static async parallelSinks(source, sinks) {
        return await Promise.all(sinks.map(sink => sink(source)));
    }

    // Chain: Source -> Sink1 -> Sink2 (sequential)
    static async sequentialSinks(source, sink1, sink2) {
        const result1 = await sink1(source);
        return await sink2(result1);
    }

    // Chain: Multiple Sources -> Merge -> Sink
    static async mergedSources(sources, merger, sink) {
        const merged = merger(...sources);
        return await sink(merged);
    }

    // Complex chain: HTTP -> SQL -> File -> Command
    static async complexChain(httpData, dbConnection) {
        // Step 1: Query database with HTTP input
        const queryBuilder = new QueryBuilder(dbConnection);
        const dbResults = await queryBuilder.findByField('configs', 'name', httpData.configName);

        // Step 2: Read file based on DB result
        const filePath = dbResults[0]?.file_path;
        const fileContent = PathTraversalSink.readFile(filePath);

        // Step 3: Execute command from file
        const command = JSON.parse(fileContent).command;
        return await CommandSink.executeCommand(`${command} ${httpData.args}`);
    }

    // SSRF -> Parse -> Store chain
    static async ssrfToStore(url, storePath) {
        // Step 1: SSRF to fetch external data
        const externalData = await SsrfSink.fetchUrl(url);

        // Step 2: Store fetched data (path traversal)
        PathTraversalSink.writeFile(storePath, externalData);

        return { fetched: url, stored: storePath };
    }

    // Template -> XSS chain
    static templateToXss(template, context, res) {
        // Step 1: Template injection
        const rendered = TemplateSink.renderEjs(template, context);

        // Step 2: XSS via response
        XssSink.sendHtml(res, rendered);

        return rendered;
    }
}

/**
 * Context Propagation - Demonstrates how context carries taint
 */
class ContextPropagation {

    constructor() {
        this.context = {};
    }

    // Store tainted data in context
    set(key, value) {
        this.context[key] = value;  // Tainted value stored
    }

    // Retrieve tainted data
    get(key) {
        return this.context[key];  // Returns tainted value
    }

    // Use context in sink
    async executeFromContext(commandKey) {
        const command = this.get(commandKey);  // Retrieve tainted
        return await CommandSink.executeCommand(command);  // Pass to sink
    }

    // Use context in template
    renderFromContext(templateKey, contextKey) {
        const template = this.get(templateKey);
        const ctx = this.get(contextKey);
        return TemplateSink.renderEjs(template, ctx);
    }

    // Chain through context
    async chainThroughContext(inputKey, outputKey, sink) {
        const input = this.get(inputKey);
        const result = await sink(input);
        this.set(outputKey, result);
        return result;
    }
}

module.exports = {
    TaintRelay,
    TaintTransform,
    SinkDispatcher,
    ChainBuilder,
    ContextPropagation
};
