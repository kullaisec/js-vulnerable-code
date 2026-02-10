/**
 * Logging Middleware - Log Injection and Information Disclosure
 * Demonstrates taint propagation through logging mechanisms
 */

const fs = require('fs');
const path = require('path');
const { LogSink } = require('../sinks/FileSink');
const { CommandSink } = require('../sinks/CommandSink');

class LoggingMiddleware {

    /**
     * SINK: Log injection via request data
     * User data written to logs without sanitization
     */
    static logRequest(req, res, next) {
        const logData = {
            timestamp: new Date().toISOString(),
            method: req.method,
            path: req.originalUrl,  // TAINTED: URL can contain malicious data
            ip: req.headers['x-forwarded-for'] || req.ip,  // TAINTED: Can be spoofed
            userAgent: req.headers['user-agent'],  // TAINTED
            referer: req.headers['referer'],  // TAINTED
            requestId: req.headers['x-request-id']  // TAINTED
        };

        // SINK: Log injection - newlines can forge entries
        const logLine = `[${logData.timestamp}] ${logData.method} ${logData.path} - IP: ${logData.ip} - UA: ${logData.userAgent}`;

        // SINK: Write to log file with tainted data
        fs.appendFileSync('/var/log/app/access.log', logLine + '\n');

        // Attach request ID (tainted, will be used later)
        req.requestId = logData.requestId || `req_${Date.now()}`;

        next();
    }

    /**
     * SINK: Audit logging with SQL injection potential
     */
    static logUserAction(action) {
        return async (req, res, next) => {
            const userId = req.user?.id || 'anonymous';
            const details = JSON.stringify({
                action: action,
                path: req.originalUrl,  // TAINTED
                body: req.body,  // TAINTED
                query: req.query  // TAINTED
            });

            // SINK: Log injection via cross-file call
            LogSink.logUserAction(userId, details);

            next();
        };
    }

    /**
     * SINK: Error logging with stack trace disclosure
     */
    static errorLogger(err, req, res, next) {
        const errorLog = {
            timestamp: new Date().toISOString(),
            error: err.message,
            stack: err.stack,
            path: req.originalUrl,  // TAINTED
            body: req.body,  // TAINTED - may contain sensitive data
            query: req.query,  // TAINTED
            headers: req.headers  // TAINTED - may contain auth tokens
        };

        // SINK: Write sensitive data to log file
        fs.appendFileSync('/var/log/app/error.log', JSON.stringify(errorLog) + '\n');

        // SINK: Send detailed error to client (information disclosure)
        res.status(500).json({
            error: err.message,
            stack: process.env.NODE_ENV !== 'production' ? err.stack : undefined,
            requestData: { path: req.originalUrl, body: req.body }  // TAINTED data in response
        });
    }

    /**
     * SINK: Log rotation with command injection
     */
    static async rotateLog(logFile) {
        // SINK: Command injection in log rotation
        const rotatedName = `${logFile}.${Date.now()}`;
        await CommandSink.executeCommand(`mv ${logFile} ${rotatedName} && gzip ${rotatedName}`);
    }

    /**
     * SINK: Log search with command injection
     */
    static async searchLogs(pattern, logFile) {
        // SINK: Command injection in log search
        const result = await CommandSink.executeCommand(`grep "${pattern}" ${logFile}`);
        return result;
    }

    /**
     * SINK: Log file path traversal
     */
    static readLog(logName) {
        // SINK: Path traversal in log reading
        const logPath = path.join('/var/log/app', logName);
        return fs.readFileSync(logPath, 'utf8');
    }

    /**
     * SINK: Custom log file (path traversal)
     */
    static writeCustomLog(logFile, message) {
        // SINK: Write to arbitrary log file
        LogSink.writeLog(logFile, message);
    }
}

/**
 * Metrics Middleware - Additional logging vectors
 */
class MetricsMiddleware {

    /**
     * SINK: Metrics with tainted labels (Prometheus injection)
     */
    static recordMetric(req, res, next) {
        const endpoint = req.originalUrl;  // TAINTED
        const method = req.method;
        const userAgent = req.headers['user-agent'];  // TAINTED

        // SINK: Prometheus metric injection via labels
        const metricLine = `http_requests_total{endpoint="${endpoint}",method="${method}",user_agent="${userAgent}"} 1`;

        fs.appendFileSync('/var/log/app/metrics.prom', metricLine + '\n');

        next();
    }

    /**
     * SINK: Timing metric with tainted data
     */
    static recordTiming(name) {
        return (req, res, next) => {
            const start = Date.now();

            res.on('finish', () => {
                const duration = Date.now() - start;
                const path = req.originalUrl;  // TAINTED

                // SINK: Log injection via timing metric
                const logLine = `[TIMING] ${name} - ${path} - ${duration}ms`;
                fs.appendFileSync('/var/log/app/timing.log', logLine + '\n');
            });

            next();
        };
    }
}

module.exports = {
    ...LoggingMiddleware,
    LoggingMiddleware,
    MetricsMiddleware
};
