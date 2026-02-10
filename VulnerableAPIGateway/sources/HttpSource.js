/**
 * HTTP Source - Custom source implementations
 * Demonstrates various entry points for tainted data
 */

class HttpSource {
    /**
     * SOURCE: Extract data from various HTTP locations
     * All returned data is considered tainted
     */

    // SOURCE: Request body (JSON, form data)
    static getBodyData(req) {
        return {
            json: req.body,
            raw: req.rawBody,
            text: req.body?.toString()
        };
    }

    // SOURCE: Query parameters
    static getQueryParams(req) {
        return req.query;
    }

    // SOURCE: URL parameters
    static getUrlParams(req) {
        return req.params;
    }

    // SOURCE: HTTP headers (custom headers are user-controlled)
    static getCustomHeaders(req) {
        return {
            xForwardedFor: req.headers['x-forwarded-for'],
            xCustomHeader: req.headers['x-custom-header'],
            userAgent: req.headers['user-agent'],
            referer: req.headers['referer'],
            authorization: req.headers['authorization'],
            contentType: req.headers['content-type'],
            xApiKey: req.headers['x-api-key'],
            xRequestId: req.headers['x-request-id'],
            host: req.headers['host']
        };
    }

    // SOURCE: Cookies
    static getCookies(req) {
        return req.cookies || {};
    }

    // SOURCE: Session data (may contain previously stored tainted data)
    static getSessionData(req) {
        return req.session || {};
    }

    // SOURCE: Uploaded files
    static getUploadedFiles(req) {
        if (!req.files) return null;

        const files = {};
        for (const [key, file] of Object.entries(req.files)) {
            files[key] = {
                name: file.name,           // TAINTED: User-controlled filename
                data: file.data,           // TAINTED: File contents
                mimetype: file.mimetype,   // TAINTED: User-controlled MIME type
                size: file.size,
                tempFilePath: file.tempFilePath
            };
        }
        return files;
    }

    // SOURCE: Extract all tainted data from request
    static extractAllSources(req) {
        return {
            body: this.getBodyData(req),
            query: this.getQueryParams(req),
            params: this.getUrlParams(req),
            headers: this.getCustomHeaders(req),
            cookies: this.getCookies(req),
            session: this.getSessionData(req),
            files: this.getUploadedFiles(req),
            ip: req.ip,                    // TAINTED: Can be spoofed via X-Forwarded-For
            hostname: req.hostname,        // TAINTED: Host header
            originalUrl: req.originalUrl,  // TAINTED: URL path
            protocol: req.protocol
        };
    }
}

/**
 * Custom Source: JWT Token Parser
 * Extracts claims from JWT without validation
 */
class JwtSource {
    // SOURCE: Extract unverified JWT claims
    static extractClaims(token) {
        if (!token) return null;

        try {
            // VULNERABLE: No signature verification
            const parts = token.split('.');
            if (parts.length !== 3) return null;

            const payload = Buffer.from(parts[1], 'base64').toString();
            return JSON.parse(payload);  // TAINTED: Unverified claims
        } catch (e) {
            return null;
        }
    }

    // SOURCE: Extract from Authorization header
    static extractFromHeader(authHeader) {
        if (!authHeader) return null;

        const [scheme, token] = authHeader.split(' ');
        if (scheme?.toLowerCase() === 'bearer') {
            return this.extractClaims(token);
        }
        return null;
    }
}

/**
 * Custom Source: XML/SOAP Parser
 * Extracts data from XML payloads
 */
class XmlSource {
    // SOURCE: Parse XML without XXE protection
    static async parseXml(xmlString) {
        const { parseStringPromise } = require('xml2js');

        // VULNERABLE: No XXE protection configured
        const result = await parseStringPromise(xmlString, {
            explicitArray: false,
            ignoreAttrs: false
        });

        return result;  // TAINTED: Parsed XML data
    }

    // SOURCE: Extract SOAP body
    static async extractSoapBody(soapXml) {
        const parsed = await this.parseXml(soapXml);
        return parsed?.['soap:Envelope']?.['soap:Body'];
    }
}

module.exports = {
    HttpSource,
    JwtSource,
    XmlSource
};
