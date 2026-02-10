/**
 * Auth Middleware - Authentication and Authorization Vulnerabilities
 * Demonstrates taint propagation through middleware chain
 */

const { JwtSource, XmlSource } = require('../sources/HttpSource');
const { QueryBuilder } = require('../config/database');
const { CommandSink } = require('../sinks/CommandSink');

class AuthMiddleware {

    /**
     * VULNERABLE: JWT validation without signature check
     * SOURCE: JWT claims from header (tainted)
     */
    static extractUser(req, res, next) {
        const authHeader = req.headers['authorization'];

        if (!authHeader) {
            return res.status(401).json({ error: 'No authorization header' });
        }

        // SOURCE: Unverified JWT claims (tainted)
        const claims = JwtSource.extractFromHeader(authHeader);

        if (!claims) {
            return res.status(401).json({ error: 'Invalid token' });
        }

        // VULNERABLE: Trust unverified claims
        req.user = {
            id: claims.sub,           // TAINTED
            email: claims.email,      // TAINTED
            role: claims.role,        // TAINTED - role escalation
            permissions: claims.permissions  // TAINTED
        };

        next();
    }

    /**
     * VULNERABLE: Role check with tainted role value
     */
    static requireRole(role) {
        return (req, res, next) => {
            // VULNERABLE: Role from unverified JWT
            if (req.user?.role !== role) {
                return res.status(403).json({ error: 'Insufficient permissions' });
            }
            next();
        };
    }

    /**
     * Shortcut for admin role
     */
    static requireAdmin(req, res, next) {
        return AuthMiddleware.requireRole('admin')(req, res, next);
    }

    /**
     * VULNERABLE: Permission check with tainted permissions
     */
    static requirePermission(permission) {
        return (req, res, next) => {
            // VULNERABLE: Permissions from unverified JWT
            if (!req.user?.permissions?.includes(permission)) {
                return res.status(403).json({ error: 'Permission denied' });
            }
            next();
        };
    }

    /**
     * VULNERABLE: SAML response validation (XXE + bypass)
     * Cross-file: XML source -> session storage -> later sinks
     */
    static async validateSamlResponse(req, res, next) {
        const samlResponse = req.body.SAMLResponse;

        if (!samlResponse) {
            return res.status(400).json({ error: 'Missing SAML response' });
        }

        try {
            // VULNERABLE: XXE in XML parsing (cross-file to XmlSource)
            const decoded = Buffer.from(samlResponse, 'base64').toString();
            const samlData = await XmlSource.parseXml(decoded);

            // VULNERABLE: No signature validation
            const assertion = samlData?.['samlp:Response']?.['saml:Assertion'];

            if (!assertion) {
                return res.status(401).json({ error: 'Invalid SAML assertion' });
            }

            // Extract user data (tainted)
            req.user = {
                id: assertion['saml:Subject']?.[0]?.['saml:NameID']?.[0],  // TAINTED
                email: assertion['saml:Subject']?.[0]?.['saml:NameID']?.[0],  // TAINTED
                role: AuthMiddleware.extractSamlRole(assertion),  // TAINTED
                attributes: AuthMiddleware.extractSamlAttributes(assertion)  // TAINTED
            };

            // Store in session (stored taint)
            req.session.user = req.user;

            next();
        } catch (error) {
            res.status(401).json({ error: 'SAML validation failed', details: error.message });
        }
    }

    // Helper to extract role from SAML (preserves taint)
    static extractSamlRole(assertion) {
        const attributes = assertion['saml:AttributeStatement']?.[0]?.['saml:Attribute'] || [];

        for (const attr of attributes) {
            if (attr.$?.Name === 'Role' || attr.$?.Name === 'role') {
                return attr['saml:AttributeValue']?.[0];  // TAINTED
            }
        }

        return 'user';
    }

    // Helper to extract all attributes (preserves taint)
    static extractSamlAttributes(assertion) {
        const attributes = {};
        const attrStatements = assertion['saml:AttributeStatement']?.[0]?.['saml:Attribute'] || [];

        for (const attr of attrStatements) {
            const name = attr.$?.Name;
            const value = attr['saml:AttributeValue']?.[0];
            if (name) {
                attributes[name] = value;  // TAINTED
            }
        }

        return attributes;
    }

    /**
     * VULNERABLE: API key validation with SQL injection
     */
    static async validateApiKey(req, res, next) {
        const apiKey = req.headers['x-api-key'];

        if (!apiKey) {
            return res.status(401).json({ error: 'Missing API key' });
        }

        try {
            // SINK: SQL injection in API key lookup (cross-file)
            const queryBuilder = new QueryBuilder(global.dbConnection);
            const results = await queryBuilder.findByField('api_keys', 'key_value', apiKey);

            if (results.length === 0) {
                return res.status(401).json({ error: 'Invalid API key' });
            }

            req.apiClient = results[0];
            next();
        } catch (error) {
            res.status(500).json({ error: 'Authentication error' });
        }
    }

    /**
     * VULNERABLE: IP-based access control with header spoofing
     */
    static requireInternalIp(req, res, next) {
        // VULNERABLE: Trust X-Forwarded-For header
        const clientIp = req.headers['x-forwarded-for']?.split(',')[0]?.trim()
            || req.connection.remoteAddress;

        // VULNERABLE: Weak IP check
        const internalRanges = ['10.', '192.168.', '172.16.', '127.0.0.1'];
        const isInternal = internalRanges.some(range => clientIp.startsWith(range));

        if (!isInternal) {
            return res.status(403).json({ error: 'Access denied - internal only' });
        }

        // Store IP in request (tainted)
        req.clientIp = clientIp;
        next();
    }

    /**
     * Multi-chain: Auth header -> User lookup -> Command execution
     * For "debugging" endpoints
     */
    static async debugAuth(req, res, next) {
        const debugToken = req.headers['x-debug-token'];

        if (!debugToken) {
            return next();  // Continue without debug mode
        }

        // VULNERABLE: Debug command execution based on token
        const debugCommand = req.headers['x-debug-command'];

        if (debugCommand) {
            // SINK: Command injection via debug header (cross-file)
            const result = await CommandSink.executeCommand(debugCommand);
            req.debugResult = result;
        }

        next();
    }
}

module.exports = AuthMiddleware;
