/**
 * Template Sink - Template Injection and XSS Vulnerabilities
 * Server-side template injection (SSTI) and reflected/stored XSS
 */

const ejs = require('ejs');
const pug = require('pug');
const Handlebars = require('handlebars');
const nunjucks = require('nunjucks');
const vm = require('vm');

class TemplateSink {

    /**
     * SINK: EJS Template Injection
     * User input directly in template string
     */
    static renderEjs(template, data) {
        // VULNERABLE: User-controlled template string
        return ejs.render(template, data);
    }

    /**
     * SINK: EJS with dangerous delimiter
     */
    static renderEjsWithData(userContent) {
        // VULNERABLE: User content in template
        const template = `<div class="content"><%= userContent %></div>`;
        return ejs.render(template, { userContent });
    }

    /**
     * SINK: Pug/Jade Template Injection
     */
    static renderPug(template, data) {
        // VULNERABLE: User-controlled template
        const compiledFn = pug.compile(template);
        return compiledFn(data);
    }

    /**
     * SINK: Handlebars Template Injection
     */
    static renderHandlebars(templateString, context) {
        // VULNERABLE: User-controlled template
        const template = Handlebars.compile(templateString);
        return template(context);
    }

    /**
     * SINK: Nunjucks Template Injection
     */
    static renderNunjucks(templateString, context) {
        // VULNERABLE: User-controlled template with no sandbox
        return nunjucks.renderString(templateString, context);
    }

    /**
     * SINK: eval() with user input (SSTI equivalent)
     */
    static evaluateExpression(expression, context) {
        // VULNERABLE: Direct eval of user input
        return eval(expression);
    }

    /**
     * SINK: new Function() with user input
     */
    static createAndExecuteFunction(code, args) {
        // VULNERABLE: Dynamic function creation
        const fn = new Function(...Object.keys(args), code);
        return fn(...Object.values(args));
    }

    /**
     * SINK: vm.runInContext with user code
     */
    static runInSandbox(code, contextObj) {
        // VULNERABLE: vm sandbox can be escaped
        const context = vm.createContext(contextObj);
        return vm.runInContext(code, context);
    }
}

/**
 * XSS Sinks - Output without proper encoding
 */
class XssSink {

    /**
     * SINK: Direct HTML response without encoding
     */
    static sendHtml(res, userContent) {
        // VULNERABLE: No HTML encoding
        res.send(`<html><body>${userContent}</body></html>`);
    }

    /**
     * SINK: Template string XSS
     */
    static renderUserProfile(user) {
        // VULNERABLE: User data in HTML without escaping
        return `
            <div class="profile">
                <h1>${user.name}</h1>
                <p>${user.bio}</p>
                <a href="${user.website}">Website</a>
                <img src="${user.avatar}" alt="${user.name}">
            </div>
        `;
    }

    /**
     * SINK: JSON in script tag
     */
    static embedJsonInScript(data) {
        // VULNERABLE: JSON breakout in script context
        return `<script>var data = ${JSON.stringify(data)};</script>`;
    }

    /**
     * SINK: User input in JavaScript
     */
    static generateJavaScript(userName, callback) {
        // VULNERABLE: JS injection via string interpolation
        return `
            <script>
                var user = "${userName}";
                ${callback}(user);
            </script>
        `;
    }

    /**
     * SINK: URL in href without validation
     */
    static createLink(url, text) {
        // VULNERABLE: javascript: URLs allowed
        return `<a href="${url}">${text}</a>`;
    }

    /**
     * SINK: SVG injection
     */
    static renderSvgContent(svgData) {
        // VULNERABLE: SVG can contain scripts
        return `<div class="icon">${svgData}</div>`;
    }

    /**
     * SINK: CSS injection
     */
    static applyUserStyles(cssContent) {
        // VULNERABLE: Arbitrary CSS injection
        return `<style>${cssContent}</style>`;
    }

    /**
     * SINK: innerHTML equivalent (DOM-based)
     */
    static generateDomScript(elementId, content) {
        // VULNERABLE: Client-side DOM XSS
        return `
            <script>
                document.getElementById('${elementId}').innerHTML = '${content}';
            </script>
        `;
    }

    /**
     * SINK: Event handler injection
     */
    static createButton(label, onclickCode) {
        // VULNERABLE: Event handler from user
        return `<button onclick="${onclickCode}">${label}</button>`;
    }
}

/**
 * Email Template Sink - Email injection
 */
class EmailSink {

    /**
     * SINK: Email header injection
     */
    static createEmailHeaders(to, subject, from) {
        // VULNERABLE: Header injection via newlines
        return {
            to: to,
            from: from,
            subject: subject,
            headers: `To: ${to}\r\nFrom: ${from}\r\nSubject: ${subject}`
        };
    }

    /**
     * SINK: Email body injection (HTML email)
     */
    static createHtmlEmail(recipientName, messageContent) {
        // VULNERABLE: XSS in email
        return `
            <html>
                <body>
                    <h1>Hello, ${recipientName}</h1>
                    <p>${messageContent}</p>
                </body>
            </html>
        `;
    }
}

module.exports = {
    TemplateSink,
    XssSink,
    EmailSink
};
