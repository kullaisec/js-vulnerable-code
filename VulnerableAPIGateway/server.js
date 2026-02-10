/**
 * Vulnerable API Gateway - Multi-Chain Cross-File Attack Demo
 *
 * This application demonstrates various vulnerability patterns with
 * custom sources, sinks, and cross-file taint propagation.
 */

const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const WebSocket = require('ws');
const fileUpload = require('express-fileupload');
const http = require('http');

// Import routes with vulnerable endpoints
const apiRoutes = require('./routes/apiRoutes');
const adminRoutes = require('./routes/adminRoutes');
const webhookRoutes = require('./routes/webhookRoutes');
const fileRoutes = require('./routes/fileRoutes');

// Import middleware
const authMiddleware = require('./middleware/authMiddleware');
const loggingMiddleware = require('./middleware/loggingMiddleware');

// Import services
const WebSocketService = require('./services/WebSocketService');

const app = express();
const server = http.createServer(app);

// Vulnerable: No body size limits
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.raw({ type: '*/*' }));

// Vulnerable: Insecure file upload configuration
app.use(fileUpload({
    createParentPath: true,
    limits: { fileSize: 50 * 1024 * 1024 },  // 50MB - too large
    useTempFiles: true,
    tempFileDir: '/tmp/'
}));

// Vulnerable: Weak session configuration
app.use(session({
    secret: process.env.SESSION_SECRET || 'default-secret-key',
    resave: false,
    saveUninitialized: true,
    cookie: { secure: false }  // Insecure in production
}));

// Apply middleware
app.use(loggingMiddleware.logRequest);

// Mount routes
app.use('/api', apiRoutes);
app.use('/admin', authMiddleware.requireAdmin, adminRoutes);
app.use('/webhook', webhookRoutes);
app.use('/files', fileRoutes);

// Initialize WebSocket service (VULNERABLE: No origin validation)
const wss = new WebSocket.Server({ server });
const wsService = new WebSocketService(wss);
wsService.initialize();

// Vulnerable: Error handler exposes internal details
app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).json({
        error: err.message,
        stack: err.stack,  // SINK: Information disclosure
        query: req.query,
        body: req.body
    });
});

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
    console.log(`API Gateway running on port ${PORT}`);
});

module.exports = { app, server };
