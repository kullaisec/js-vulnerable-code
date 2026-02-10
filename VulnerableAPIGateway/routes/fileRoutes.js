/**
 * File Routes - File Upload and Processing Vulnerabilities
 * Demonstrates file-based attack vectors with cross-file taint
 */

const express = require('express');
const router = express.Router();
const path = require('path');

const { HttpSource } = require('../sources/HttpSource');
const { FileSource } = require('../sources/ExternalSource');
const { CommandSink } = require('../sinks/CommandSink');
const { PathTraversalSink, FileUploadSink, ArchiveSink } = require('../sinks/FileSink');
const { TemplateSink } = require('../sinks/TemplateSink');
const { SsrfSink } = require('../sinks/NetworkSink');

/**
 * MULTI-CHAIN: File Upload -> Path Traversal
 * Source: req.files -> FileUploadSink
 */
router.post('/upload', async (req, res) => {
    try {
        // SOURCE: Uploaded file
        const file = req.files?.file;

        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Get tainted file metadata
        const fileInfo = HttpSource.getUploadedFiles(req);

        // SINK: Path traversal via filename
        const savedPath = FileUploadSink.saveUpload(file, '/var/app/uploads');

        res.json({
            filename: file.name,  // TAINTED
            path: savedPath,
            size: file.size,
            mimetype: file.mimetype  // TAINTED
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: File Upload -> Command Injection (Image Processing)
 * Source: req.files -> CommandSink
 */
router.post('/upload/image', async (req, res) => {
    try {
        const image = req.files?.image;
        const { format, width, height } = req.body;

        if (!image) {
            return res.status(400).json({ error: 'No image uploaded' });
        }

        // Save original
        const originalPath = `/tmp/${image.name}`;
        await image.mv(originalPath);

        // SINK: Command injection in image processing
        const outputPath = `/var/app/processed/${path.basename(image.name, path.extname(image.name))}.${format}`;

        // VULNERABLE: All parameters from user input
        await CommandSink.convertImage(
            originalPath,    // TAINTED filename
            outputPath,
            format          // TAINTED format
        );

        res.json({ processed: outputPath });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: File Upload -> Archive Extraction (Zip Slip)
 * Source: req.files -> ArchiveSink
 */
router.post('/upload/archive', async (req, res) => {
    try {
        const archive = req.files?.archive;
        const { extractTo } = req.body;

        if (!archive) {
            return res.status(400).json({ error: 'No archive uploaded' });
        }

        // Save archive temporarily
        const archivePath = `/tmp/${archive.name}`;
        await archive.mv(archivePath);

        // SINK: Zip slip vulnerability
        const extractPath = extractTo || '/var/app/extracted';
        await ArchiveSink.extractZip(archivePath, extractPath);

        res.json({ extracted: extractPath });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: File Upload -> Template Injection
 * Source: req.files (template file) -> TemplateSink
 */
router.post('/upload/template', async (req, res) => {
    try {
        const templateFile = req.files?.template;
        const { engine, context } = req.body;

        if (!templateFile) {
            return res.status(400).json({ error: 'No template uploaded' });
        }

        // Read uploaded template content
        const templateContent = templateFile.data.toString();

        // SINK: Template injection via uploaded file
        let rendered;
        const parsedContext = JSON.parse(context || '{}');

        switch (engine) {
            case 'ejs':
                rendered = TemplateSink.renderEjs(templateContent, parsedContext);
                break;
            case 'pug':
                rendered = TemplateSink.renderPug(templateContent, parsedContext);
                break;
            default:
                rendered = TemplateSink.renderNunjucks(templateContent, parsedContext);
        }

        res.send(rendered);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: File Upload -> SSRF (Config with URLs)
 * Source: req.files (config file) -> SsrfSink
 */
router.post('/upload/config', async (req, res) => {
    try {
        const configFile = req.files?.config;

        if (!configFile) {
            return res.status(400).json({ error: 'No config uploaded' });
        }

        // Parse config file
        const config = JSON.parse(configFile.data.toString());

        const results = {};

        // SINK: SSRF via URLs in config file
        if (config.endpoints) {
            for (const [name, url] of Object.entries(config.endpoints)) {
                results[name] = await SsrfSink.fetchUrl(url);
            }
        }

        // SINK: Command injection via commands in config
        if (config.commands) {
            for (const [name, cmd] of Object.entries(config.commands)) {
                results[name] = await CommandSink.executeCommand(cmd);
            }
        }

        // SINK: Path traversal via file paths in config
        if (config.files) {
            for (const [name, filePath] of Object.entries(config.files)) {
                results[name] = PathTraversalSink.readFile(filePath);
            }
        }

        res.json({ results });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: File Read -> Template -> Response
 * Source: req.query (path) -> PathTraversalSink -> TemplateSink
 */
router.get('/render/:template', async (req, res) => {
    try {
        // SOURCE: URL parameter
        const templateName = req.params.template;
        const context = req.query;

        // SINK: Path traversal to read template
        const templatePath = `/var/app/templates/${templateName}`;
        const templateContent = PathTraversalSink.readFile(templatePath);

        // SINK: Template injection with file content
        const rendered = TemplateSink.renderEjs(templateContent, context);

        // SINK: XSS in response
        res.send(rendered);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: File Download -> Path Traversal
 * Source: req.query -> PathTraversalSink -> Response
 */
router.get('/download', (req, res) => {
    try {
        // SOURCE: Query parameter
        const { filename, directory } = req.query;

        // SINK: Path traversal in file download
        const filePath = path.join('/var/app/files', directory || '', filename);
        const content = PathTraversalSink.readFile(filePath);

        // Set filename for download (potential XSS in Content-Disposition)
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.send(content);
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: File List -> Directory Traversal
 * Source: req.query -> PathTraversalSink
 */
router.get('/list', (req, res) => {
    try {
        // SOURCE: Query parameter
        const { directory } = req.query;

        // SINK: Directory traversal
        const files = PathTraversalSink.listDirectory(directory);

        res.json({ files });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: File Operations -> Command Injection
 * Source: req.body -> CommandSink
 */
router.post('/operations', async (req, res) => {
    try {
        const { operation, source, destination, options } = req.body;

        let result;

        switch (operation) {
            case 'copy':
                // SINK: Command injection in file copy
                result = await CommandSink.executeCommand(`cp ${options || ''} "${source}" "${destination}"`);
                break;

            case 'move':
                // SINK: Command injection in file move
                result = await CommandSink.executeCommand(`mv "${source}" "${destination}"`);
                break;

            case 'compress':
                // SINK: Command injection in compression
                result = await CommandSink.executeCommand(`tar -czvf "${destination}" "${source}"`);
                break;

            case 'extract':
                // SINK: Command injection in extraction
                result = await CommandSink.extractArchive(source, destination);
                break;

            case 'convert':
                // SINK: Command injection in file conversion
                result = await CommandSink.executeCommand(`convert "${source}" "${destination}"`);
                break;

            case 'checksum':
                // SINK: Command injection in checksum
                result = await CommandSink.executeCommand(`sha256sum "${source}"`);
                break;

            default:
                return res.status(400).json({ error: 'Unknown operation' });
        }

        res.json({ result });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: Remote File Fetch -> Path Traversal + Command Injection
 * Source: req.body.url -> SsrfSink -> PathTraversalSink -> CommandSink
 */
router.post('/fetch-and-process', async (req, res) => {
    try {
        const { url, savePath, postProcess } = req.body;

        // Step 1: SSRF - Fetch remote file
        const content = await SsrfSink.fetchUrl(url);

        // Step 2: Path traversal - Save to specified path
        PathTraversalSink.writeFile(savePath, content);

        // Step 3: Command injection - Post-process file
        let result = 'saved';
        if (postProcess) {
            result = await CommandSink.executeCommand(`${postProcess} "${savePath}"`);
        }

        res.json({
            fetched: url,
            saved: savePath,
            processed: result
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: Symlink Attack
 * Source: req.body -> PathTraversalSink (symlink creation)
 */
router.post('/symlink', (req, res) => {
    try {
        const { target, linkName } = req.body;

        // SINK: Symlink creation to arbitrary target
        PathTraversalSink.createSymlink(target, linkName);

        res.json({
            created: linkName,
            pointsTo: target
        });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

/**
 * MULTI-CHAIN: Bulk File Upload with Processing
 * Source: req.files (multiple) -> Multiple sinks
 */
router.post('/bulk-upload', async (req, res) => {
    try {
        const files = req.files;
        const { processCommand, outputDir } = req.body;

        if (!files) {
            return res.status(400).json({ error: 'No files uploaded' });
        }

        const results = [];

        for (const [key, file] of Object.entries(files)) {
            // SINK: Path traversal via filename
            const savedPath = FileUploadSink.saveUpload(file, '/var/app/uploads');

            // SINK: Command injection in processing
            if (processCommand) {
                const processResult = await CommandSink.executeWithArgs(
                    processCommand,
                    savedPath
                );
                results.push({ file: file.name, path: savedPath, processed: processResult });
            } else {
                results.push({ file: file.name, path: savedPath });
            }
        }

        res.json({ uploaded: results });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

module.exports = router;
