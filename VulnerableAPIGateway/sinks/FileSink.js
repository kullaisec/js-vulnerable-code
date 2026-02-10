/**
 * File Sink - Path Traversal and File System Vulnerabilities
 * Arbitrary file read/write and path manipulation attacks
 */

const fs = require('fs');
const fsp = require('fs').promises;
const path = require('path');
const archiver = require('archiver');
const unzipper = require('unzipper');

class PathTraversalSink {

    /**
     * SINK: Arbitrary file read via path concatenation
     */
    static readFile(filename) {
        // VULNERABLE: Direct path concatenation
        const filePath = '/var/app/data/' + filename;
        return fs.readFileSync(filePath, 'utf8');
    }

    /**
     * SINK: Arbitrary file read via path.join
     * path.join does NOT prevent traversal!
     */
    static readFileJoin(userPath) {
        // VULNERABLE: path.join doesn't prevent ../
        const filePath = path.join('/var/app/uploads', userPath);
        return fs.readFileSync(filePath, 'utf8');
    }

    /**
     * SINK: Arbitrary file write
     */
    static writeFile(filename, content) {
        // VULNERABLE: Write to arbitrary path
        const filePath = '/var/app/data/' + filename;
        fs.writeFileSync(filePath, content);
        return filePath;
    }

    /**
     * SINK: File deletion
     */
    static deleteFile(filename) {
        // VULNERABLE: Delete arbitrary files
        const filePath = path.join('/var/app/uploads', filename);
        fs.unlinkSync(filePath);
        return true;
    }

    /**
     * SINK: Directory listing
     */
    static listDirectory(dirName) {
        // VULNERABLE: List arbitrary directories
        const dirPath = '/var/app/' + dirName;
        return fs.readdirSync(dirPath);
    }

    /**
     * SINK: File copy with traversal
     */
    static copyFile(src, dest) {
        // VULNERABLE: Both paths user-controlled
        const srcPath = path.join('/var/app/uploads', src);
        const destPath = path.join('/var/app/uploads', dest);
        fs.copyFileSync(srcPath, destPath);
        return destPath;
    }

    /**
     * SINK: File rename/move
     */
    static moveFile(oldPath, newPath) {
        // VULNERABLE: Move files anywhere
        fs.renameSync(
            path.join('/var/app', oldPath),
            path.join('/var/app', newPath)
        );
        return true;
    }

    /**
     * SINK: Async file read with traversal
     */
    static async readFileAsync(userFilename) {
        // VULNERABLE: Template literal path construction
        const filePath = `/var/app/documents/${userFilename}`;
        return await fsp.readFile(filePath, 'utf8');
    }

    /**
     * SINK: Stream-based file read
     */
    static createReadStream(filename) {
        // VULNERABLE: Stream from arbitrary path
        const filePath = path.resolve('/var/app/files', filename);
        return fs.createReadStream(filePath);
    }

    /**
     * SINK: Symlink creation
     */
    static createSymlink(target, linkPath) {
        // VULNERABLE: Create symlink to arbitrary target
        fs.symlinkSync(target, path.join('/var/app/links', linkPath));
        return true;
    }
}

/**
 * Custom Sink: File Upload Handling
 */
class FileUploadSink {

    /**
     * SINK: Upload with original filename (path traversal)
     */
    static saveUpload(file, uploadDir) {
        // VULNERABLE: Original filename preserved
        const destPath = path.join(uploadDir, file.name);
        file.mv(destPath);
        return destPath;
    }

    /**
     * SINK: Upload with controlled extension
     */
    static saveWithExtension(file, newName, extension) {
        // VULNERABLE: User-controlled extension
        const destPath = `/var/app/uploads/${newName}.${extension}`;
        file.mv(destPath);
        return destPath;
    }

    /**
     * SINK: Upload to user-specified directory
     */
    static saveToDirectory(file, directory) {
        // VULNERABLE: User-controlled directory
        const destPath = path.join('/var/app', directory, file.name);
        fs.mkdirSync(path.dirname(destPath), { recursive: true });
        file.mv(destPath);
        return destPath;
    }

    /**
     * SINK: Upload with MIME type trust
     */
    static saveByMimeType(file) {
        // VULNERABLE: Trust user-provided MIME type
        const ext = file.mimetype.split('/')[1];
        const destPath = `/var/app/uploads/${Date.now()}.${ext}`;
        file.mv(destPath);
        return destPath;
    }
}

/**
 * Custom Sink: Archive Extraction (Zip Slip)
 */
class ArchiveSink {

    /**
     * SINK: Zip extraction with path traversal (Zip Slip)
     */
    static async extractZip(zipPath, extractTo) {
        // VULNERABLE: Zip slip vulnerability
        const directory = await unzipper.Open.file(zipPath);

        for (const entry of directory.files) {
            // VULNERABLE: No validation of entry path
            const destPath = path.join(extractTo, entry.path);

            if (entry.type === 'Directory') {
                fs.mkdirSync(destPath, { recursive: true });
            } else {
                const content = await entry.buffer();
                fs.writeFileSync(destPath, content);
            }
        }

        return extractTo;
    }

    /**
     * SINK: Tar extraction vulnerability
     */
    static async extractTar(tarPath, extractTo) {
        const tar = require('tar');

        // VULNERABLE: No path validation
        await tar.extract({
            file: tarPath,
            cwd: extractTo,
            preservePaths: true  // Dangerous option
        });

        return extractTo;
    }

    /**
     * SINK: Create archive with user paths
     */
    static createZip(outputPath, filePaths) {
        return new Promise((resolve, reject) => {
            const output = fs.createWriteStream(outputPath);
            const archive = archiver('zip');

            output.on('close', () => resolve(outputPath));
            archive.on('error', reject);
            archive.pipe(output);

            // VULNERABLE: Add files from user-specified paths
            for (const filePath of filePaths) {
                archive.file(filePath, { name: path.basename(filePath) });
            }

            archive.finalize();
        });
    }
}

/**
 * Custom Sink: Log File Writing
 */
class LogSink {

    /**
     * SINK: Log injection via user data
     */
    static writeLog(logFile, message) {
        // VULNERABLE: Log to user-specified file
        const logPath = `/var/log/app/${logFile}`;
        const timestamp = new Date().toISOString();
        fs.appendFileSync(logPath, `[${timestamp}] ${message}\n`);
    }

    /**
     * SINK: Log forging via newlines
     */
    static logUserAction(userId, action) {
        // VULNERABLE: Newlines can forge log entries
        const logMessage = `User ${userId} performed action: ${action}`;
        fs.appendFileSync('/var/log/app/audit.log', logMessage + '\n');
    }
}

module.exports = {
    PathTraversalSink,
    FileUploadSink,
    ArchiveSink,
    LogSink
};
