/**
 * Command Sink - Command Injection Vulnerabilities
 * Various patterns of command execution with tainted data
 */

const { exec, execSync, spawn, spawnSync } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);

class CommandSink {

    /**
     * SINK: Direct command injection via exec
     * Tainted data directly in shell command
     */
    static async executeCommand(command) {
        // VULNERABLE: Direct execution of user input
        const { stdout, stderr } = await execPromise(command);
        return { stdout, stderr };
    }

    /**
     * SINK: Command injection via string interpolation
     */
    static async executeWithArgs(binary, userArg) {
        // VULNERABLE: String interpolation with user input
        const command = `${binary} ${userArg}`;
        const { stdout } = await execPromise(command);
        return stdout;
    }

    /**
     * SINK: Command injection via template literal
     */
    static runSystemCommand(action, target) {
        // VULNERABLE: Template literal with user input
        const cmd = `systemctl ${action} ${target}`;
        return execSync(cmd).toString();
    }

    /**
     * SINK: Command injection in file operations
     */
    static async processFile(filename, operation) {
        // VULNERABLE: Filename in command
        const command = `${operation} /data/uploads/${filename}`;
        return await execPromise(command);
    }

    /**
     * SINK: Command injection via concatenation
     */
    static searchInFiles(pattern, directory) {
        // VULNERABLE: Pattern and directory from user
        const cmd = 'grep -r "' + pattern + '" ' + directory;
        return execSync(cmd).toString();
    }

    /**
     * SINK: Command injection with environment variable
     */
    static runWithEnv(command, envVars) {
        // VULNERABLE: User-controlled environment
        return execSync(command, {
            env: { ...process.env, ...envVars }
        }).toString();
    }

    /**
     * SINK: Command injection via spawn (less obvious)
     */
    static spawnProcess(cmd, args) {
        // VULNERABLE: When args are not properly sanitized
        return new Promise((resolve, reject) => {
            const proc = spawn(cmd, args, { shell: true });  // shell: true is dangerous
            let output = '';

            proc.stdout.on('data', (data) => output += data);
            proc.stderr.on('data', (data) => output += data);
            proc.on('close', (code) => resolve({ output, code }));
            proc.on('error', reject);
        });
    }

    /**
     * SINK: OS command in curl request
     */
    static async fetchUrl(url) {
        // VULNERABLE: URL in command
        const command = `curl -s "${url}"`;
        return await execPromise(command);
    }

    /**
     * SINK: Command injection in image processing
     */
    static async convertImage(inputPath, outputPath, format) {
        // VULNERABLE: All paths and format from user
        const cmd = `convert ${inputPath} -format ${format} ${outputPath}`;
        return await execPromise(cmd);
    }

    /**
     * SINK: Command injection in git operations
     */
    static gitClone(repoUrl, targetDir) {
        // VULNERABLE: URL and directory from user
        const cmd = `git clone ${repoUrl} ${targetDir}`;
        return execSync(cmd).toString();
    }

    /**
     * SINK: Command injection in archive extraction
     */
    static extractArchive(archivePath, extractTo) {
        // VULNERABLE: Both paths from user
        const cmd = `tar -xzf ${archivePath} -C ${extractTo}`;
        return execSync(cmd).toString();
    }

    /**
     * SINK: Command injection in PDF generation
     */
    static generatePdf(htmlContent, outputPath) {
        // VULNERABLE: Content could contain shell metacharacters
        const cmd = `wkhtmltopdf - ${outputPath} <<< "${htmlContent}"`;
        return execSync(cmd).toString();
    }

    /**
     * SINK: Indirect command injection via config
     */
    static runFromConfig(config) {
        // VULNERABLE: Config values from user input
        const cmd = `${config.binary} --config=${config.configFile} --output=${config.outputDir}`;
        return execSync(cmd).toString();
    }
}

/**
 * Custom Sink: Docker Command Execution
 */
class DockerSink {

    // SINK: Docker exec with user input
    static async dockerExec(containerId, command) {
        const cmd = `docker exec ${containerId} ${command}`;
        return await execPromise(cmd);
    }

    // SINK: Docker run with user image
    static async dockerRun(image, command) {
        const cmd = `docker run --rm ${image} ${command}`;
        return await execPromise(cmd);
    }

    // SINK: Docker build with user Dockerfile
    static dockerBuild(dockerfilePath, tag) {
        const cmd = `docker build -f ${dockerfilePath} -t ${tag} .`;
        return execSync(cmd).toString();
    }
}

/**
 * Custom Sink: SSH Command Execution
 */
class SshSink {

    // SINK: SSH command with user input
    static async sshExecute(host, user, command) {
        const cmd = `ssh ${user}@${host} "${command}"`;
        return await execPromise(cmd);
    }

    // SINK: SCP file transfer
    static async scpTransfer(localPath, remoteHost, remotePath) {
        const cmd = `scp ${localPath} ${remoteHost}:${remotePath}`;
        return await execPromise(cmd);
    }
}

module.exports = {
    CommandSink,
    DockerSink,
    SshSink
};
