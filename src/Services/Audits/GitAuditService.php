<?php

namespace Dgtlss\Warden\Services\Audits;

use Symfony\Component\Process\Process;
use Symfony\Component\Process\Exception\ProcessFailedException;
use Illuminate\Support\Facades\Log;
use Exception;

class GitAuditService extends AbstractAuditService
{
    protected string $repositoryPath;
    protected array $secretPatterns = [];
    protected array $fileExtensions = [];
    protected array $excludePaths = [];

    public function getName(): string
    {
        return 'Git Security Audit';
    }

    protected function getDefaultConfig(): array
    {
        return array_merge(parent::getDefaultConfig(), [
            'repository_path' => base_path(),
            'scan_history' => true,
            'scan_staged' => true,
            'scan_working_tree' => true,
            'max_commits' => 100,
            'check_secrets' => true,
            'check_credentials' => true,
            'check_keys' => true,
            'check_tokens' => true,
            'check_api_keys' => true,
            'check_certificates' => true,
            'check_passwords' => true,
            'check_sensitive_files' => true,
            'check_large_files' => true,
            'check_binary_files' => true,
            'max_file_size' => 1048576, // 1MB
            'severity_threshold' => 'medium', // low|medium|high|critical
            'timeout' => 300, // 5 minutes for git operations
            'exclude_paths' => [
                'vendor/',
                'node_modules/',
                '.git/',
                'storage/',
                'bootstrap/cache/',
                'tests/',
                '*.log',
                '*.tmp',
            ],
            'include_extensions' => [
                'php', 'js', 'ts', 'jsx', 'tsx', 'vue', 'py', 'rb', 'java', 'go', 'rs', 'c', 'cpp', 'h',
                'yml', 'yaml', 'json', 'xml', 'ini', 'conf', 'config', 'env', 'sh', 'bash', 'zsh',
                'sql', 'md', 'txt', 'html', 'css', 'scss', 'less', 'dockerfile',
            ],
            'custom_patterns' => [],
        ]);
    }

    protected function onInitialize(): void
    {
        $this->repositoryPath = $this->getConfigValue('repository_path', base_path());
        
        // Handle string to array conversion for exclude_paths
        $excludePaths = $this->getConfigValue('exclude_paths', []);
        if (is_string($excludePaths)) {
            $this->excludePaths = explode(',', $excludePaths);
        } else {
            $this->excludePaths = $excludePaths;
        }
        
        // Handle string to array conversion for include_extensions
        $fileExtensions = $this->getConfigValue('include_extensions', []);
        if (is_string($fileExtensions)) {
            $this->fileExtensions = explode(',', $fileExtensions);
        } else {
            $this->fileExtensions = $fileExtensions;
        }
        
        $this->initializeSecretPatterns();
    }

    protected function onShouldRun(): bool
    {
        // Check if this is a git repository
        if (!$this->isGitRepository()) {
            $this->info('Not a Git repository, skipping Git audit');
            return false;
        }

        return true;
    }

    public function run(): bool
    {
        try {
            $this->info('Starting Git security audit');

            // Scan working tree if enabled
            if ($this->getConfigValue('scan_working_tree', true)) {
                $this->scanWorkingTree();
            }

            // Scan staged files if enabled
            if ($this->getConfigValue('scan_staged', true)) {
                $this->scanStagedFiles();
            }

            // Scan git history if enabled
            if ($this->getConfigValue('scan_history', true)) {
                $this->scanGitHistory();
            }

            // Check for sensitive files
            if ($this->getConfigValue('check_sensitive_files', true)) {
                $this->checkSensitiveFiles();
            }

            // Check for large files
            if ($this->getConfigValue('check_large_files', true)) {
                $this->checkLargeFiles();
            }

            $this->info('Git security audit completed');
            return empty($this->findings);

        } catch (Exception $e) {
            $this->error('Git audit failed: ' . $e->getMessage());
            $this->addFinding([
                'package' => 'git-audit',
                'title' => 'Git Audit Failed',
                'description' => 'The Git security audit encountered an error: ' . $e->getMessage(),
                'severity' => 'high',
                'cve' => null,
                'affected_versions' => 'all',
                'fix_version' => null,
                'link' => null,
                'error' => $e->getMessage(),
            ]);
            return false;
        }
    }

    protected function initializeSecretPatterns(): void
    {
        $this->secretPatterns = [
            // AWS Keys
            'aws_access_key_id' => [
                'pattern' => '/AKIA[0-9A-Z]{16}/i',
                'description' => 'AWS Access Key ID',
                'severity' => 'critical',
            ],
            'aws_secret_access_key' => [
                'pattern' => '/aws[_-]?secret[_-]?access[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9\/+=]{40})["\']?/i',
                'description' => 'AWS Secret Access Key',
                'severity' => 'critical',
            ],

            // Google Cloud Keys
            'gcp_service_account_key' => [
                'pattern' => '/"private_key":\s*"-----BEGIN\s+PRIVATE\s+KEY-----/i',
                'description' => 'Google Cloud Service Account Private Key',
                'severity' => 'critical',
            ],

            // Azure Keys
            'azure_client_secret' => [
                'pattern' => '/client[_-]?secret\s*[:=]\s*["\']?([A-Za-z0-9\-_~]{36,})["\']?/i',
                'description' => 'Azure Client Secret',
                'severity' => 'critical',
            ],

            // GitHub Tokens
            'github_token' => [
                'pattern' => '/ghp_[A-Za-z0-9]{36}/i',
                'description' => 'GitHub Personal Access Token',
                'severity' => 'critical',
            ],
            'github_oauth' => [
                'pattern' => '/github_oauth[_-]?token\s*[:=]\s*["\']?([A-Za-z0-9]{40})["\']?/i',
                'description' => 'GitHub OAuth Token',
                'severity' => 'critical',
            ],

            // Database URLs and Credentials
            'database_url' => [
                'pattern' => '/(mysql|postgresql|mongodb|redis):\/\/[^:]+:[^@]+@[^\/]+/i',
                'description' => 'Database URL with credentials',
                'severity' => 'high',
            ],

            // API Keys
            'api_key_generic' => [
                'pattern' => '/api[_-]?key\s*[:=]\s*["\']?([A-Za-z0-9\-_]{16,})["\']?/i',
                'description' => 'Generic API Key',
                'severity' => 'high',
            ],

            // JWT Tokens
            'jwt_token' => [
                'pattern' => '/eyJ[A-Za-z0-9\-_=]+\.[A-Za-z0-9\-_=]+\.?[A-Za-z0-9\-_.+\/=]*/i',
                'description' => 'JWT Token',
                'severity' => 'medium',
            ],

            // Private Keys
            'private_key_rsa' => [
                'pattern' => '/-----BEGIN\s+RSA\s+PRIVATE\s+KEY-----/i',
                'description' => 'RSA Private Key',
                'severity' => 'critical',
            ],
            'private_key_generic' => [
                'pattern' => '/-----BEGIN\s+(?:DSA|EC|OPENSSH)?\s*PRIVATE\s+KEY-----/i',
                'description' => 'Private Key',
                'severity' => 'critical',
            ],

            // Certificates
            'certificate' => [
                'pattern' => '/-----BEGIN\s+CERTIFICATE-----/i',
                'description' => 'SSL Certificate',
                'severity' => 'medium',
            ],

            // Passwords
            'password_in_url' => [
                'pattern' => '/[a-zA-Z][a-zA-Z0-9+.-]*:\/\/[^:\/\s]+:[^@\/\s]+@[^\/\s]+/i',
                'description' => 'Password in URL',
                'severity' => 'high',
            ],
            'password_field' => [
                'pattern' => '/password\s*[:=]\s*["\']?([^"\'\s]{8,})["\']?/i',
                'description' => 'Password Field',
                'severity' => 'medium',
            ],

            // SSH Keys
            'ssh_private_key' => [
                'pattern' => '/-----BEGIN\s+OPENSSH\s+PRIVATE\s+KEY-----/i',
                'description' => 'SSH Private Key',
                'severity' => 'critical',
            ],
            'ssh_public_key' => [
                'pattern' => '/ssh-(rsa|dss|ed25519)\s+[A-Za-z0-9\/+]+/i',
                'description' => 'SSH Public Key',
                'severity' => 'medium',
            ],

            // Slack Tokens
            'slack_token' => [
                'pattern' => '/xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9]{12}-[a-z0-9]{32}/i',
                'description' => 'Slack Token',
                'severity' => 'high',
            ],

            // Stripe Keys
            'stripe_key' => [
                'pattern' => '/sk_(live|test)_[0-9a-zA-Z]{24}/i',
                'description' => 'Stripe API Key',
                'severity' => 'critical',
            ],

            // Twilio Keys
            'twilio_key' => [
                'pattern' => '/AC[a-z0-9]{32}/i',
                'description' => 'Twilio Account SID',
                'severity' => 'high',
            ],

            // SendGrid Keys
            'sendgrid_key' => [
                'pattern' => '/SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}/i',
                'description' => 'SendGrid API Key',
                'severity' => 'high',
            ],

            // Auth0 Keys
            'auth0_secret' => [
                'pattern' => '/[a-zA-Z0-9_-]{43}/i',
                'description' => 'Auth0 Client Secret',
                'severity' => 'high',
            ],
        ];

        // Add custom patterns from configuration
        $customPatterns = $this->getConfigValue('custom_patterns', []);
        if (is_string($customPatterns)) {
            // Handle JSON string or empty string
            $customPatterns = json_decode($customPatterns, true) ?: [];
        }
        
        if (is_array($customPatterns)) {
            foreach ($customPatterns as $name => $pattern) {
                $this->secretPatterns[$name] = $pattern;
            }
        }
    }

    protected function isGitRepository(): bool
    {
        return is_dir($this->repositoryPath . '/.git');
    }

    protected function scanWorkingTree(): void
    {
        $this->info('Scanning working tree for secrets');

        try {
            $process = $this->createGitProcess(['ls-files', '-z']);
            $process->run();

            if (!$process->isSuccessful()) {
                $this->warning('Failed to list files in working tree: ' . $process->getErrorOutput());
                return;
            }

            $files = explode("\0", trim($process->getOutput(), "\0"));
            $this->scanFiles($files, 'working tree');

        } catch (Exception $e) {
            $this->warning('Working tree scan failed: ' . $e->getMessage());
        }
    }

    protected function scanStagedFiles(): void
    {
        $this->info('Scanning staged files for secrets');

        try {
            $process = $this->createGitProcess(['diff', '--cached', '--name-only', '-z']);
            $process->run();

            if (!$process->isSuccessful()) {
                $this->warning('Failed to list staged files: ' . $process->getErrorOutput());
                return;
            }

            $files = explode("\0", trim($process->getOutput(), "\0"));
            $this->scanFiles($files, 'staged');

        } catch (Exception $e) {
            $this->warning('Staged files scan failed: ' . $e->getMessage());
        }
    }

    protected function scanGitHistory(): void
    {
        $this->info('Scanning Git history for secrets');

        try {
            $maxCommits = $this->getConfigValue('max_commits', 100);
            
            $process = $this->createGitProcess(['log', '--pretty=format:%H', "-n{$maxCommits}"]);
            $process->run();

            if (!$process->isSuccessful()) {
                $this->warning('Failed to get commit history: ' . $process->getErrorOutput());
                return;
            }

            $commits = array_filter(explode("\n", $process->getOutput()));
            
            foreach ($commits as $commit) {
                $this->scanCommit($commit);
            }

        } catch (Exception $e) {
            $this->warning('Git history scan failed: ' . $e->getMessage());
        }
    }

    protected function scanCommit(string $commit): void
    {
        try {
            // Get files changed in this commit
            $process = $this->createGitProcess(['diff-tree', '--no-commit-id', '--name-only', '-r', $commit]);
            $process->run();

            if (!$process->isSuccessful()) {
                return;
            }

            $files = array_filter(explode("\n", $process->getOutput()));
            $this->scanFilesInCommit($files, $commit);

        } catch (Exception $e) {
            $this->warning("Failed to scan commit {$commit}: " . $e->getMessage());
        }
    }

    protected function scanFiles(array $files, string $context): void
    {
        foreach ($files as $file) {
            if (empty($file)) {
                continue;
            }

            if ($this->shouldExcludeFile($file)) {
                continue;
            }

            $filePath = $this->repositoryPath . '/' . $file;
            
            if (!file_exists($filePath)) {
                continue;
            }

            $this->scanFile($filePath, $file, $context);
        }
    }

    protected function scanFilesInCommit(array $files, string $commit): void
    {
        foreach ($files as $file) {
            if (empty($file) || $this->shouldExcludeFile($file)) {
                continue;
            }

            try {
                $process = $this->createGitProcess(['show', "{$commit}:{$file}"]);
                $process->run();

                if ($process->isSuccessful()) {
                    $content = $process->getOutput();
                    $this->scanContent($content, $file, "commit {$commit}");
                }

            } catch (Exception $e) {
                $this->warning("Failed to scan file {$file} in commit {$commit}: " . $e->getMessage());
            }
        }
    }

    protected function scanFile(string $filePath, string $relativePath, string $context): void
    {
        // Check file size
        $fileSize = filesize($filePath);
        $maxFileSize = $this->getConfigValue('max_file_size', 1048576);
        
        if ($fileSize > $maxFileSize) {
            $this->addFinding([
                'package' => 'git-file-size',
                'title' => 'Large File Detected',
                'description' => "File '{$relativePath}' is large ({$this->formatBytes($fileSize)}) and may contain sensitive data.",
                'severity' => 'low',
                'cve' => null,
                'affected_versions' => 'all',
                'fix_version' => null,
                'link' => null,
                'file' => $relativePath,
                'context' => $context,
            ]);
            return;
        }

        // Check if it's a binary file
        if ($this->isBinaryFile($filePath)) {
            if ($this->getConfigValue('check_binary_files', true)) {
                $this->addFinding([
                    'package' => 'git-binary-file',
                    'title' => 'Binary File Detected',
                    'description' => "Binary file '{$relativePath}' found in repository. Binary files should not be committed unless necessary.",
                    'severity' => 'low',
                    'cve' => null,
                    'affected_versions' => 'all',
                    'fix_version' => null,
                    'link' => null,
                    'file' => $relativePath,
                    'context' => $context,
                ]);
            }
            return;
        }

        $content = file_get_contents($filePath);
        $this->scanContent($content, $relativePath, $context);
    }

    protected function scanContent(string $content, string $file, string $context): void
    {
        foreach ($this->secretPatterns as $patternName => $patternInfo) {
            if (!$this->isPatternEnabled($patternName)) {
                continue;
            }

            if (preg_match_all($patternInfo['pattern'], $content, $matches, PREG_OFFSET_CAPTURE)) {
                foreach ($matches[0] as $match) {
                    $lineNumber = $this->getLineNumber($content, $match[1]);
                    
                    $this->addFinding([
                        'package' => 'git-secret',
                        'title' => $patternInfo['description'],
                        'description' => "Potential {$patternInfo['description']} found in file '{$file}' at line {$lineNumber}.",
                        'severity' => $patternInfo['severity'],
                        'cve' => null,
                        'affected_versions' => 'all',
                        'fix_version' => null,
                        'link' => null,
                        'file' => $file,
                        'line' => $lineNumber,
                        'context' => $context,
                        'pattern' => $patternName,
                        'match' => $this->truncateMatch($match[0]),
                    ]);
                }
            }
        }
    }

    protected function checkSensitiveFiles(): void
    {
        $this->info('Checking for sensitive files');

        $sensitiveFiles = [
            '.env' => 'Environment file',
            '.env.local' => 'Local environment file',
            '.env.production' => 'Production environment file',
            'id_rsa' => 'SSH private key',
            'id_dsa' => 'SSH private key',
            'id_ecdsa' => 'SSH private key',
            'id_ed25519' => 'SSH private key',
            '.pem' => 'PEM certificate/key file',
            '.key' => 'Private key file',
            '.crt' => 'Certificate file',
            '.p12' => 'PKCS12 certificate file',
            '.pfx' => 'PKCS12 certificate file',
            'dump.sql' => 'Database dump',
            'backup.sql' => 'Database backup',
            '.htpasswd' => 'Apache password file',
            'web.config' => 'IIS configuration file',
        ];

        try {
            $process = $this->createGitProcess(['ls-files', '-z']);
            $process->run();

            if (!$process->isSuccessful()) {
                return;
            }

            $files = explode("\0", trim($process->getOutput(), "\0"));

            foreach ($files as $file) {
                if (empty($file)) {
                    continue;
                }

                foreach ($sensitiveFiles as $pattern => $description) {
                    if (fnmatch("*{$pattern}", $file) || fnmatch("*/{$pattern}", $file)) {
                        $this->addFinding([
                            'package' => 'git-sensitive-file',
                            'title' => 'Sensitive File Detected',
                            'description' => "Sensitive file '{$description}' found: '{$file}'",
                            'severity' => 'high',
                            'cve' => null,
                            'affected_versions' => 'all',
                            'fix_version' => null,
                            'link' => null,
                            'file' => $file,
                            'context' => 'repository',
                        ]);
                    }
                }
            }

        } catch (Exception $e) {
            $this->warning('Sensitive files check failed: ' . $e->getMessage());
        }
    }

    protected function checkLargeFiles(): void
    {
        $this->info('Checking for large files');

        try {
            $process = $this->createGitProcess(['ls-files', '-z']);
            $process->run();

            if (!$process->isSuccessful()) {
                return;
            }

            $files = explode("\0", trim($process->getOutput(), "\0"));
            $threshold = $this->getConfigValue('max_file_size', 1048576);

            foreach ($files as $file) {
                if (empty($file)) {
                    continue;
                }

                $filePath = $this->repositoryPath . '/' . $file;
                
                if (file_exists($filePath)) {
                    $fileSize = filesize($filePath);
                    
                    if ($fileSize > $threshold) {
                        $this->addFinding([
                            'package' => 'git-large-file',
                            'title' => 'Large File in Repository',
                            'description' => "Large file '{$file}' ({$this->formatBytes($fileSize)}) detected in repository.",
                            'severity' => 'medium',
                            'cve' => null,
                            'affected_versions' => 'all',
                            'fix_version' => null,
                            'link' => null,
                            'file' => $file,
                            'size' => $fileSize,
                            'context' => 'repository',
                        ]);
                    }
                }
            }

        } catch (Exception $e) {
            $this->warning('Large files check failed: ' . $e->getMessage());
        }
    }

    protected function shouldExcludeFile(string $file): bool
    {
        foreach ($this->excludePaths as $excludePath) {
            if (fnmatch($excludePath, $file) || strpos($file, $excludePath) === 0) {
                return true;
            }
        }

        // Check file extension
        if (!empty($this->fileExtensions)) {
            $extension = pathinfo($file, PATHINFO_EXTENSION);
            if (!in_array($extension, $this->fileExtensions)) {
                return true;
            }
        }

        return false;
    }

    protected function isPatternEnabled(string $patternName): bool
    {
        $configKey = "check_{$patternName}";
        return $this->getConfigValue($configKey, true);
    }

    protected function isBinaryFile(string $filePath): bool
    {
        $handle = fopen($filePath, 'rb');
        $chunk = fread($handle, 1024);
        fclose($handle);

        return strpos($chunk, "\0") !== false;
    }

    protected function getLineNumber(string $content, int $offset): int
    {
        $before = substr($content, 0, $offset);
        return substr_count($before, "\n") + 1;
    }

    protected function truncateMatch(string $match): string
    {
        if (strlen($match) > 50) {
            return substr($match, 0, 47) . '...';
        }
        return $match;
    }

    protected function formatBytes(int $bytes): string
    {
        $units = ['B', 'KB', 'MB', 'GB'];
        $bytes = max($bytes, 0);
        $pow = floor(($bytes ? log($bytes) : 0) / log(1024));
        $pow = min($pow, count($units) - 1);
        
        $bytes /= (1 << (10 * $pow));
        
        return round($bytes, 2) . ' ' . $units[$pow];
    }

    protected function createGitProcess(array $command): Process
    {
        $process = new Process(array_merge(['git'], $command), $this->repositoryPath);
        $process->setTimeout($this->getTimeout());
        
        return $process;
    }
}