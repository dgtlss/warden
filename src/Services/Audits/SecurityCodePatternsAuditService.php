<?php

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Abstracts\AbstractAuditService;
use Illuminate\Support\Facades\File;
use RecursiveDirectoryIterator;
use RecursiveIteratorIterator;
use SplFileInfo;

class SecurityCodePatternsAuditService extends AbstractAuditService
{
    protected array $patterns = [];
    protected array $findings = [];
    protected array $scannedFiles = [];
    protected array $excludedDirectories = [];
    protected array $excludedFiles = [];
    protected array $includedExtensions = ['.php'];

    /**
     * Initialize the audit service with configuration.
     *
     * @param array $config
     * @return void
     */
    public function initialize(array $config = []): void
    {
        parent::initialize($config);
        
        $this->excludedDirectories = $this->getConfig('exclude_directories', [
            'vendor',
            'node_modules',
            'storage',
            'bootstrap/cache',
            '.git',
            'tests',
        ]);
        
        $this->excludedFiles = $this->getConfig('exclude_files', [
            '*.min.php',
            'vendor/*',
            'node_modules/*',
        ]);
        
        $this->includedExtensions = $this->getConfig('included_extensions', ['.php']);
        
        $this->loadSecurityPatterns();
    }

    /**
     * Load security patterns for detection.
     *
     * @return void
     */
    protected function loadSecurityPatterns(): void
    {
        $this->patterns = [
            // SQL Injection Patterns
            'sql_injection' => [
                'name' => 'SQL Injection',
                'severity' => 'critical',
                'patterns' => [
                    '/\$_(GET|POST|REQUEST|COOKIE)\[.*?\].*?(mysql_query|mysqli_query|pg_query|query)\s*\(/i',
                    '/\$_(GET|POST|REQUEST|COOKIE)\[.*?\].*?(prepare|execute).*?\$/i',
                    '/\$_(GET|POST|REQUEST|COOKIE)\[.*?\].*?(SELECT|INSERT|UPDATE|DELETE).*?FROM/i',
                    '/sprintf.*?%s.*?\$_(GET|POST|REQUEST|COOKIE)/i',
                ],
                'description' => 'Potential SQL injection vulnerability detected'
            ],

            // Cross-Site Scripting (XSS)
            'xss' => [
                'name' => 'Cross-Site Scripting (XSS)',
                'severity' => 'high',
                'patterns' => [
                    '/echo.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]/i',
                    '/print.*?\$_(GET|POST|REQUEST|COOKIE)\[.*?\]/i',
                    '/\$_(GET|POST|REQUEST|COOKIE)\[.*?\].*?<(script|iframe|object|embed)/i',
                    '/htmlspecialchars.*?\$_(GET|POST|REQUEST|COOKIE).*?(?!.*ENT_QUOTES|.*HTML_SPECIALCHARS)/i',
                ],
                'description' => 'Potential XSS vulnerability detected'
            ],

            // Command Injection
            'command_injection' => [
                'name' => 'Command Injection',
                'severity' => 'critical',
                'patterns' => [
                    '/(exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
                    '/(exec|shell_exec|system|passthru|popen|proc_open)\s*\(\s*["\'].*?\$.*?["\']\s*\)/i',
                    '/backtick.*?\$_(GET|POST|REQUEST|COOKIE)/i',
                ],
                'description' => 'Potential command injection vulnerability detected'
            ],

            // File Inclusion
            'file_inclusion' => [
                'name' => 'File Inclusion Vulnerability',
                'severity' => 'high',
                'patterns' => [
                    '/(include|require|include_once|require_once)\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
                    '/(include|require|include_once|require_once)\s*\(\s*\$.*?\$_(GET|POST|REQUEST|COOKIE)/i',
                    '/file_get_contents\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
                    '/fopen\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
                ],
                'description' => 'Potential file inclusion vulnerability detected'
            ],

            // Hardcoded Credentials
            'hardcoded_credentials' => [
                'name' => 'Hardcoded Credentials',
                'severity' => 'high',
                'patterns' => [
                    '/(password|passwd|pwd)\s*=\s*["\'][^"\']{4,}["\']/i',
                    '/(api_key|apikey|secret)\s*=\s*["\'][^"\']{10,}["\']/i',
                    '/(db_host|db_user|db_pass|db_name)\s*=\s*["\'][^"\']+/i',
                    '/(token|auth_key|private_key)\s*=\s*["\'][^"\']{20,}["\']/i',
                ],
                'description' => 'Hardcoded credentials detected'
            ],

            // Weak Cryptographic Functions
            'weak_crypto' => [
                'name' => 'Weak Cryptographic Functions',
                'severity' => 'medium',
                'patterns' => [
                    '/md5\s*\(/i',
                    '/sha1\s*\(/i',
                    '/crc32\s*\(/i',
                    '/(crypt|encrypt).*?(md5|sha1)/i',
                    '/base64_encode.*?(password|secret|key)/i',
                ],
                'description' => 'Weak cryptographic function detected'
            ],

            // Insecure Random Number Generation
            'weak_random' => [
                'name' => 'Insecure Random Number Generation',
                'severity' => 'medium',
                'patterns' => [
                    '/rand\s*\(\s*\)/i',
                    '/mt_rand\s*\(\s*\)/i',
                    '/random_int\s*\(\s*[^,]*,\s*[^)]*\s*\)/i',
                    '/uniqid\s*\(\s*["\']?\s*["\']?\s*\)/i',
                ],
                'description' => 'Insecure random number generation detected'
            ],

            // Insecure File Upload
            'insecure_upload' => [
                'name' => 'Insecure File Upload',
                'severity' => 'high',
                'patterns' => [
                    '/move_uploaded_file\s*\(\s*\$_FILES\[/i',
                    '/\$_FILES\[.*?\]\[.*?name.*?\]/i',
                    '/(file_get_contents|fopen).*?\$_FILES/i',
                    '/(exec|shell_exec|system).*?\$_FILES/i',
                ],
                'description' => 'Potential insecure file upload detected'
            ],

            // Insecure Session Management
            'insecure_session' => [
                'name' => 'Insecure Session Management',
                'severity' => 'medium',
                'patterns' => [
                    '/session_id\s*\(\s*\)/i',
                    '/session_regenerate_id\s*\(\s*false\s*\)/i',
                    '/session_start\s*\(\s*\)/i',
                    '/\$_SESSION\[.*?\].*?(password|secret|key)/i',
                ],
                'description' => 'Insecure session management detected'
            ],

            // Insecure Deserialization
            'insecure_deserialization' => [
                'name' => 'Insecure Deserialization',
                'severity' => 'critical',
                'patterns' => [
                    '/unserialize\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
                    '/unserialize\s*\(\s*\$.*?\$_(GET|POST|REQUEST|COOKIE)/i',
                    '/(json_decode|simplexml_load_string).*?\$_(GET|POST|REQUEST|COOKIE)/i',
                ],
                'description' => 'Potential insecure deserialization detected'
            ],

            // Information Disclosure
            'information_disclosure' => [
                'name' => 'Information Disclosure',
                'severity' => 'low',
                'patterns' => [
                    '/(error_reporting|ini_set).*?E_ALL/i',
                    '/var_dump\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
                    '/print_r\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)/i',
                    '/(phpinfo|debug_backtrace|debug_print_backtrace)\s*\(/i',
                ],
                'description' => 'Potential information disclosure detected'
            ],

            // Insecure Direct Object Reference
            'idor' => [
                'name' => 'Insecure Direct Object Reference',
                'severity' => 'medium',
                'patterns' => [
                    '/\$_(GET|POST|REQUEST)\[.*(id|user_id|file_id|order_id).*\].*?(SELECT|UPDATE|DELETE)/i',
                    '/\$_(GET|POST|REQUEST)\[.*(id|user_id|file_id|order_id).*\].*?(include|require|file_get_contents)/i',
                ],
                'description' => 'Potential insecure direct object reference detected'
            ],

            // LDAP Injection
            'ldap_injection' => [
                'name' => 'LDAP Injection',
                'severity' => 'high',
                'patterns' => [
                    '/ldap_search\s*\(\s*.*?\$_(GET|POST|REQUEST|COOKIE)/i',
                    '/ldap_bind\s*\(\s*.*?\$_(GET|POST|REQUEST|COOKIE)/i',
                    '/\$_(GET|POST|REQUEST|COOKIE).*?[(][)]*[(][)]/i',
                ],
                'description' => 'Potential LDAP injection vulnerability detected'
            ],

            // XML External Entity (XXE)
            'xxe' => [
                'name' => 'XML External Entity (XXE)',
                'severity' => 'high',
                'patterns' => [
                    '/simplexml_load_file\s*\(/i',
                    '/simplexml_load_string\s*\(/i',
                    '/DOMDocument::load\s*\(/i',
                    '/xml_parser_create\s*\(/i',
                ],
                'description' => 'Potential XXE vulnerability detected'
            ],

            // Insecure Headers
            'insecure_headers' => [
                'name' => 'Insecure Headers',
                'severity' => 'low',
                'patterns' => [
                    '/header\s*\(\s*["\'].*?X-Frame-Options.*?DENY/i',
                    '/header\s*\(\s*["\'].*?X-Content-Type-Options.*?nosniff/i',
                    '/header\s*\(\s*["\'].*?Strict-Transport-Security/i',
                ],
                'description' => 'Missing security headers detected'
            ],
        ];

        // Add custom patterns from configuration
        $customPatterns = $this->getConfig('custom_patterns', []);
        foreach ($customPatterns as $name => $pattern) {
            if (isset($pattern['patterns']) && isset($pattern['severity'])) {
                $this->patterns[$name] = [
                    'name' => $pattern['name'] ?? $name,
                    'severity' => $pattern['severity'],
                    'patterns' => (array) $pattern['patterns'],
                    'description' => $pattern['description'] ?? "Custom pattern: {$name}"
                ];
            }
        }
    }

    /**
     * Run the security code patterns audit.
     *
     * @return bool
     */
    public function run(): bool
    {
        try {
            $this->info('Starting Security Code Patterns Audit...');

            $scanPaths = $this->getScanPaths();
            $totalFiles = 0;

            foreach ($scanPaths as $path) {
                if (is_dir($path)) {
                    $files = $this->getPhpFiles($path);
                    $totalFiles += count($files);
                    
                    $this->info("Scanning " . count($files) . " PHP files in {$path}...");
                    
                    foreach ($files as $file) {
                        $this->scanFile($file);
                    }
                } elseif (is_file($path) && in_array(pathinfo($path, PATHINFO_EXTENSION), ['php'])) {
                    $totalFiles++;
                    $this->scanFile($path);
                }
            }

            $this->info("Security Code Patterns Audit completed. Scanned {$totalFiles} files.");
            $this->info("Found " . count($this->findings) . " security issues.");

            return empty($this->findings);

        } catch (\Exception $e) {
            $this->error("Security Code Patterns Audit failed: " . $e->getMessage());
            return false;
        }
    }

    /**
     * Get the paths to scan.
     *
     * @return array
     */
    protected function getScanPaths(): array
    {
        $paths = $this->getConfig('scan_paths', []);
        
        if (empty($paths)) {
            // Default to common Laravel directories
            $paths = [
                base_path('app'),
                base_path('config'),
                base_path('routes'),
                base_path('database'),
                base_path('resources'),
            ];
        }

        return array_filter($paths, function ($path) {
            return file_exists($path);
        });
    }

    /**
     * Get all PHP files in a directory recursively.
     *
     * @param string $directory
     * @return array
     */
    protected function getPhpFiles(string $directory): array
    {
        $files = [];
        $iterator = new RecursiveIteratorIterator(
            new RecursiveDirectoryIterator($directory, RecursiveDirectoryIterator::SKIP_DOTS)
        );

        foreach ($iterator as $file) {
            if ($file->isFile() && $this->shouldScanFile($file)) {
                $files[] = $file->getPathname();
            }
        }

        return $files;
    }

    /**
     * Check if a file should be scanned.
     *
     * @param SplFileInfo $file
     * @return bool
     */
    protected function shouldScanFile(SplFileInfo $file): bool
    {
        $path = $file->getPathname();
        $filename = $file->getFilename();
        $extension = '.' . $file->getExtension();

        // Check extension
        if (!in_array($extension, $this->includedExtensions)) {
            return false;
        }

        // Check excluded directories
        foreach ($this->excludedDirectories as $dir) {
            if (strpos($path, '/' . $dir . '/') !== false || strpos($path, '\\' . $dir . '\\') !== false) {
                return false;
            }
        }

        // Check excluded files
        foreach ($this->excludedFiles as $pattern) {
            if (fnmatch($pattern, $filename)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Scan a single file for security patterns.
     *
     * @param string $filePath
     * @return void
     */
    protected function scanFile(string $filePath): void
    {
        if (in_array($filePath, $this->scannedFiles)) {
            return;
        }

        $this->scannedFiles[] = $filePath;

        try {
            $content = file_get_contents($filePath);
            if ($content === false) {
                return;
            }

            $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            
            foreach ($this->patterns as $patternType => $patternInfo) {
                foreach ($patternInfo['patterns'] as $pattern) {
                    $this->checkPattern($filePath, $content, $lines, $patternType, $patternInfo, $pattern);
                }
            }
        } catch (\Exception $e) {
            $this->warn("Could not scan file {$filePath}: " . $e->getMessage());
        }
    }

    /**
     * Check a specific pattern in the file content.
     *
     * @param string $filePath
     * @param string $content
     * @param array $lines
     * @param string $patternType
     * @param array $patternInfo
     * @param string $pattern
     * @return void
     */
    protected function checkPattern(string $filePath, string $content, array $lines, string $patternType, array $patternInfo, string $pattern): void
    {
        if (preg_match_all($pattern, $content, $matches, PREG_OFFSET_CAPTURE)) {
            foreach ($matches[0] as $match) {
                $lineNumber = $this->getLineNumber($content, $match[1]);
                $lineContent = $lines[$lineNumber - 1] ?? '';

                $this->findings[] = [
                    'type' => $patternType,
                    'severity' => $patternInfo['severity'],
                    'title' => $patternInfo['name'],
                    'description' => $patternInfo['description'],
                    'file' => str_replace(base_path() . '/', '', $filePath),
                    'line' => $lineNumber,
                    'content' => trim($lineContent),
                    'pattern' => $pattern,
                    'source' => 'Security Code Patterns Audit',
                    'recommendation' => $this->getRecommendation($patternType),
                ];
            }
        }
    }

    /**
     * Get the line number for a given position in the content.
     *
     * @param string $content
     * @param int $position
     * @return int
     */
    protected function getLineNumber(string $content, int $position): int
    {
        $before = substr($content, 0, $position);
        return substr_count($before, "\n") + 1;
    }

    /**
     * Get recommendation for a specific pattern type.
     *
     * @param string $patternType
     * @return string
     */
    protected function getRecommendation(string $patternType): string
    {
        $recommendations = [
            'sql_injection' => 'Use prepared statements or parameterized queries to prevent SQL injection.',
            'xss' => 'Sanitize all user input before outputting it. Use htmlspecialchars() with ENT_QUOTES flag.',
            'command_injection' => 'Avoid executing user input as commands. Use whitelisting and proper escaping.',
            'file_inclusion' => 'Validate and sanitize file paths. Use whitelisting for allowed files.',
            'hardcoded_credentials' => 'Store credentials in environment variables or secure configuration files.',
            'weak_crypto' => 'Use strong cryptographic functions like password_hash(), hash_hmac(), or sodium_crypto_* functions.',
            'weak_random' => 'Use random_int() or random_bytes() for cryptographically secure random numbers.',
            'insecure_upload' => 'Validate file types, sizes, and scan uploads for malware. Store uploads outside web root.',
            'insecure_session' => 'Use secure session configuration with proper regeneration and secure flags.',
            'insecure_deserialization' => 'Avoid deserializing untrusted data. Use safe data formats like JSON.',
            'information_disclosure' => 'Remove debug information from production. Disable error display.',
            'idor' => 'Implement proper access controls and validate user permissions for all resources.',
            'ldap_injection' => 'Use LDAP escaping and parameterized queries for LDAP operations.',
            'xxe' => 'Disable XML external entities in XML parsers. Use safe XML parsing libraries.',
            'insecure_headers' => 'Implement security headers like X-Frame-Options, X-Content-Type-Options, and HSTS.',
        ];

        return $recommendations[$patternType] ?? 'Review and fix the identified security issue.';
    }

    /**
     * Get the audit findings.
     *
     * @return array
     */
    public function getFindings(): array
    {
        return $this->findings;
    }

    /**
     * Get the name of the audit service.
     *
     * @return string
     */
    public function getName(): string
    {
        return 'Security Code Patterns Audit';
    }

    /**
     * Check if the audit service can run.
     *
     * @return bool
     */
    public function canRun(): bool
    {
        return true; // This audit can always run
    }
}