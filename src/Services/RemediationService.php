<?php

namespace Dgtlss\Warden\Services;

use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\ValueObjects\Finding;
use Dgtlss\Warden\ValueObjects\Remediation;

/**
 * Service for generating remediation suggestions based on security findings.
 */
class RemediationService
{
    /**
     * Get remediation suggestions for a finding.
     */
    public function getSuggestions(Finding $finding): Remediation
    {
        $priority = $this->determinePriority($finding->severity);

        return match (strtolower($finding->source)) {
            'composer', 'composer audit' => $this->getComposerRemediation($finding, $priority),
            'npm', 'npm audit' => $this->getNpmRemediation($finding, $priority),
            'debug mode', 'debug mode audit' => $this->getDebugModeRemediation($finding, $priority),
            'storage', 'storage audit' => $this->getStorageRemediation($finding, $priority),
            'file permissions', 'file permissions audit' => $this->getFilePermissionsRemediation($finding, $priority),
            'cors', 'cors audit' => $this->getCorsRemediation($finding, $priority),
            'ssl', 'ssl audit' => $this->getSslRemediation($finding, $priority),
            'security headers', 'security headers audit' => $this->getSecurityHeadersRemediation($finding, $priority),
            'database security', 'database security audit' => $this->getDatabaseSecurityRemediation($finding, $priority),
            'env', 'env audit' => $this->getEnvRemediation($finding, $priority),
            'config', 'config audit' => $this->getConfigRemediation($finding, $priority),
            default => $this->getGenericRemediation($finding, $priority),
        };
    }

    /**
     * Get remediation suggestions for multiple findings.
     *
     * @param array<int, Finding> $findings
     * @return array<int, Remediation>
     */
    public function getSuggestionsForAll(array $findings): array
    {
        return array_map(fn(Finding $finding) => $this->getSuggestions($finding), $findings);
    }

    /**
     * Enrich findings with remediation suggestions.
     *
     * @param array<int, Finding> $findings
     * @return array<int, Finding>
     */
    public function enrichFindings(array $findings): array
    {
        return array_map(function (Finding $finding) {
            $remediation = $this->getSuggestions($finding);

            return $finding->withRemediation($remediation);
        }, $findings);
    }

    /**
     * Determine priority based on severity.
     */
    protected function determinePriority(Severity $severity): string
    {
        return match ($severity) {
            Severity::CRITICAL => 'immediate',
            Severity::HIGH => 'high',
            Severity::MEDIUM, Severity::MODERATE => 'medium',
            default => 'low',
        };
    }

    /**
     * Get remediation for Composer vulnerabilities.
     */
    protected function getComposerRemediation(Finding $finding, string $priority): Remediation
    {
        $package = $finding->package;
        $commands = [];
        $manualSteps = [];
        $links = [];

        if ($package !== 'composer' && $package !== 'unknown') {
            $commands[] = "composer update {$package}";
            $commands[] = "composer audit";
        }

        $manualSteps[] = "Review the security advisory for {$package}";
        $manualSteps[] = "Check if the updated version is compatible with your application";
        $manualSteps[] = "Run your test suite after updating";

        if ($finding->cve) {
            $links[] = "https://nvd.nist.gov/vuln/detail/{$finding->cve}";
            $links[] = "https://github.com/advisories?query={$finding->cve}";
        }

        $links[] = "https://packagist.org/packages/{$package}";

        return new Remediation(
            description: "Update {$package} to a patched version to resolve this vulnerability.",
            commands: $commands,
            manualSteps: $manualSteps,
            links: $links,
            priority: $priority,
        );
    }

    /**
     * Get remediation for NPM vulnerabilities.
     */
    protected function getNpmRemediation(Finding $finding, string $priority): Remediation
    {
        $package = $finding->package;
        $commands = [];
        $manualSteps = [];
        $links = [];

        if ($package !== 'npm' && $package !== 'unknown') {
            $commands[] = "npm update {$package}";
            $commands[] = "npm audit fix";
        } else {
            $commands[] = "npm audit fix";
        }

        $commands[] = "npm audit";

        $manualSteps[] = "Review the security advisory for {$package}";
        $manualSteps[] = "If npm audit fix fails, manually update the package";
        $manualSteps[] = "Consider using npm audit fix --force for breaking changes (use with caution)";

        if ($finding->cve) {
            $links[] = "https://nvd.nist.gov/vuln/detail/{$finding->cve}";
        }

        $links[] = "https://www.npmjs.com/package/{$package}";

        return new Remediation(
            description: "Update {$package} to resolve this vulnerability. Run npm audit fix to automatically update compatible versions.",
            commands: $commands,
            manualSteps: $manualSteps,
            links: $links,
            priority: $priority,
        );
    }

    /**
     * Get remediation for debug mode issues.
     */
    protected function getDebugModeRemediation(Finding $finding, string $priority): Remediation
    {
        return new Remediation(
            description: "Disable debug mode in production to prevent sensitive information exposure.",
            commands: [],
            manualSteps: [
                "Set APP_DEBUG=false in your .env file",
                "Ensure APP_ENV=production in your .env file",
                "Clear the config cache: php artisan config:clear",
                "Verify debug mode is disabled by checking the application",
            ],
            links: [
                "https://laravel.com/docs/configuration#environment-configuration",
            ],
            priority: $priority,
        );
    }

    /**
     * Get remediation for storage permission issues.
     */
    protected function getStorageRemediation(Finding $finding, string $priority): Remediation
    {
        return new Remediation(
            description: "Fix storage directory permissions to ensure proper access control.",
            commands: [
                "chmod -R 755 storage",
                "chmod -R 755 bootstrap/cache",
                "chown -R www-data:www-data storage bootstrap/cache",
            ],
            manualSteps: [
                "Ensure the web server user owns the storage directories",
                "Set appropriate permissions (755 for directories, 644 for files)",
                "Verify the application can write to storage/logs and storage/framework",
            ],
            links: [
                "https://laravel.com/docs/installation#directory-permissions",
            ],
            priority: $priority,
        );
    }

    /**
     * Get remediation for file permission issues.
     */
    protected function getFilePermissionsRemediation(Finding $finding, string $priority): Remediation
    {
        $commands = [];
        $manualSteps = [];

        if (str_contains($finding->title, '.env')) {
            $commands[] = "chmod 600 .env";
            $manualSteps[] = "Ensure .env file is only readable by the owner";
        }

        $manualSteps[] = "Review file permissions for sensitive configuration files";
        $manualSteps[] = "Ensure config files are not world-readable or writable";
        $manualSteps[] = "Remove any sensitive files from public directories";

        return new Remediation(
            description: "Adjust file permissions to prevent unauthorized access to sensitive files.",
            commands: $commands,
            manualSteps: $manualSteps,
            links: [
                "https://laravel.com/docs/installation#directory-permissions",
            ],
            priority: $priority,
        );
    }

    /**
     * Get remediation for CORS issues.
     */
    protected function getCorsRemediation(Finding $finding, string $priority): Remediation
    {
        return new Remediation(
            description: "Configure CORS to restrict access to trusted origins only.",
            commands: [
                "php artisan config:clear",
            ],
            manualSteps: [
                "Edit config/cors.php to specify allowed origins instead of using wildcards",
                "Replace 'allowed_origins' => ['*'] with specific domain list",
                "Avoid using credentials with wildcard origins",
                "Test CORS configuration with your frontend applications",
            ],
            links: [
                "https://laravel.com/docs/routing#cors",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS",
            ],
            priority: $priority,
        );
    }

    /**
     * Get remediation for SSL/HTTPS issues.
     */
    protected function getSslRemediation(Finding $finding, string $priority): Remediation
    {
        return new Remediation(
            description: "Enable HTTPS and configure secure session cookies for production.",
            commands: [
                "php artisan config:clear",
            ],
            manualSteps: [
                "Set SESSION_SECURE_COOKIE=true in .env for production",
                "Ensure your web server is configured with a valid SSL certificate",
                "Enable HSTS headers in your web server configuration",
                "Redirect all HTTP traffic to HTTPS",
                "Set FORCE_HTTPS=true or configure trusted proxies if behind a load balancer",
            ],
            links: [
                "https://laravel.com/docs/session#configuration",
                "https://letsencrypt.org/getting-started/",
            ],
            priority: $priority,
        );
    }

    /**
     * Get remediation for security headers issues.
     */
    protected function getSecurityHeadersRemediation(Finding $finding, string $priority): Remediation
    {
        $manualSteps = [
            "Add security headers via middleware or web server configuration",
        ];

        $title = strtolower($finding->title);

        if (str_contains($title, 'x-frame-options')) {
            $manualSteps[] = "Add X-Frame-Options: DENY or SAMEORIGIN header";
        }

        if (str_contains($title, 'content-security-policy') || str_contains($title, 'csp')) {
            $manualSteps[] = "Configure Content-Security-Policy header appropriate for your application";
        }

        if (str_contains($title, 'x-content-type-options')) {
            $manualSteps[] = "Add X-Content-Type-Options: nosniff header";
        }

        if (str_contains($title, 'strict-transport-security') || str_contains($title, 'hsts')) {
            $manualSteps[] = "Add Strict-Transport-Security header with appropriate max-age";
        }

        $manualSteps[] = "Test headers using securityheaders.com or similar tools";

        return new Remediation(
            description: "Configure security headers to protect against common web vulnerabilities.",
            commands: [],
            manualSteps: $manualSteps,
            links: [
                "https://securityheaders.com/",
                "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers#security",
                "https://owasp.org/www-project-secure-headers/",
            ],
            priority: $priority,
        );
    }

    /**
     * Get remediation for database security issues.
     */
    protected function getDatabaseSecurityRemediation(Finding $finding, string $priority): Remediation
    {
        $manualSteps = [];
        $title = strtolower($finding->title);

        if (str_contains($title, 'password')) {
            $manualSteps[] = "Use a strong, unique password for database connections";
            $manualSteps[] = "Ensure DB_PASSWORD in .env is not a default or weak password";
        }

        if (str_contains($title, 'ssl') || str_contains($title, 'tls')) {
            $manualSteps[] = "Enable SSL/TLS for database connections";
            $manualSteps[] = "Configure database driver options to require SSL";
        }

        if (str_contains($title, 'root')) {
            $manualSteps[] = "Create a dedicated database user instead of using root";
            $manualSteps[] = "Grant only necessary privileges to the application user";
        }

        $manualSteps[] = "Review database user permissions and restrict access";
        $manualSteps[] = "Ensure database is not publicly accessible";

        return new Remediation(
            description: "Secure database configuration to prevent unauthorized access.",
            commands: [],
            manualSteps: $manualSteps,
            links: [
                "https://laravel.com/docs/database#configuration",
            ],
            priority: $priority,
        );
    }

    /**
     * Get remediation for environment configuration issues.
     */
    protected function getEnvRemediation(Finding $finding, string $priority): Remediation
    {
        $manualSteps = [];
        $title = strtolower($finding->title);

        if (str_contains($title, 'app_key')) {
            $manualSteps[] = "Generate a new application key: php artisan key:generate";
        }

        if (str_contains($title, 'debug')) {
            $manualSteps[] = "Set APP_DEBUG=false in production";
        }

        $manualSteps[] = "Review all environment variables for sensitive data exposure";
        $manualSteps[] = "Ensure .env file is not committed to version control";
        $manualSteps[] = "Use environment-specific configuration for production";

        return new Remediation(
            description: "Update environment configuration to follow security best practices.",
            commands: [
                "php artisan config:clear",
            ],
            manualSteps: $manualSteps,
            links: [
                "https://laravel.com/docs/configuration#environment-configuration",
            ],
            priority: $priority,
        );
    }

    /**
     * Get remediation for config audit issues.
     */
    protected function getConfigRemediation(Finding $finding, string $priority): Remediation
    {
        return new Remediation(
            description: "Review and update application configuration for security compliance.",
            commands: [
                "php artisan config:clear",
                "php artisan config:cache",
            ],
            manualSteps: [
                "Review the flagged configuration setting",
                "Update config values to follow security best practices",
                "Test application functionality after making changes",
            ],
            links: [
                "https://laravel.com/docs/configuration",
            ],
            priority: $priority,
        );
    }

    /**
     * Get generic remediation for unknown issue types.
     */
    protected function getGenericRemediation(Finding $finding, string $priority): Remediation
    {
        $links = [];

        if ($finding->cve) {
            $links[] = "https://nvd.nist.gov/vuln/detail/{$finding->cve}";
        }

        return new Remediation(
            description: "Review the security finding and apply appropriate fixes.",
            commands: [],
            manualSteps: [
                "Review the security advisory details",
                "Identify the affected component or configuration",
                "Apply the recommended fix or update",
                "Test the application after making changes",
            ],
            links: $links,
            priority: $priority,
        );
    }
}
