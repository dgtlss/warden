<?php

namespace Dgtlss\Warden\Services\Audits;

use Dgtlss\Warden\Enums\Severity;
use Illuminate\Support\Facades\Config;

class DatabaseSecurityAuditService extends AbstractAuditService
{
    public function run(): bool
    {
        $this->checkDatabasePassword();
        $this->checkDatabaseHost();
        $this->checkSslConfiguration();
        $this->checkDefaultCredentials();

        return true;
    }

    public function getName(): string
    {
        return 'Database Security';
    }

    /**
     * Check for weak or default database passwords.
     */
    protected function checkDatabasePassword(): void
    {
        $defaultConnection = Config::get('database.default');
        if (!is_string($defaultConnection)) {
            return;
        }

        $password = Config::get("database.connections.{$defaultConnection}.password", '');
        if (!is_string($password)) {
            $password = '';
        }

        if (empty($password)) {
            $this->addFinding([
                'package' => 'Database Configuration',
                'title' => 'Database has no password configured',
                'severity' => Severity::CRITICAL,
                'cve' => null,
                'affected_versions' => null,
                'error' => 'Database connections should always use strong passwords.',
            ]);
            return;
        }

        // Check for common weak passwords
        $weakPasswords = ['password', 'root', 'admin', '123456', 'secret', 'laravel'];
        if (in_array(strtolower($password), $weakPasswords, true)) {
            $this->addFinding([
                'package' => 'Database Configuration',
                'title' => 'Weak database password detected',
                'severity' => Severity::CRITICAL,
                'cve' => null,
                'affected_versions' => null,
                'error' => 'Database is using a common weak password. Use a strong, randomly generated password.',
            ]);
        }

        // Check password length
        if (strlen($password) < 12) {
            $this->addFinding([
                'package' => 'Database Configuration',
                'title' => 'Database password is too short',
                'severity' => Severity::HIGH,
                'cve' => null,
                'affected_versions' => null,
                'error' => 'Database password should be at least 12 characters long.',
            ]);
        }
    }

    /**
     * Check if database is exposed to public networks.
     */
    protected function checkDatabaseHost(): void
    {
        $defaultConnection = Config::get('database.default');
        if (!is_string($defaultConnection)) {
            return;
        }

        $host = Config::get("database.connections.{$defaultConnection}.host", 'localhost');
        if (!is_string($host)) {
            return;
        }

        $isProduction = Config::get('app.env') === 'production';

        // Check if database is accessible from anywhere
        if ($isProduction && in_array($host, ['0.0.0.0', '*'], true)) {
            $this->addFinding([
                'package' => 'Database Configuration',
                'title' => 'Database exposed to public network',
                'severity' => Severity::CRITICAL,
                'cve' => null,
                'affected_versions' => null,
                'error' => 'Production database should not be accessible from all IP addresses.',
            ]);
        }
    }

    /**
     * Check for SSL/TLS configuration.
     */
    protected function checkSslConfiguration(): void
    {
        $defaultConnection = Config::get('database.default');
        if (!is_string($defaultConnection)) {
            return;
        }

        $sslMode = Config::get("database.connections.{$defaultConnection}.sslmode", null);
        $isProduction = Config::get('app.env') === 'production';

        if ($isProduction && empty($sslMode)) {
            $this->addFinding([
                'package' => 'Database Configuration',
                'title' => 'Database SSL/TLS not configured',
                'severity' => Severity::HIGH,
                'cve' => null,
                'affected_versions' => null,
                'error' => 'Production databases should use encrypted SSL/TLS connections.',
            ]);
        }

        // For PostgreSQL, check for weak SSL modes
        $driver = Config::get("database.connections.{$defaultConnection}.driver", '');
        if (is_string($driver) && is_string($sslMode) && $driver === 'pgsql' && in_array($sslMode, ['allow', 'prefer'], true)) {
            $this->addFinding([
                'package' => 'Database Configuration',
                'title' => 'Weak PostgreSQL SSL mode',
                'severity' => Severity::MEDIUM,
                'cve' => null,
                'affected_versions' => null,
                'error' => "SSL mode '{$sslMode}' allows unencrypted connections. Use 'require' or 'verify-full'.",
            ]);
        }
    }

    /**
     * Check for default database credentials.
     */
    protected function checkDefaultCredentials(): void
    {
        $defaultConnection = Config::get('database.default');
        if (!is_string($defaultConnection)) {
            return;
        }

        $username = Config::get("database.connections.{$defaultConnection}.username", '');
        if (!is_string($username)) {
            return;
        }

        $defaultUsernames = ['root', 'admin', 'postgres', 'mysql', 'sa'];
        if (in_array(strtolower($username), $defaultUsernames, true)) {
            $this->addFinding([
                'package' => 'Database Configuration',
                'title' => 'Using default database username',
                'severity' => Severity::MEDIUM,
                'cve' => null,
                'affected_versions' => null,
                'error' => "Username '{$username}' is a common default. Consider using a custom database user.",
            ]);
        }
    }
}
