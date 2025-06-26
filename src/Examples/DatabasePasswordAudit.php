<?php

namespace Dgtlss\Warden\Examples;

use Dgtlss\Warden\Contracts\CustomAudit;

/**
 * Example custom audit that checks for common database password security issues.
 * 
 * This is an example implementation showing how to create custom audits.
 * Copy this file to your app/Audits directory and modify as needed.
 */
class DatabasePasswordAudit implements CustomAudit
{
    protected array $findings = [];
    
    /**
     * Run the database password security audit.
     */
    public function audit(): bool
    {
        $this->findings = [];
        
        // Check for common weak passwords in environment
        $this->checkWeakPasswords();
        
        // Check for password length
        $this->checkPasswordLength();
        
        // Check for default passwords
        $this->checkDefaultPasswords();
        
        // Check for passwords in version control
        $this->checkPasswordsInVersionControl();
        
        return empty($this->findings);
    }
    
    /**
     * Get the findings from this audit.
     */
    public function getFindings(): array
    {
        return $this->findings;
    }
    
    /**
     * Get the name of this audit.
     */
    public function getName(): string
    {
        return 'Database Password Security';
    }
    
    /**
     * Get the description of what this audit checks.
     */
    public function getDescription(): string
    {
        return 'Checks for common database password security issues including weak passwords, short passwords, and default credentials.';
    }
    
    /**
     * Determine if this audit should run.
     */
    public function shouldRun(): bool
    {
        // Only run if database is configured
        return !empty(env('DB_CONNECTION'));
    }
    
    /**
     * Check for common weak passwords.
     */
    protected function checkWeakPasswords(): void
    {
        $weakPasswords = [
            'password', '123456', 'admin', 'root', 'pass', 
            'secret', 'qwerty', 'letmein', 'password123'
        ];
        
        $dbPassword = env('DB_PASSWORD', '');
        
        if (in_array(strtolower($dbPassword), $weakPasswords)) {
            $this->findings[] = [
                'package' => 'environment',
                'title' => 'Weak Database Password Detected',
                'severity' => 'critical',
                'description' => 'The database password is using a commonly known weak password. This poses a severe security risk.',
                'remediation' => 'Change the DB_PASSWORD to a strong, unique password with at least 16 characters including uppercase, lowercase, numbers, and special characters.',
            ];
        }
    }
    
    /**
     * Check password length.
     */
    protected function checkPasswordLength(): void
    {
        $dbPassword = env('DB_PASSWORD', '');
        
        if (!empty($dbPassword) && strlen($dbPassword) < 12) {
            $this->findings[] = [
                'package' => 'environment',
                'title' => 'Short Database Password',
                'severity' => 'high',
                'description' => sprintf('The database password is only %d characters long. Short passwords are easier to crack.', strlen($dbPassword)),
                'remediation' => 'Use a database password with at least 16 characters for better security.',
            ];
        }
    }
    
    /**
     * Check for default passwords.
     */
    protected function checkDefaultPasswords(): void
    {
        $defaultPasswords = [
            'mysql' => ['root' => ''],
            'postgres' => ['postgres' => 'postgres'],
            'sqlserver' => ['sa' => 'sa'],
        ];
        
        $connection = env('DB_CONNECTION');
        $username = env('DB_USERNAME');
        $password = env('DB_PASSWORD');
        
        if (isset($defaultPasswords[$connection][$username]) && 
            $defaultPasswords[$connection][$username] === $password) {
            $this->findings[] = [
                'package' => 'environment',
                'title' => 'Default Database Credentials Detected',
                'severity' => 'critical',
                'description' => 'The database is using default credentials. This is a severe security vulnerability.',
                'remediation' => 'Immediately change both the database username and password from their default values.',
            ];
        }
    }
    
    /**
     * Check for passwords in version control.
     */
    protected function checkPasswordsInVersionControl(): void
    {
        $suspiciousFiles = [
            '.env.example',
            'config/database.php',
            'docker-compose.yml',
            'docker-compose.yaml',
        ];
        
        foreach ($suspiciousFiles as $file) {
            if (file_exists(base_path($file))) {
                $content = file_get_contents(base_path($file));
                
                // Look for actual passwords (not placeholders)
                if (preg_match('/DB_PASSWORD\s*=\s*["\']?(?!your-password|password|secret|<[^>]+>|\$\{[^}]+\})[a-zA-Z0-9!@#$%^&*()_+\-=\[\]{};:\'",.<>?\\/]+["\']?/i', $content, $matches)) {
                    $this->findings[] = [
                        'package' => 'configuration',
                        'title' => 'Potential Password in Version Control',
                        'severity' => 'high',
                        'description' => sprintf('File "%s" may contain an actual database password instead of a placeholder.', $file),
                        'remediation' => 'Ensure only placeholder values are committed to version control. Use environment variables for actual passwords.',
                    ];
                }
            }
        }
    }
} 