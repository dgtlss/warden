# Warden

[![Latest Version on Packagist](https://img.shields.io/packagist/v/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
[![Total Downloads](https://img.shields.io/packagist/dt/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
[![License](https://img.shields.io/packagist/l/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)

Warden is a comprehensive Laravel security audit package that proactively monitors your dependencies and application configuration for security vulnerabilities. With support for parallel execution, multiple notification channels, and extensible custom audits, Warden provides enterprise-grade security scanning for Laravel applications.

**Key Features:**
- 🚀 **Parallel audit execution** for faster performance
- 🔔 **Multiple notification channels** (Slack, Discord, Email, Teams)
- 📊 **Multiple output formats** (JSON, GitHub Actions, GitLab CI, Jenkins)
- 🕒 **Scheduled automated audits** via Laravel scheduler
- 🔧 **Custom audit rules** for organization-specific security policies
- 📈 **Audit history tracking** and trend analysis
- ⚡ **Intelligent caching** to prevent redundant scans
- 🎯 **Severity filtering** to focus on critical issues

Perfect for CI/CD pipelines and continuous security monitoring.

## Installation

You can install the package via composer:

```bash
composer require dgtlss/warden
```

## Configuration

Publish the configuration file:

```bash
php artisan vendor:publish --tag="warden-config"
```

This will create a `config/warden.php` file in your application with extensive customization options.

### Environment Variables

Warden v1.3.0 supports multiple notification channels and advanced features. Add the relevant variables to your `.env` file:

#### Notification Channels
```env
# Slack (recommended for rich formatting)
WARDEN_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Discord
WARDEN_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/WEBHOOK

# Microsoft Teams
WARDEN_TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/YOUR/WEBHOOK

# Email
WARDEN_EMAIL_RECIPIENTS=security@company.com,admin@company.com
WARDEN_EMAIL_FROM=security@company.com
WARDEN_EMAIL_FROM_NAME="Security Team"

# Legacy webhook support (backward compatibility)
WARDEN_WEBHOOK_URL=https://your-webhook-url.com
```

#### Performance & Caching
```env
WARDEN_CACHE_ENABLED=true
WARDEN_CACHE_DURATION=3600  # Cache results for 1 hour
WARDEN_PARALLEL_EXECUTION=true  # Enable parallel audit execution
```

#### Scheduling
```env
WARDEN_SCHEDULE_ENABLED=false
WARDEN_SCHEDULE_FREQUENCY=daily  # hourly|daily|weekly|monthly
WARDEN_SCHEDULE_TIME=03:00
WARDEN_SCHEDULE_TIMEZONE=UTC
```

#### Audit History (Optional)
```env
WARDEN_HISTORY_ENABLED=false
WARDEN_HISTORY_RETENTION_DAYS=90
```

#### Output Formats
```env
WARDEN_OUTPUT_JSON=false
WARDEN_OUTPUT_JUNIT=false
WARDEN_SEVERITY_FILTER=  # null|low|medium|high|critical
```

## Available Audits

Warden performs several security audits on your Laravel application:

### 1. Composer Dependencies Audit
Checks your PHP dependencies for known security vulnerabilities using the `composer audit` command.

### 2. NPM Dependencies Audit
When enabled with the `--npm` flag, checks your JavaScript dependencies for known security vulnerabilities using `npm audit`.

### 3. Environment Configuration Audit
Verifies your environment configuration for security best practices:
- Checks for presence of `.env` file
- Ensures `.env` is properly gitignored
- Validates presence of critical environment variables
- Identifies potentially sensitive information

### 4. Storage Permissions Audit
Validates directory permissions for critical Laravel paths:
- `storage/framework`
- `storage/logs`
- `bootstrap/cache`
- Ensures proper write permissions
- Identifies missing or incorrectly configured directories

### 5. Configuration Security Audit
Examines your Laravel configuration for security issues:
- Debug mode status
- Session security settings
- CSRF protection
- Other common security misconfigurations

## Custom Audit Rules

Warden v1.3.0 introduces the ability to create custom security audit rules for your organization's specific needs.

### Creating Custom Audits

Implement the `CustomAudit` interface:

```php
<?php

namespace App\Audits;

use Dgtlss\Warden\Contracts\CustomAudit;

class DatabasePasswordAudit implements CustomAudit
{
    public function audit(): bool
    {
        // Your custom audit logic
        $dbPassword = env('DB_PASSWORD', '');
        return !in_array(strtolower($dbPassword), ['password', '123456', 'admin']);
    }

    public function getFindings(): array
    {
        // Return array of findings if audit fails
        return [
            [
                'package' => 'environment',
                'title' => 'Weak Database Password',
                'severity' => 'critical',
                'description' => 'Database password is weak or commonly used',
                'remediation' => 'Use a strong, unique password'
            ]
        ];
    }

    public function getName(): string
    {
        return 'Database Password Security';
    }

    public function getDescription(): string
    {
        return 'Checks for weak database passwords';
    }

    public function shouldRun(): bool
    {
        return !empty(env('DB_CONNECTION'));
    }
}
```

### Registering Custom Audits

Add your custom audit classes to `config/warden.php`:

```php
'custom_audits' => [
    \App\Audits\DatabasePasswordAudit::class,
    \App\Audits\ApiKeySecurityAudit::class,
    // Add more custom audits here
],
```

### Example Custom Audits

The package includes example audits in `src/Examples/` that you can copy and modify:
- `DatabasePasswordAudit.php` - Checks for weak database passwords
- More examples coming in future releases

## Usage

### Basic Commands

#### Basic Audit
```bash
php artisan warden:audit
```

#### Including NPM Audit
```bash
php artisan warden:audit --npm
```

#### Silent Mode (No Notifications)
```bash
php artisan warden:audit --silent
```

#### Ignore Abandoned Packages
```bash
php artisan warden:audit --ignore-abandoned
```

#### Filter by Severity
```bash
php artisan warden:audit --severity=high  # Only show high and critical
```

#### Force Cache Refresh
```bash
php artisan warden:audit --force
```

### Output Formats

#### JSON Output (for CI/CD)
```bash
php artisan warden:audit --output=json > audit-report.json
```

#### GitHub Actions Format
```bash
php artisan warden:audit --output=github
```

#### GitLab CI Format
```bash
php artisan warden:audit --output=gitlab > gl-dependency-scanning-report.json
```

#### Jenkins Format
```bash
php artisan warden:audit --output=jenkins
```

### Scheduling Management

#### Enable Scheduled Audits
```bash
php artisan warden:schedule --enable
```

#### Check Schedule Status
```bash
php artisan warden:schedule --status
```

#### Disable Scheduled Audits
```bash
php artisan warden:schedule --disable
```

### Advanced Usage

#### Custom Audit with Multiple Options
```bash
php artisan warden:audit --npm --severity=medium --output=json --silent
```

#### History Tracking Setup (if enabled)
```bash
# Publish and run migrations
php artisan vendor:publish --tag=warden-migrations
php artisan migrate
```

## Understanding Audit Results

The audit command will return different status codes:
- `0`: No vulnerabilities or issues found
- `1`: Vulnerabilities or security issues detected
- `2`: One or more audit processes failed to run

### Severity Levels

Findings are categorized by severity:
- `critical`: Requires immediate attention
- `high`: Should be addressed as soon as possible
- `medium`: Should be reviewed and fixed
- `low`: Minor security concerns
- `error`: Audit process or configuration errors

## Notification Format

When notifications are enabled, the report includes:
- Audit type (composer, npm, environment, storage, or configuration)
- Issue details specific to each audit type
- Severity level
- Remediation suggestions where applicable

## Notifications

Warden v1.3.0 supports multiple notification channels with rich formatting and enhanced integrations:

### 1. Slack Notifications (Recommended)
Rich formatted messages with severity indicators, clickable CVE links, and organized blocks:

```env
WARDEN_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

Features:
- Color-coded severity levels
- Organized finding blocks
- Clickable CVE links
- Professional formatting

### 2. Discord Notifications
Formatted embeds with severity colors and organized fields:

```env
WARDEN_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/WEBHOOK
```

Features:
- Rich embeds with color coding
- Grouped findings by audit source
- Custom avatar and branding

### 3. Microsoft Teams (Coming Soon)
Native Teams webhook support:

```env
WARDEN_TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/YOUR/WEBHOOK
```

### 4. Email Notifications
Enhanced email formatting with better templates:

```env
WARDEN_EMAIL_RECIPIENTS=security@company.com,admin@company.com
WARDEN_EMAIL_FROM=security@company.com
WARDEN_EMAIL_FROM_NAME="Security Team"
```

### 5. Legacy Webhook Support
Backward compatibility with existing webhook integrations:

```env
WARDEN_WEBHOOK_URL=https://your-webhook-url.com  # Legacy support
```

### Multiple Channels
You can configure multiple notification channels simultaneously. Warden will send notifications to all configured channels.

## Report Format

The audit report includes:
- Package name
- Vulnerability title
- CVE identifier
- Reference link
- Affected versions

## CI/CD Integration

Warden v1.3.0 provides enhanced CI/CD integration with specialized output formats and caching support.

### GitHub Actions

#### Basic Integration
```yaml
steps:
  - name: Security Audit
    run: php artisan warden:audit --output=github --severity=high
    continue-on-error: false
```

#### Advanced Integration with Caching
```yaml
steps:
  - name: Security Audit
    run: |
      php artisan warden:audit \
        --output=github \
        --severity=medium \
        --silent
    continue-on-error: false
    
  - name: Upload Security Report
    if: failure()
    uses: actions/upload-artifact@v3
    with:
      name: security-audit-report
      path: audit-report.json
```

### GitLab CI

```yaml
security_audit:
  stage: test
  script:
    - php artisan warden:audit --output=gitlab --silent > gl-dependency-scanning-report.json
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
    expire_in: 1 week
  allow_failure: false
```

### Jenkins

```yaml
pipeline {
    agent any
    stages {
        stage('Security Audit') {
            steps {
                sh 'php artisan warden:audit --output=jenkins --severity=high'
            }
            post {
                always {
                    publishHTML([
                        allowMissing: false,
                        alwaysLinkToLastBuild: true,
                        keepAll: true,
                        reportDir: '.',
                        reportFiles: 'audit-report.json',
                        reportName: 'Security Audit Report'
                    ])
                }
            }
        }
    }
}
```

### Performance Tips for CI/CD

1. **Use caching** to avoid rate limits:
   ```bash
   php artisan warden:audit --silent  # Uses cache by default
   ```

2. **Filter by severity** to focus on critical issues:
   ```bash
   php artisan warden:audit --severity=high --silent
   ```

3. **Use parallel execution** (enabled by default):
   ```env
   WARDEN_PARALLEL_EXECUTION=true
   ```

4. **Output to JSON** for further processing:
   ```bash
   php artisan warden:audit --output=json --silent > security-report.json
   ```

## Performance & Scalability

Warden v1.3.0 is designed for high-performance security scanning with several optimization features:

### Parallel Execution
- Audits run concurrently by default for up to 5x faster execution
- Configurable via `WARDEN_PARALLEL_EXECUTION` environment variable

### Intelligent Caching
- Results cached to prevent redundant API calls
- Configurable cache duration and drivers
- Force refresh capability when needed

### Severity Filtering
- Focus on critical issues by filtering low-priority findings
- Reduces noise in CI/CD pipelines
- Configurable default severity levels

## Scheduled Audits

Set up automated security monitoring with Laravel's scheduler:

```bash
# Enable scheduled audits
php artisan warden:schedule --enable

# Check current status
php artisan warden:schedule --status
```

Configure schedule frequency in your `.env`:
```env
WARDEN_SCHEDULE_ENABLED=true
WARDEN_SCHEDULE_FREQUENCY=daily
WARDEN_SCHEDULE_TIME=03:00
```

Make sure your Laravel scheduler is running:
```bash
* * * * * cd /path-to-your-project && php artisan schedule:run >> /dev/null 2>&1
```

## What's New in v1.3.0

- 🚀 **Parallel audit execution** for 5x faster performance
- 🔔 **Multiple notification channels** (Slack, Discord, Teams)
- 📊 **CI/CD output formats** (GitHub Actions, GitLab CI, Jenkins)
- 🕒 **Automated scheduling** via Laravel scheduler
- 🔧 **Custom audit rules** for organization-specific policies
- 📈 **Audit history tracking** for trend analysis
- ⚡ **Intelligent caching** to optimize performance
- 🎯 **Severity filtering** to focus on critical issues

For a complete list of changes, see the [releases page](https://github.com/dgtlss/warden/releases).

## Upgrading from v1.2.x

1. Update your composer dependency:
   ```bash
   composer update dgtlss/warden
   ```

2. Publish the new configuration:
   ```bash
   php artisan vendor:publish --tag=warden-config --force
   ```

3. Update your environment variables to use the new notification channels

4. Optionally enable new features like caching and scheduling

See the configuration sections above for detailed setup instructions for each new feature.

## License

This package is open source and released under the MIT License.

## Contributing

We welcome contributions to improve the package. Please see our [CONTRIBUTING GUIDELINES](CONTRIBUTING.md) for guidelines on how to submit improvements and bug fixes.

## Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/dgtlss/warden/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/dgtlss/warden/discussions)
- 📋 **Releases**: [GitHub Releases](https://github.com/dgtlss/warden/releases) for version history and changelogs

## Donate

If you find this package useful, please consider donating to support its development and maintenance.
