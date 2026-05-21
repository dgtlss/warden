# Warden

[![Latest Version on Packagist](https://img.shields.io/packagist/v/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
[![Total Downloads](https://img.shields.io/packagist/dt/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
[![License](https://img.shields.io/packagist/l/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
[![PHP Version Require](https://img.shields.io/packagist/php-v/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
![GitHub repo size](https://img.shields.io/github/repo-size/dgtlss/warden)

**Warden** is a comprehensive Laravel security audit package that proactively monitors your dependencies and application configuration for security vulnerabilities. Built for enterprise-grade security scanning, Warden provides powerful features for modern Laravel applications, ensuring your projects remain secure from development to production.

## 🚀 Key Features

### ✅ Core Security Audits
- **🔍 Dependency Scanning**: Composer and NPM vulnerability detection
- **⚙️ Configuration Audits**: Environment, storage permissions, and Laravel config
- **📝 Code Analysis**: PHP syntax validation and security checks
- **🔧 Custom Audit Rules**: Organization-specific security policies

### ✅ Performance & Scalability  
- **⚡ Parallel Execution**: Up to 5x faster audit performance
- **🗄️ Intelligent Caching**: Prevents redundant scans with configurable TTL
- **🎯 Severity Filtering**: Focus on critical issues only

### ✅ Integration & Automation
- **📊 Multiple Output Formats**: JSON, GitHub Actions, GitLab CI, Jenkins
- **🔔 Rich Notifications**: Slack, Discord, Email with formatted reports
- **⏰ Automated Scheduling**: Laravel scheduler integration
- **🔄 CI/CD Ready**: Native support for all major platforms

Perfect for continuous security monitoring and DevOps pipelines.

---

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Command Reference](#command-reference)
- [Configuration](#configuration)
- [Security Audits](#security-audits)
- [Usage Examples](#usage-examples)
- [Notifications](#notifications)
- [Custom Audits](#custom-audits)
- [Scheduling](#scheduling)
- [CI/CD Integration](#cicd-integration)
- [Advanced Features](#advanced-features)
- [FAQ](#faq)
- [Troubleshooting](#troubleshooting)

---

## 🚀 Installation

To install Warden, use Composer:

```bash
composer require dgtlss/warden
```

Publish configuration:

```bash
php artisan vendor:publish --tag="warden-config"
```

This creates `config/warden.php` with all available options.

**Note**: The package includes `.idea` in `.gitignore` for improved support with IntelliJ IDEA and JetBrains IDEs.

---

## ⚡ Quick Start

Dive into Warden's powerful security auditing capabilities with these simple commands:

### Basic Security Audit
Run a comprehensive security scan of your Laravel application:
```bash
php artisan warden:audit
```

### With NPM Dependencies
Include JavaScript vulnerabilities in your audit:
```bash
php artisan warden:audit --npm
```

### JSON Output for CI/CD
Generate machine-readable reports for automated pipelines:
```bash
php artisan warden:audit --output=json --severity=high
```

### No Notifications
Run audits without sending notifications (useful for CI or local checks):
```bash
php artisan warden:audit --no-notify
```
> **Note:** `--silent` still works for backward compatibility.

---

## 📌 Command Reference

Quick reference for all commands and options.

| Command | Options | Description |
|--------|---------|-------------|
| `warden:audit` | — | Run all security audits |
| | `--no-notify` | Suppress notifications (CI/local use) |
| | `--npm` | Include NPM dependency scan |
| | `--ignore-abandoned` | Don't fail on abandoned packages |
| | `--output=json\|github\|gitlab\|jenkins` | Machine-readable output |
| | `--severity=low\|medium\|high\|critical` | Filter by minimum severity |
| | `--force` | Clear cache and re-run all audits |
| `warden:syntax` | — | PHP syntax validation only |
| `warden:schedule` | `--enable` | Enable scheduled audits |
| | `--disable` | Disable scheduled audits |
| | `--status` | Show schedule status |

---

## ⚙️ Configuration

### Environment Variables

Add these to your `.env` file:

#### 🔔 Notifications
```env
# Slack (recommended - rich formatting)
WARDEN_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Discord
WARDEN_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/WEBHOOK

# Microsoft Teams
WARDEN_TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/YOUR/WEBHOOK

# Email
WARDEN_EMAIL_RECIPIENTS=security@company.com,admin@company.com
WARDEN_EMAIL_FROM=security@company.com
WARDEN_EMAIL_FROM_NAME="Security Team"

# Legacy webhook (backward compatibility)
WARDEN_WEBHOOK_URL=https://your-webhook-url.com
```

#### ⚡ Performance
```env
WARDEN_CACHE_ENABLED=true
WARDEN_CACHE_DURATION=3600        # Cache for 1 hour
WARDEN_PARALLEL_EXECUTION=true    # Enable parallel audits
```

#### 🔬 PHP Syntax Audit
```env
WARDEN_PHP_SYNTAX_AUDIT_ENABLED=false   # Enable via warden:syntax or config
```

#### ⏰ Scheduling
```env
WARDEN_SCHEDULE_ENABLED=false
WARDEN_SCHEDULE_FREQUENCY=daily   # hourly|daily|weekly|monthly
WARDEN_SCHEDULE_TIME=03:00
WARDEN_SCHEDULE_TIMEZONE=UTC
```

### Ignoring Accepted Findings

If your team has reviewed a finding and wants to suppress it without forking the package, add an `ignore_findings` rule to `config/warden.php`.

```php
'ignore_findings' => [
    ['source' => 'debug-mode', 'package' => 'laravel/horizon'],
    ['source' => 'debug-mode', 'title' => 'Testing routes*'],
],
```

All provided keys in a rule must match for the finding to be ignored. String values support wildcard matching.

---

## 🔍 Security Audits

Warden performs comprehensive security analysis across multiple areas:

### 1. **Composer Dependencies**
- Scans PHP dependencies for known vulnerabilities
- Uses official `composer audit` command
- Identifies abandoned packages with replacement suggestions

### 2. **NPM Dependencies** 
- Analyzes JavaScript dependencies (when `--npm` flag used)
- Detects vulnerable packages in `package.json`
- Validates `package-lock.json` integrity

### 3. **Environment Configuration**
- Verifies `.env` file presence and `.gitignore` status
- Checks for missing critical environment variables
- Validates sensitive key configuration

### 4. **Storage & Permissions**
- Audits Laravel storage directories (`storage/`, `bootstrap/cache/`)
- Ensures proper write permissions
- Identifies missing or misconfigured paths

### 5. **Laravel Configuration**
- **Enhanced debug mode auditing**: Accurately detects development packages in production by scanning `vendor/composer/installed.json`
- Session security settings
- CSRF protection validation
- General security misconfigurations

### 6. **PHP Syntax Analysis**
- Code syntax validation across your application
- Configurable directory exclusions
- Integration with existing audit workflow

---

## 💡 Usage Examples

### Basic Commands

```bash
# Standard audit
php artisan warden:audit

# Include NPM + severity filtering
php artisan warden:audit --npm --severity=medium

# Force cache refresh
php artisan warden:audit --force

# Ignore abandoned packages
php artisan warden:audit --ignore-abandoned
```

### Output Formats

```bash
# JSON for processing
php artisan warden:audit --output=json > security-report.json

# GitHub Actions annotations
php artisan warden:audit --output=github

# GitLab CI dependency scanning
php artisan warden:audit --output=gitlab > gl-dependency-scanning-report.json

# Jenkins format
php artisan warden:audit --output=jenkins
```

### Advanced Usage

```bash
# Combined options
php artisan warden:audit --npm --severity=high --output=json --no-notify

# PHP syntax check
php artisan warden:syntax

# Schedule management
php artisan warden:schedule --enable
php artisan warden:schedule --status
```

---

## 🔔 Notifications

Warden supports multiple notification channels with rich formatting:

### ✅ Slack (Recommended)
- Color-coded severity levels
- Organized finding blocks  
- Clickable CVE links
- Professional formatting

```env
WARDEN_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

### ✅ Discord  
- Rich embeds with color coding
- Grouped findings by source
- Custom branding

```env
WARDEN_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/WEBHOOK
```

### ✅ Microsoft Teams
- Adaptive Cards with structured layouts
- Color-coded severity indicators
- Action buttons and rich formatting

```env
WARDEN_TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/YOUR/WEBHOOK
```

### ✅ Email
- Professional HTML templates with modern styling
- Severity-based color coding and summary statistics
- Grouped findings by source with detailed information
- Separate templates for vulnerabilities and abandoned packages

```env
WARDEN_EMAIL_RECIPIENTS=security@company.com,admin@company.com
WARDEN_EMAIL_FROM=security@company.com
WARDEN_EMAIL_FROM_NAME="Security Team"
```

### Multiple Channels
Configure multiple channels simultaneously - Warden sends to all configured endpoints.

---

## 🔧 Custom Audits

Create organization-specific security rules:

### 1. Implement Custom Audit

```php
<?php

namespace App\Audits;

use Dgtlss\Warden\Contracts\CustomAudit;

class DatabasePasswordAudit implements CustomAudit
{
    public function audit(): bool
    {
        $dbPassword = env('DB_PASSWORD', '');
        return !in_array(strtolower($dbPassword), ['password', '123456', 'admin']);
    }

    public function getFindings(): array
    {
        return [
            [
                'source' => 'Database Password Security',
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

### 2. Register Custom Audit

Add to `config/warden.php`:

```php
'custom_audits' => [
    \App\Audits\DatabasePasswordAudit::class,
    \App\Audits\ApiKeySecurityAudit::class,
    // Add more custom audits
],
```

---

## ⏰ Scheduling

### Enable Automated Audits

```bash
# Enable scheduling
php artisan warden:schedule --enable

# Check status
php artisan warden:schedule --status

# Disable scheduling  
php artisan warden:schedule --disable
```

### Configure Schedule

```env
WARDEN_SCHEDULE_ENABLED=true
WARDEN_SCHEDULE_FREQUENCY=daily
WARDEN_SCHEDULE_TIME=03:00
```

### Laravel Cron Setup

Ensure Laravel's scheduler is running:

```bash
* * * * * cd /path-to-your-project && php artisan schedule:run >> /dev/null 2>&1
```

---

## 🔄 CI/CD Integration

### GitHub Actions

```yaml
name: Security Audit
on: [push, pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Setup PHP
        uses: shivammathur/setup-php@v2
        with:
          php-version: '8.4'
      
      - name: Install dependencies
        run: composer install --no-progress --prefer-dist
      
      - name: Security Audit
        run: php artisan warden:audit --output=github --severity=high
```

### GitLab CI

```yaml
  security_audit:
  stage: test
  script:
    - composer install --no-progress --prefer-dist
    - php artisan warden:audit --output=gitlab --no-notify > gl-dependency-scanning-report.json
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
    expire_in: 1 week
  allow_failure: false
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Security Audit') {
            steps {
                sh 'composer install --no-progress --prefer-dist'
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

---

## 🎯 Advanced Features

### Performance Optimization

1. **Parallel Execution**: Enabled by default for 5x speed improvement
2. **Intelligent Caching**: Configurable cache duration prevents redundant API calls  
3. **Severity Filtering**: Focus resources on critical issues

### Audit Results

**Exit Codes:**
- `0`: No vulnerabilities found
- `1`: Vulnerabilities detected  
- `2`: Audit process failures

**Severity Levels:**
- `critical`: Immediate attention required
- `high`: Address as soon as possible
- `medium`: Should be reviewed and fixed
- `low`: Minor security concerns

### Configuration Examples

```php
// config/warden.php

'audits' => [
    'parallel_execution' => true,
    'timeout' => 300, // seconds
],

'cache' => [
    'enabled' => true,
    'duration' => 3600, // 1 hour
],

'sensitive_keys' => [
    'DB_PASSWORD',
    'STRIPE_SECRET',
    'AWS_SECRET_ACCESS_KEY',
],
```

> **Output & severity:** Use `--output` and `--severity` CLI options (not config). See [Command Reference](#-command-reference) above.

---

## 📈 Roadmap

### Coming Soon
- 📊 **Audit history tracking** and trend analysis
- 🔍 **Additional audit types** (Docker, Git, API security)
- 📋 **Web dashboard** for audit management
- 🤖 **AI-powered vulnerability analysis** and recommendations

---

## ❓ FAQ

### How does Warden differ from built-in Composer audit?
Warden extends beyond Composer audit with NPM scanning, environment checks, storage permissions, Laravel-specific configurations, and custom audit rules for comprehensive security monitoring.

### Can Warden run in CI/CD without notifications?
Yes! Use `--no-notify` to suppress notifications while still generating reports for your pipeline. (`--silent` also works.)

### What are the performance impacts?
Minimal! Parallel execution and intelligent caching ensure audits complete in seconds, with configurable timeouts and retry logic.

### How do I handle false positives?
Use severity filtering (`--severity=high`) and custom audits to tune findings for your organization's security policies.

### Is my data secure?
Absolutely. Warden processes everything locally - no external data transmission except for configured notification webhooks.

---

## 🛠️ Troubleshooting

### Common Issues

**Command not found:**
```bash
php artisan config:clear
composer dump-autoload
```

**Composer audit failures:**
```bash
# Update Composer to latest version
composer self-update
```

---

## 📄 License

This package is open source and released under the [MIT License](LICENSE).

---

## 🤝 Contributing

We welcome contributions! Please see our [CONTRIBUTING GUIDELINES](CONTRIBUTING.md) for details on:

- 🐛 Bug reports
- ✨ Feature requests  
- 🔧 Code contributions
- 📚 Documentation improvements

---

## 💬 Support

- 🐛 **Issues**: [GitHub Issues](https://github.com/dgtlss/warden/issues)
- 💬 **Discussions**: [GitHub Discussions](https://github.com/dgtlss/warden/discussions)  
- 📋 **Releases**: [Version History & Changelogs](https://github.com/dgtlss/warden/releases)

---

## 💝 Support Development

If you find Warden useful for your organization's security needs, please consider [supporting its development](https://github.com/sponsors/dgtlss).

---

<div align="center">

**Made with ❤️ for the Laravel community**

[⭐ Star on GitHub](https://github.com/dgtlss/warden) | [📦 Packagist](https://packagist.org/packages/dgtlss/warden) | [🐦 Follow Updates](https://twitter.com/nlangerdev)

</div>
