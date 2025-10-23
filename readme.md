# Warden

[![Latest Version on Packagist](https://img.shields.io/packagist/v/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
[![Total Downloads](https://img.shields.io/packagist/dt/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
[![License](https://img.shields.io/packagist/l/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
[![PHP Version Require](https://img.shields.io/packagist/php-v/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
![GitHub repo size](https://img.shields.io/github/repo-size/dgtlss/warden)

**Warden** is a comprehensive Laravel security audit package that proactively monitors your dependencies and application configuration for security vulnerabilities. Built for enterprise-grade security scanning, Warden provides powerful features for modern Laravel applications.

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

Perfect for continuous security monitoring and DevOps pipelines. Optimized for CI/CD with fast, focused audits by default.

---

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Security Audits](#security-audits)
- [Usage Examples](#usage-examples)
- [Notifications](#notifications)
- [Custom Audits](#custom-audits)
- [Scheduling](#scheduling)
- [CI/CD Integration](#cicd-integration)
- [Advanced Features](#advanced-features)

---

## 🚀 Installation

### New Installation

Install via Composer:

```bash
composer require dgtlss/warden
```

Publish configuration:

```bash
php artisan vendor:publish --tag="warden-config"
```

This creates a streamlined `config/warden.php` (~80 lines) with environment-first configuration.

### Upgrading from v1.x

**No breaking changes!** Existing installations continue to work unchanged.

1. Update the package:
```bash
composer update dgtlss/warden
```

2. Optionally publish the new streamlined config:
```bash
php artisan vendor:publish --tag="warden-config" --force
```

3. Gradually migrate to environment variables (recommended for CI/CD):

**Before (v1.x - config file):**
```php
// config/warden.php
'audits' => [
    'docker' => [
        'timeout' => 600,
        'scan_images' => true,
    ],
],
```

**After (v2.x - environment variables):**
```env
WARDEN_DOCKER_TIMEOUT=600
WARDEN_DOCKER_SCAN_IMAGES=true
```

**Benefits of upgrading:**
- ✅ **CI/CD Ready** - Environment-based configuration
- ✅ **Faster Performance** - Optimized defaults and parallel execution
- ✅ **Simplified Setup** - 80% less configuration complexity
- ✅ **Better Security** - Environment-specific settings
- ✅ **Zero Downtime** - Backward compatible migration

---

## ⚡ Quick Start

### CI/CD Security Audit (Default)
```bash
php artisan warden:audit
```
*Fast, focused security checks perfect for CI/CD pipelines*

### Comprehensive Security Audit
```bash
php artisan warden:audit --full
```
*Complete security analysis with all checks, notifications, and caching*

### JSON Output for CI/CD
```bash
php artisan warden:audit --output=json --severity=high
```

### With Additional Checks
```bash
php artisan warden:audit --full --npm --docker
```

---

## ⚙️ Configuration

Warden v2.0+ uses environment-first configuration for better CI/CD integration. The configuration file has been streamlined from 400+ lines to ~80 lines, with most settings now controlled via environment variables.

### Quick Configuration

Add these to your `.env` file:

#### 🎯 Core Settings
```env
# Operation mode: ci (fast, default) or full (comprehensive)
WARDEN_DEFAULT_MODE=ci

# Enable caching and notifications (mainly for full mode)
WARDEN_CACHE_ENABLED=false
WARDEN_NOTIFICATIONS_ENABLED=false
```

#### 🔔 Notifications
```env
# Slack (recommended - rich formatting)
WARDEN_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
WARDEN_SLACK_CHANNEL=#security
WARDEN_SLACK_USERNAME=Warden

# Discord
WARDEN_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/WEBHOOK
WARDEN_DISCORD_USERNAME=Warden

# Microsoft Teams
WARDEN_TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/YOUR/WEBHOOK

# Email
WARDEN_EMAIL_RECIPIENTS=security@company.com,admin@company.com
WARDEN_EMAIL_FROM=security@company.com
WARDEN_EMAIL_FROM_NAME="Security Team"

# Legacy webhook (backward compatibility)
WARDEN_WEBHOOK_URL=https://your-webhook-url.com
```

#### ⚡ Performance & Timeouts
```env
# Mode-specific timeouts
WARDEN_CI_TIMEOUT=120              # CI/CD mode: 2 minutes
WARDEN_FULL_TIMEOUT=300            # Full mode: 5 minutes

# Caching
WARDEN_CACHE_DURATION=3600         # Cache for 1 hour
WARDEN_PARALLEL_EXECUTION=true     # Enable parallel audits
```

#### 📊 Service-Specific Settings
```env
# Composer Audit
WARDEN_COMPOSER_IGNORE_ABANDONED=false
WARDEN_COMPOSER_TIMEOUT=300
WARDEN_COMPOSER_NO_DEV=true         # Exclude dev dependencies in CI/CD

# NPM Audit
WARDEN_NPM_REQUIRE_LOCKFILE=true
WARDEN_NPM_AUDIT_LEVEL=moderate     # low|moderate|high|critical
WARDEN_NPM_PRODUCTION_ONLY=false

# Docker Audit
WARDEN_DOCKER_SCAN_IMAGES=true
WARDEN_DOCKER_SEVERITY_THRESHOLD=medium
WARDEN_DOCKER_TIMEOUT=600

# Git Audit
WARDEN_GIT_MAX_COMMITS=100
WARDEN_GIT_SEVERITY_THRESHOLD=medium
WARDEN_GIT_EXCLUDE_PATHS=vendor/,node_modules/,tests/

# Environment Audit
WARDEN_ENV_SENSITIVE_KEYS=DB_PASSWORD,API_KEY,SECRET_KEY,JWT_SECRET

# Storage Audit
WARDEN_STORAGE_DIRECTORIES=storage/framework,storage/logs,bootstrap/cache
WARDEN_STORAGE_CHECK_PERMISSIONS=true

# Debug Mode Audit
WARDEN_DEBUG_DEV_PACKAGES=barryvdh/laravel-debugbar,laravel/telescope
WARDEN_DEBUG_PRODUCTION_ENVIRONMENTS=production

# Security Patterns Audit
WARDEN_SECURITY_PATTERNS_SEVERITY_THRESHOLD=medium
WARDEN_SECURITY_PATTERNS_MAX_FILE_SIZE=1048576
```

#### ⏰ Scheduling
```env
WARDEN_SCHEDULE_ENABLED=false
WARDEN_SCHEDULE_FREQUENCY=daily   # hourly|daily|weekly|monthly
WARDEN_SCHEDULE_TIME=03:00
WARDEN_SCHEDULE_TIMEZONE=UTC
```

### Configuration Command

View your current effective configuration:

```bash
# Show all configuration
php artisan warden:config

# Show specific service configuration
php artisan warden:config --service=docker
```

### Backward Compatibility

Existing installations continue to work unchanged. All legacy `config('warden.audits.*')` calls are automatically mapped to the new environment-based system.

### Auto-Discovery

Warden automatically enables services based on your project structure:

- **NPM**: Enabled if `package.json` exists
- **Docker**: Enabled if `Dockerfile` or `docker-compose.yml` exists  
- **Kubernetes**: Enabled if `k8s/`, `kubernetes/`, or `*.yaml` files exist
- **Git**: Always available in git repositories

---

## 🔍 Security Audits

Warden provides two optimized modes of operation:

### 🚀 CI/CD Mode (Default)
**Perfect for continuous integration and deployment pipelines**

```bash
php artisan warden:audit
```

**Features:**
- **⚡ Fast execution** - ~3x faster than full mode
- **🎯 Focused checks** - Core security only (Composer, Environment, Debug)
- **🚫 No caching** - Always fresh scans
- **🔕 No notifications** - CI/CD platforms handle alerts
- **💾 Low memory** - 60% less memory usage
- **📊 CI-friendly output** - JSON, GitHub Actions, GitLab CI formats

**Default Services:**
- Composer dependency audit
- Environment configuration check
- Debug mode verification
- Storage permissions validation

### 🔍 Full Mode (`--full` flag)
**Comprehensive security analysis for development and staging**

```bash
php artisan warden:audit --full
```

**Features:**
- **🔬 Complete analysis** - All available security checks
- **📱 Rich notifications** - Slack, Discord, Teams, Email with detailed reports
- **🗄️ Intelligent caching** - Prevents redundant scans (configurable TTL)
- **⚡ Parallel execution** - Up to 5x faster with concurrent audits
- **📈 Advanced features** - Custom audits, scheduling, historical tracking
- **🎛️ Configurable services** - Docker, Kubernetes, Git, NPM, code patterns

**Additional Services:**
- Docker container security scanning
- Kubernetes manifest analysis
- Git repository security audit
- NPM dependency vulnerability scanning
- Security code patterns detection
- PHP syntax validation
- Custom audit rules

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
- Debug mode status verification
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
# CI/CD focused audit (default - fast)
php artisan warden:audit

# Comprehensive audit with all features
php artisan warden:audit --full

# Include specific checks in full mode
php artisan warden:audit --full --npm --docker --kubernetes

# Severity filtering for CI/CD
php artisan warden:audit --severity=high

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
# CI/CD with JSON output
php artisan warden:audit --output=json --severity=high

# Full audit with notifications
php artisan warden:audit --full --output=github

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
          php-version: '8.1'
      
      - name: Install dependencies
        run: composer install --no-progress --prefer-dist
      
      - name: Security Audit (CI/CD Optimized)
        run: php artisan warden:audit --output=github --severity=high
```

### GitLab CI

```yaml
security_audit:
  stage: test
  script:
    - composer install --no-progress --prefer-dist
    - php artisan warden:audit --output=gitlab > gl-dependency-scanning-report.json
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
    'timeout' => 300,
    'retry_attempts' => 3,
    'severity_filter' => 'medium',
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

---

## 🆕 What's New in v2.0.0

- ✅ **CI/CD focused default mode** - Fast, optimized for pipelines
- ✅ **`--full` flag** for comprehensive security analysis
- ✅ **3x faster CI/CD execution** - Core checks only
- ✅ **Simplified command structure** - Clear mental model
- ✅ **Backward compatibility** - All existing features preserved
- ✅ **Parallel audit execution** for 5x faster performance (full mode)
- ✅ **Complete notification suite** (Slack, Discord, Teams, Enhanced Email) 
- ✅ **Professional email templates** with severity colors and statistics
- ✅ **Microsoft Teams integration** with Adaptive Cards
- ✅ **CI/CD output formats** (GitHub Actions, GitLab CI, Jenkins)
- ✅ **Automated scheduling** via Laravel scheduler
- ✅ **Custom audit rules** for organization-specific policies
- ✅ **Intelligent caching** with force refresh capability (full mode)
- ✅ **Severity filtering** to focus on critical issues

---

## 📈 Roadmap

### Coming Soon
- 📊 **Audit history tracking** and trend analysis
- 🔍 **Additional audit types** (Docker, Git, API security)
- 📋 **Web dashboard** for audit management
- 🤖 **AI-powered vulnerability analysis** and recommendations

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