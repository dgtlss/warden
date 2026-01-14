# Warden

[![Latest Version on Packagist](https://img.shields.io/packagist/v/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
[![Total Downloads](https://img.shields.io/packagist/dt/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
[![License](https://img.shields.io/packagist/l/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
[![PHP Version Require](https://img.shields.io/packagist/php-v/dgtlss/warden.svg?style=flat-square)](https://packagist.org/packages/dgtlss/warden)
![GitHub repo size](https://img.shields.io/github/repo-size/dgtlss/warden)

**Warden** is a comprehensive Laravel security audit package that proactively monitors your dependencies and application configuration for security vulnerabilities. Built for enterprise-grade security scanning, Warden provides powerful features for modern Laravel applications, ensuring your projects remain secure from development to production.

## 🚀 Key Features

### ✅ Comprehensive Security Audits
- **🔍 Dependency Scanning**: Composer and NPM vulnerability detection
- **⚙️ Configuration Audits**: Environment, storage permissions, and Laravel config
- **🔒 Security Headers**: X-Frame-Options, CSP, HSTS, X-Content-Type-Options
- **🗄️ Database Security**: Password strength, SSL/TLS connections, credential checks
- **🌐 CORS Analysis**: Wildcard detection and permissive settings audit
- **🔐 SSL/HTTPS**: Enforcement checks and secure cookie validation
- **📁 File Permissions**: Directory permission audits for sensitive paths
- **📝 Code Analysis**: PHP syntax validation and security checks
- **🔧 Custom Audit Rules**: Organization-specific security policies

### ✅ Performance & Scalability  
- **⚡ Parallel Execution**: Up to 5x faster audit performance
- **🗄️ Intelligent Caching**: Prevents redundant scans with configurable TTL
- **🎯 Severity Filtering**: Focus on critical issues only
- **📈 Incremental Audits**: Only scan changed dependencies for faster runs
- **⏳ Queue Processing**: Background job execution for non-blocking audits

### ✅ Integration & Automation
- **📊 Multiple Output Formats**: JSON, SARIF, HTML, GitHub Actions, GitLab CI, Jenkins
- **🔔 Rich Notifications**: Slack, Discord, Teams, Email, Telegram, PagerDuty
- **⏰ Automated Scheduling**: Laravel scheduler integration
- **🔄 CI/CD Ready**: Native support for all major platforms
- **🛡️ Webhook Security**: HMAC-SHA256 signature verification

### ✅ Developer Experience
- **🎮 Interactive Mode**: Guided audit selection with Laravel Prompts
- **🧪 Dry-Run Mode**: Simulate audits without sending notifications
- **🧙 Setup Wizard**: Interactive configuration wizard (`warden:setup`)
- **📊 Progress Indicators**: Visual feedback during audit execution
- **🔍 Verbose Debugging**: Detailed timing and cache information

### ✅ Remediation Support
- **💡 Fix Suggestions**: Actionable remediation steps for each finding
- **🔗 Reference Links**: CVE links and documentation references
- **⚡ Priority Badges**: Immediate vs standard fix prioritization

Perfect for continuous security monitoring and DevOps pipelines.

---

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Setup Wizard](#setup-wizard)
- [Configuration](#configuration)
- [Security Audits](#security-audits)
- [Usage Examples](#usage-examples)
- [Output Formats](#output-formats)
- [Notifications](#notifications)
- [Custom Audits](#custom-audits)
- [Plugin System](#-plugin-system-new)
- [Scheduling](#scheduling)
- [CI/CD Integration](#cicd-integration)
- [Advanced Features](#advanced-features)
- [FAQ](#faq)

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

### Silent Mode (No Notifications)
Perform audits without triggering notifications:
```bash
php artisan warden:audit --silent
```

---

## 🧙 Setup Wizard

Warden includes an interactive setup wizard to help you configure all features:

```bash
php artisan warden:setup
```

The wizard guides you through:

### Step 1: Notification Channels
- Slack, Discord, Microsoft Teams webhooks
- Email recipient configuration
- Telegram bot setup
- PagerDuty integration

### Step 2: Cache Settings
- Enable/disable caching
- Configure cache duration (30 min to 24 hours)

### Step 3: Scheduled Audits
- Enable automated scheduling
- Set frequency (hourly, daily, weekly, monthly)
- Configure run time

### Step 4: Security Settings
- Rate limiting configuration
- Webhook signature verification
- Secret key setup

### Step 5: Advanced Settings
- Queue processing options
- Audit history tracking
- Incremental audit configuration

### Show All Environment Variables

To see all available configuration options without interactive prompts:

```bash
php artisan warden:setup --show-env
```

This outputs a complete list of environment variables you can add to your `.env` file.

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

# Telegram (New)
WARDEN_TELEGRAM_BOT_TOKEN=your-bot-token
WARDEN_TELEGRAM_CHAT_ID=your-chat-id

# PagerDuty (New)
WARDEN_PAGERDUTY_ROUTING_KEY=your-integration-key

# Legacy webhook (backward compatibility)
WARDEN_WEBHOOK_URL=https://your-webhook-url.com
```

#### ⚡ Performance
```env
WARDEN_CACHE_ENABLED=true
WARDEN_CACHE_DURATION=3600        # Cache for 1 hour
WARDEN_PARALLEL_EXECUTION=true    # Enable parallel audits
```

#### ⏰ Scheduling
```env
WARDEN_SCHEDULE_ENABLED=false
WARDEN_SCHEDULE_FREQUENCY=daily   # hourly|daily|weekly|monthly
WARDEN_SCHEDULE_TIME=03:00
WARDEN_SCHEDULE_TIMEZONE=UTC
```

#### 📊 Output & Filtering
```env
WARDEN_SEVERITY_FILTER=           # null|low|medium|high|critical
WARDEN_OUTPUT_JSON=false
WARDEN_OUTPUT_JUNIT=false
```

#### 🔒 Security (New)
```env
# Webhook Signing
WARDEN_WEBHOOK_SIGNING_ENABLED=false
WARDEN_WEBHOOK_SECRET=your-secret-key
WARDEN_WEBHOOK_MAX_TIME_DIFF=300  # seconds

# Rate Limiting
WARDEN_RATE_LIMIT_ENABLED=false
WARDEN_RATE_LIMIT_MAX_ATTEMPTS=10
WARDEN_RATE_LIMIT_DECAY_MINUTES=60

# Audit History Integrity
WARDEN_HISTORY_SECRET=            # defaults to APP_KEY
```

#### ⏳ Queue Processing (New)
```env
WARDEN_QUEUE_ENABLED=true
WARDEN_QUEUE_CONNECTION=          # defaults to queue.default
WARDEN_QUEUE_NAME=default
WARDEN_QUEUE_TRIES=3
WARDEN_QUEUE_TIMEOUT=300
```

#### 📈 Audit History (New)
```env
WARDEN_HISTORY_ENABLED=false
WARDEN_HISTORY_TABLE=warden_audit_history
WARDEN_HISTORY_RETENTION_DAYS=90
```

#### 🚀 Incremental Audits (New)
```env
WARDEN_INCREMENTAL_ENABLED=false
WARDEN_INCREMENTAL_CACHE_TTL=86400  # 24 hours
```

---

## 🔍 Security Audits

Warden performs comprehensive security analysis across multiple areas:

### 1. **Composer Dependencies**
- Scans PHP dependencies for known vulnerabilities
- Uses official `composer audit` command
- Identifies abandoned packages with replacement suggestions
- Provides remediation suggestions with CVE links

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

### 7. **Security Headers** *(New)*
- **X-Frame-Options**: Clickjacking protection validation
- **Content-Security-Policy**: CSP header presence and configuration
- **Strict-Transport-Security**: HSTS enforcement check
- **X-Content-Type-Options**: MIME type sniffing protection
- **X-XSS-Protection**: XSS filter header validation
- **Referrer-Policy**: Information leakage prevention

### 8. **Database Security** *(New)*
- Password strength analysis (detects weak/common passwords)
- SSL/TLS connection enforcement checks
- Credential configuration validation
- Default password detection

### 9. **CORS Configuration** *(New)*
- Wildcard origin detection (`*` in allowed origins)
- Permissive `Access-Control-Allow-Credentials` settings
- Overly permissive allowed methods and headers
- Configuration best practices validation

### 10. **SSL/HTTPS** *(New)*
- HTTPS enforcement in production
- Secure session cookie configuration
- `HTTPS_ONLY` and `SECURE_COOKIES` environment validation
- Mixed content vulnerability detection

### 11. **File Permissions** *(New)*
- Directory permission audits for sensitive paths
- World-writable file detection
- Storage and cache directory validation
- Recommended permission enforcement

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

### Interactive Mode *(New)*

```bash
# Launch interactive mode with guided prompts
php artisan warden:audit --interactive
```

Interactive mode lets you:
- Select which audits to run (multi-select)
- Choose minimum severity level
- Toggle notification sending
- Force cache refresh

### Dry-Run Mode *(New)*

```bash
# Simulate audit without sending notifications
php artisan warden:audit --dry-run

# Combine with other options
php artisan warden:audit --npm --severity=high --dry-run
```

Dry-run mode:
- Runs all audits normally
- Displays findings in console
- Shows what notifications would be sent
- Does NOT actually send any notifications

### Background Processing *(New)*

```bash
# Run audit as a background job
php artisan warden:audit --queue

# Combine with other options
php artisan warden:audit --npm --queue --silent
```

Queue mode dispatches the audit as a Laravel job for non-blocking execution.

### Verbose Mode

```bash
# Show detailed debug information
php artisan warden:audit -v

# Very verbose with timestamps
php artisan warden:audit -vv
```

Verbose output includes:
- Audit service initialization details
- Cache hit/miss information
- Timing for each audit
- Command execution details

### Advanced Usage

```bash
# Combined options
php artisan warden:audit --npm --severity=high --output=json --silent

# PHP syntax check
php artisan warden:syntax

# Schedule management
php artisan warden:schedule --enable
php artisan warden:schedule --status

# Configuration wizard
php artisan warden:setup
```

---

## 📊 Output Formats

Warden supports multiple output formats for different use cases:

### JSON Format
Machine-readable output for processing and storage:
```bash
php artisan warden:audit --output=json > security-report.json
```

### SARIF Format *(New)*
[SARIF (Static Analysis Results Interchange Format)](https://sarifweb.azurewebsites.net/) 2.1.0 compliant output for integration with:
- **GitHub Advanced Security**: Code scanning alerts
- **Azure DevOps**: Security scanning results
- **VS Code**: SARIF Viewer extension

```bash
# Generate SARIF report
php artisan warden:audit --output=sarif > warden-results.sarif

# Upload to GitHub Code Scanning (in GitHub Actions)
# Uses the github/codeql-action/upload-sarif action
```

SARIF output includes:
- Tool information and version
- Rule definitions for each audit type
- Results with locations and severity
- **Remediation suggestions** in the `fixes` property

### HTML Format *(New)*
Beautiful, human-readable HTML reports:
```bash
php artisan warden:audit --output=html > security-report.html
```

HTML reports include:
- **Executive Summary**: Total findings, severity breakdown
- **Severity Badges**: Color-coded (Critical, High, Medium, Low)
- **Remediation Section**: Commands, manual steps, reference links
- **Priority Indicators**: Immediate vs standard fixes
- Responsive design for easy viewing

### CI/CD Formats

```bash
# GitHub Actions annotations
php artisan warden:audit --output=github

# GitLab CI dependency scanning
php artisan warden:audit --output=gitlab > gl-dependency-scanning-report.json

# Jenkins format
php artisan warden:audit --output=jenkins
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

### ✅ Telegram *(New)*
- Bot-based messaging with HTML formatting
- Severity-based alerts with emoji indicators
- Grouped findings with CVE links
- Supports both private chats and groups

```env
WARDEN_TELEGRAM_BOT_TOKEN=your-bot-token-from-botfather
WARDEN_TELEGRAM_CHAT_ID=your-chat-or-group-id
```

To get your bot token:
1. Message [@BotFather](https://t.me/BotFather) on Telegram
2. Create a new bot with `/newbot`
3. Copy the token provided

To get your chat ID:
1. Add the bot to your chat/group
2. Send a message to the bot
3. Visit `https://api.telegram.org/bot<YOUR_TOKEN>/getUpdates` to find your chat ID

### ✅ PagerDuty *(New)*
- Critical incident creation via Events API v2
- Automatic severity mapping to PagerDuty urgency levels
- Deduplication support for related findings
- Perfect for on-call security teams

```env
WARDEN_PAGERDUTY_ROUTING_KEY=your-integration-key
```

To get your routing key:
1. Go to **Services** > **Service Directory** in PagerDuty
2. Create or select a service
3. Go to **Integrations** tab > **Add Integration**
4. Select **Events API v2** and copy the Integration Key

### Multiple Channels
Configure multiple channels simultaneously - Warden sends to all configured endpoints.

### Webhook Security *(New)*
Enable HMAC-SHA256 signature verification for outgoing webhooks:

```env
WARDEN_WEBHOOK_SIGNING_ENABLED=true
WARDEN_WEBHOOK_SECRET=your-secret-key
```

When enabled, all webhook requests include `X-Warden-Signature` and `X-Warden-Timestamp` headers for verification.

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

## 🔌 Plugin System *(New)*

Extend Warden with reusable plugins that bundle custom audits, notification channels, and commands. Plugins can be shared across projects or distributed as Composer packages.

### What Plugins Can Provide

| Component | Description |
|-----------|-------------|
| **Audits** | Custom security checks (e.g., Docker, AWS, Kubernetes) |
| **Channels** | Custom notification endpoints (e.g., custom webhooks, SMS) |
| **Commands** | Additional Artisan commands |

### Creating a Plugin

Create a class extending `AbstractPlugin`:

```php
<?php

namespace App\Warden;

use Dgtlss\Warden\Plugins\AbstractPlugin;

class MySecurityPlugin extends AbstractPlugin
{
    protected string $name = 'my-security-plugin';
    protected string $version = '1.0.0';
    protected string $description = 'Custom security audits for my organization';

    public function audits(): array
    {
        return [
            \App\Warden\Audits\AwsSecurityAudit::class,
            \App\Warden\Audits\KubernetesAudit::class,
        ];
    }

    public function channels(): array
    {
        return [
            \App\Warden\Channels\SmsChannel::class,
        ];
    }
}
```

### Registering Plugins

Add your plugin to `config/warden.php`:

```php
'plugins' => [
    'auto_discover' => true,
    'registered' => [
        \App\Warden\MySecurityPlugin::class,
    ],
],
```

### Auto-Discovery for Packages

Distributed plugins can be auto-discovered! Add to your package's `composer.json`:

```json
{
    "name": "vendor/warden-docker",
    "extra": {
        "warden": {
            "plugin": "Vendor\\WardenDocker\\DockerPlugin"
        }
    }
}
```

When users install your package, Warden automatically discovers and loads the plugin.

### Creating Custom Audits for Plugins

Audit classes must implement `AuditService` or extend `AbstractAuditService`:

```php
<?php

namespace App\Warden\Audits;

use Dgtlss\Warden\Services\Audits\AbstractAuditService;
use Dgtlss\Warden\Enums\Severity;
use Dgtlss\Warden\ValueObjects\Finding;
use Dgtlss\Warden\ValueObjects\Remediation;

class AwsSecurityAudit extends AbstractAuditService
{
    public function getName(): string
    {
        return 'AWS Security';
    }

    public function run(): bool
    {
        // Check for exposed AWS credentials
        if ($this->hasExposedCredentials()) {
            $this->addFinding(Finding::create(
                source: $this->getName(),
                package: 'aws-config',
                title: 'AWS credentials in environment',
                severity: Severity::Critical,
                remediation: Remediation::create(
                    description: 'Use IAM roles instead of hardcoded credentials',
                    links: ['https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html']
                )
            ));
        }

        return $this->findings === [];
    }

    protected function hasExposedCredentials(): bool
    {
        return env('AWS_ACCESS_KEY_ID') !== null 
            && env('AWS_SECRET_ACCESS_KEY') !== null;
    }
}
```

### Creating Custom Channels for Plugins

Channel classes must implement `NotificationChannel`:

```php
<?php

namespace App\Warden\Channels;

use Dgtlss\Warden\Contracts\NotificationChannel;
use Dgtlss\Warden\ValueObjects\Finding;
use Illuminate\Support\Facades\Http;

class SmsChannel implements NotificationChannel
{
    public function getName(): string
    {
        return 'SMS';
    }

    public function isConfigured(): bool
    {
        return config('services.twilio.sid') !== null;
    }

    public function send(array $findings): void
    {
        $criticalCount = count(array_filter(
            $findings, 
            fn(Finding $f) => $f->severity->value === 'critical'
        ));

        if ($criticalCount > 0) {
            // Send SMS via Twilio, Vonage, etc.
            $this->sendSms("ALERT: {$criticalCount} critical security findings");
        }
    }

    public function sendAbandonedPackages(array $abandonedPackages): void
    {
        // Optional: notify about abandoned packages
    }

    protected function sendSms(string $message): void
    {
        // Your SMS implementation
    }
}
```

### Example Plugin

Warden includes an example plugin with Docker security audits and a custom webhook channel:

```php
// Register the example plugin to try it out
'plugins' => [
    'registered' => [
        \Dgtlss\Warden\Examples\ExamplePlugin::class,
    ],
],
```

The example plugin includes:
- **DockerAuditService**: Checks for Docker socket permissions, privileged containers, and exposed Docker API
- **WebhookChannel**: Sends findings to any HTTP endpoint with optional authentication

### Plugin Configuration

```env
# Enable/disable plugin auto-discovery
WARDEN_PLUGIN_AUTO_DISCOVER=true

# Example webhook channel configuration
WARDEN_CUSTOM_WEBHOOK_URL=https://your-service.com/api/security-alerts
WARDEN_CUSTOM_WEBHOOK_SECRET=your-shared-secret
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
      
      - name: Security Audit
        run: php artisan warden:audit --output=github --severity=high
```

### GitLab CI

```yaml
security_audit:
  stage: test
  script:
    - composer install --no-progress --prefer-dist
    - php artisan warden:audit --output=gitlab --silent > gl-dependency-scanning-report.json
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
4. **Incremental Audits** *(New)*: Only scan changed dependencies

### Incremental Audits *(New)*

Warden can detect changes in your lockfiles and only scan modified dependencies:

```env
WARDEN_INCREMENTAL_ENABLED=true
WARDEN_INCREMENTAL_CACHE_TTL=86400  # 24 hours
```

How it works:
- Compares `composer.lock` and `package-lock.json` hashes
- Only runs full audit when dependencies change
- Caches previous scan results for unchanged packages
- Significantly faster for large projects with frequent runs

### Queue Processing *(New)*

Run audits in the background without blocking your application:

```env
WARDEN_QUEUE_ENABLED=true
WARDEN_QUEUE_CONNECTION=redis        # or sync, database, etc.
WARDEN_QUEUE_NAME=security-audits
WARDEN_QUEUE_TRIES=3
WARDEN_QUEUE_TIMEOUT=300
```

Usage:
```bash
php artisan warden:audit --queue
```

### Rate Limiting *(New)*

Prevent audit abuse in multi-tenant or shared environments:

```env
WARDEN_RATE_LIMIT_ENABLED=true
WARDEN_RATE_LIMIT_MAX_ATTEMPTS=10   # Max attempts per hour
WARDEN_RATE_LIMIT_DECAY_MINUTES=60  # Reset period
```

When rate limited, the command will display time until next available attempt.

### Webhook Security *(New)*

Sign outgoing webhook requests with HMAC-SHA256:

```env
WARDEN_WEBHOOK_SIGNING_ENABLED=true
WARDEN_WEBHOOK_SECRET=your-secret-key
WARDEN_WEBHOOK_MAX_TIME_DIFF=300    # 5 minute tolerance
```

Signed requests include:
- `X-Warden-Signature`: HMAC-SHA256 signature
- `X-Warden-Timestamp`: Request timestamp

Verify incoming webhooks in your receiving application:
```php
$signature = hash_hmac('sha256', $timestamp . $payload, $secret);
$isValid = hash_equals($signature, $receivedSignature);
```

### Audit History *(New)*

Track audit results over time for trending and compliance:

```env
WARDEN_HISTORY_ENABLED=true
WARDEN_HISTORY_TABLE=warden_audit_history
WARDEN_HISTORY_RETENTION_DAYS=90
```

Features:
- Stores severity breakdowns per audit
- Query historical trends and statistics
- Automatic cleanup of old data
- Integrity hashing for tamper detection

Run migration:
```bash
php artisan migrate
```

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

// New in v2.x
'rate_limit' => [
    'enabled' => true,
    'max_attempts' => 10,
    'decay_minutes' => 60,
],

'queue' => [
    'enabled' => true,
    'connection' => 'redis',
    'queue_name' => 'security-audits',
],

'incremental' => [
    'enabled' => true,
    'cache_ttl' => 86400,
],
```

---

## 📈 Roadmap

### ✅ Recently Completed
- 📊 **Audit history tracking** with trend analysis and integrity hashing
- 🔍 **5 new audit types**: Security Headers, Database Security, CORS, SSL/HTTPS, File Permissions
- 📄 **SARIF & HTML output** for GitHub Advanced Security and human-readable reports
- 📱 **Telegram & PagerDuty** notification channels
- 💡 **Remediation suggestions** with commands, steps, and reference links
- 🔒 **Security features**: Webhook signing, rate limiting, incremental audits
- 🎮 **Interactive CLI mode** with Laravel Prompts
- 🧙 **Setup wizard** for easy configuration

### Coming Soon
- 📋 **Web dashboard** for audit management (warden-dashboard package)
- 📈 **Historical trend graphs** and visualization
- 🔌 **Plugin system** for community extensions
- 🐳 **Docker security audits**
- 🔑 **API security scanning**
- 🤖 **AI-powered vulnerability analysis** and recommendations

---

## ❓ FAQ

### How does Warden differ from built-in Composer audit?
Warden extends beyond Composer audit with NPM scanning, environment checks, storage permissions, Laravel-specific configurations, and custom audit rules for comprehensive security monitoring.

### Can Warden run in CI/CD without notifications?
Yes! Use the `--silent` flag to suppress notifications while still generating reports for your pipeline.

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