# Warden v1.3.0 Upgrades

This document outlines all the new features, improvements, and enhancements introduced in Warden v1.3.0.

## 🚀 Major New Features

### 1. **Multiple Notification Channels**
Previously limited to a single webhook URL and email, Warden now supports multiple notification channels:

- **Slack** - Rich formatted messages with severity indicators and actionable links
- **Discord** - Webhook integration for Discord servers
- **Microsoft Teams** - Native Teams webhook support
- **Email** - Improved email notifications with better formatting

#### Configuration:
```env
# Slack
WARDEN_SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL

# Discord
WARDEN_DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/YOUR/WEBHOOK

# Microsoft Teams
WARDEN_TEAMS_WEBHOOK_URL=https://outlook.office.com/webhook/YOUR/WEBHOOK

# Email (enhanced)
WARDEN_EMAIL_RECIPIENTS=security@company.com,admin@company.com
WARDEN_EMAIL_FROM=security@yourcompany.com
WARDEN_EMAIL_FROM_NAME="Security Team"
```

### 2. **Parallel Audit Execution**
Audits now run in parallel by default, significantly improving performance:

- Composer, NPM, Environment, Storage, and Configuration audits run concurrently
- Up to 5x faster execution for full audit runs
- Configurable via `WARDEN_PARALLEL_EXECUTION=true/false`

### 3. **Audit Result Caching**
Prevent running audits too frequently with intelligent caching:

```env
WARDEN_CACHE_ENABLED=true
WARDEN_CACHE_DURATION=3600  # Cache for 1 hour
WARDEN_CACHE_DRIVER=redis   # Use specific cache driver
```

- Reduces unnecessary API calls
- Improves CI/CD pipeline efficiency
- Force refresh with `--force` flag

### 4. **Scheduled Automated Audits**
Built-in Laravel scheduler integration for automated security scans:

```bash
# Enable scheduled audits
php artisan warden:schedule --enable

# Configure frequency
WARDEN_SCHEDULE_ENABLED=true
WARDEN_SCHEDULE_FREQUENCY=daily  # hourly|daily|weekly|monthly
WARDEN_SCHEDULE_TIME=03:00
WARDEN_SCHEDULE_TIMEZONE=UTC
```

### 5. **Custom Audit Rules**
Create your own security audit rules by implementing the `CustomAudit` interface:

```php
use Dgtlss\Warden\Contracts\CustomAudit;

class MyCustomSecurityAudit implements CustomAudit
{
    public function audit(): bool
    {
        // Your audit logic
    }
    
    public function getFindings(): array
    {
        // Return findings array
    }
}
```

Register in `config/warden.php`:
```php
'custom_audits' => [
    \App\Audits\MyCustomSecurityAudit::class,
],
```

### 6. **Multiple Output Formats**
Export audit results in various formats for better CI/CD integration:

- **JSON** - Machine-readable format with metadata
- **JUnit XML** - For test reporting in CI systems
- **Markdown** - Human-readable reports
- **CI-specific formats** - GitHub Actions, GitLab CI, Jenkins

```bash
# Output as JSON
php artisan warden:audit --output=json > audit-report.json

# Output for GitHub Actions
php artisan warden:audit --output=github

# Output for GitLab CI
php artisan warden:audit --output=gitlab
```

### 7. **Audit History Tracking**
Store and track audit results over time:

```env
WARDEN_HISTORY_ENABLED=true
WARDEN_HISTORY_TABLE=warden_audit_history
WARDEN_HISTORY_RETENTION_DAYS=90
```

Features:
- Database storage of all audit runs
- Track vulnerability trends
- Automatic cleanup of old records
- Query historical data

### 8. **Severity Filtering**
Filter audit results by severity level:

```bash
# Only show high and critical vulnerabilities
php artisan warden:audit --severity=high

# Configure default filter
WARDEN_SEVERITY_FILTER=medium  # null|low|medium|high|critical
```

### 9. **Progress Indicators**
Enhanced CLI experience with:
- Real-time progress bars
- Spinner animations during long operations
- Better error formatting
- Color-coded severity indicators

### 10. **Retry Mechanism**
Automatic retry for failed audits with exponential backoff:

```env
WARDEN_RETRY_ATTEMPTS=3
WARDEN_RETRY_DELAY=1000  # milliseconds
```

## 🔧 Improvements

### Enhanced Error Handling
- More descriptive error messages
- Better exception handling
- Graceful fallbacks for network issues

### Performance Optimizations
- Parallel execution by default
- Efficient result processing
- Memory usage improvements

### Better Configuration Validation
- Validates configuration on boot
- Helpful error messages for misconfigurations
- Type safety improvements

### Laravel Prompts Integration
- Modern CLI interface
- Interactive prompts where appropriate
- Better visual feedback

## 📦 Breaking Changes

### Notification Configuration
The old single webhook configuration is maintained for backward compatibility, but we recommend migrating to the new structure:

**Old:**
```env
WARDEN_WEBHOOK_URL=https://hooks.slack.com/...
```

**New:**
```env
WARDEN_SLACK_WEBHOOK_URL=https://hooks.slack.com/...
```

## 🚀 Migration Guide

### From v1.2.x to v1.3.0

1. **Update composer dependency:**
   ```bash
   composer update dgtlss/warden
   ```

2. **Publish new configuration:**
   ```bash
   php artisan vendor:publish --tag=warden-config --force
   ```

3. **Update environment variables:**
   - Add new notification channel webhooks
   - Configure caching if desired
   - Set up scheduling if needed

4. **Run migrations (if using history):**
   ```bash
   php artisan vendor:publish --tag=warden-migrations
   php artisan migrate
   ```

## 🎯 Use Cases

### CI/CD Integration
```yaml
# GitHub Actions
- name: Run Security Audit
  run: |
    php artisan warden:audit --output=github --severity=high
    
# GitLab CI
security_audit:
  script:
    - php artisan warden:audit --output=gitlab > gl-dependency-scanning-report.json
  artifacts:
    reports:
      dependency_scanning: gl-dependency-scanning-report.json
```

### Scheduled Security Monitoring
```bash
# Enable daily audits at 3 AM
php artisan warden:schedule --enable
```

### Custom Security Policies
Create organization-specific security rules:
```php
class PiiDataExposureAudit implements CustomAudit
{
    public function audit(): bool
    {
        // Check for PII data exposure in logs
    }
}
```

## 🔒 Security Enhancements

- Improved credential handling
- Secure webhook communication
- Rate limiting support
- Audit trail for compliance

## 📈 Future Roadmap

- Web dashboard for audit visualization
- Integration with security platforms (Snyk, SonarQube)
- Machine learning for vulnerability prediction
- Automated remediation suggestions
- Slack/Teams bot integration

## 💡 Tips

1. **Use caching in CI/CD** to avoid rate limits
2. **Set up multiple notification channels** for redundancy
3. **Create custom audits** for organization-specific security policies
4. **Use severity filtering** to focus on critical issues
5. **Enable history tracking** for compliance and trend analysis

## 🤝 Contributing

We welcome contributions! Please see our [contributing guidelines](contributing.md) for details on submitting improvements.

## 📝 Changelog

For a complete list of changes, see the [releases page](https://github.com/dgtlss/warden/releases).

---

**Note:** This is a major update with significant improvements to the Warden security audit system. We recommend thoroughly testing in a staging environment before deploying to production. 